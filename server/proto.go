package main

import (
	"encoding/binary"
	"errors"
	"strings"
)

// ---------------------------------------------------------------------------
// DNSTun v1 wire format - speed-only, no crypto.
//
// QUERY (client -> server), payload in the QNAME:
//   <b32(hdr4 || fragment)> . <sid6> . <zone>
//     hdr4: u16 frag_id | u8 frag_idx | u8 flags (bit0 = more fragments)
//   A poll (nothing to send) is just the 4-byte header: flags=0, frag_idx=0.
//
// RESPONSE (server -> client), payload in ONE TXT record:
//   rdata = u16 seq | u8 flags | concatenated IPv4 packets
//   (rdata is a sequence of <=255-byte character strings, per DNS TXT wire
//    format; the client concatenates them)
// ---------------------------------------------------------------------------

const (
	flagMore = 1 << 0 // upstream: more fragments follow
	flagDown = 1 << 0 // downstream: server still has data queued
)

// base32 (RFC4648 alphabet, lowercase, no padding). Case-insensitive so that
// resolver 0x20 case randomisation can never corrupt the payload.
const b32alpha = "abcdefghijklmnopqrstuvwxyz234567"

var b32rev = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(b32alpha); i++ {
		t[b32alpha[i]] = int8(i)
		t[strings.ToUpper(b32alpha)[i]] = int8(i)
	}
	return t
}()

func b32Encode(src []byte) string {
	if len(src) == 0 {
		return ""
	}
	out := make([]byte, 0, (len(src)*8+4)/5)
	var acc uint32
	var bits uint
	for _, b := range src {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, b32alpha[(acc>>bits)&0x1f])
		}
	}
	if bits > 0 {
		out = append(out, b32alpha[(acc<<(5-bits))&0x1f])
	}
	return string(out)
}

func b32Decode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)*5/8)
	var acc uint32
	var bits uint
	for i := 0; i < len(s); i++ {
		v := b32rev[s[i]]
		if v < 0 {
			return nil, errors.New("bad base32 char")
		}
		acc = acc<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// upstream header
// ---------------------------------------------------------------------------

type upHdr struct {
	FragID  uint16
	FragIdx uint8
	Flags   uint8
}

func appendUpHdr(dst []byte, h upHdr, data []byte) []byte {
	var b [4]byte
	binary.BigEndian.PutUint16(b[0:], h.FragID)
	b[2] = h.FragIdx
	b[3] = h.Flags
	dst = append(dst, b[:]...)
	return append(dst, data...)
}

func decodeUpHdr(b []byte) (upHdr, []byte, error) {
	if len(b) < 4 {
		return upHdr{}, nil, errors.New("short upstream header")
	}
	return upHdr{
		FragID:  binary.BigEndian.Uint16(b[0:]),
		FragIdx: b[2],
		Flags:   b[3],
	}, b[4:], nil
}

// ---------------------------------------------------------------------------
// downstream header
// ---------------------------------------------------------------------------

func appendDownHdr(dst []byte, seq uint16, flags uint8) []byte {
	var b [3]byte
	binary.BigEndian.PutUint16(b[0:], seq)
	b[2] = flags
	return append(dst, b[:]...)
}

func decodeDownHdr(b []byte) (uint16, uint8, []byte, error) {
	if len(b) < 3 {
		return 0, 0, nil, errors.New("short downstream header")
	}
	return binary.BigEndian.Uint16(b[0:]), b[2], b[3:], nil
}

// ---------------------------------------------------------------------------
// query name layout helpers
// ---------------------------------------------------------------------------

// splitQueryName returns the labels of the query name (lowercased for logic)
// and the original-case name for echoing back.
func splitQueryName(name string) (lower []string, orig []string) {
	name = strings.TrimSuffix(name, ".")
	orig = strings.Split(name, ".")
	lower = make([]string, len(orig))
	for i, l := range orig {
		lower[i] = strings.ToLower(l)
	}
	return lower, orig
}

// buildQueryName assembles <b32(hdr||data)> . <sid> . <zone> with the base32
// blob split into <=63-char labels.
func buildQueryName(blob string, sid, zone string) string {
	var labels []string
	for len(blob) > 63 {
		labels = append(labels, blob[:63])
		blob = blob[63:]
	}
	if len(blob) > 0 {
		labels = append(labels, blob)
	}
	labels = append(labels, sid)
	return strings.Join(labels, ".") + "." + zone
}

// wireLen returns the encoded length of a dotted name (labels + length bytes +
// root byte) - used to compute how much room a response has left.
func wireLen(name string) int {
	n := 1 // root label
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" {
			continue
		}
		n += 1 + len(l)
	}
	return n
}

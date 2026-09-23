package main

import (
	"encoding/binary"
	"errors"
	"strings"
)

// ---------------------------------------------------------------------------
// Minimal DNS wire codec (only what the FalconDNS protocol needs)
// ---------------------------------------------------------------------------

type dnsQuestion struct {
	Name   string
	QType  uint16
	QClass uint16
}

type dnsQuery struct {
	ID          uint16
	Flags       uint16
	Q           dnsQuestion
	EdnsPresent bool
	EdnsUDPSize uint16
}

type dnsAnswer struct {
	Name string // owner name (used for authority records; answers use a pointer)
	Type uint16
	Data []byte
	TTL  uint32
}

var errShortPacket = errors.New("short dns packet")

// parseName decodes a (possibly compressed) name starting at off.
func parseName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	ptr := 0
	for {
		if off >= len(msg) {
			return "", 0, errShortPacket
		}
		b := msg[off]
		switch {
		case b == 0:
			off++
			if next < 0 {
				next = off
			}
			return strings.Join(labels, "."), next, nil
		case b&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", 0, errShortPacket
			}
			p := int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
			if next < 0 {
				next = off + 2
			}
			ptr++
			if ptr > 16 {
				return "", 0, errors.New("compression loop")
			}
			off = p
		default:
			l := int(b)
			if off+1+l > len(msg) {
				return "", 0, errShortPacket
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

func parseDNSQuery(msg []byte) (*dnsQuery, error) {
	if len(msg) < 12 {
		return nil, errShortPacket
	}
	q := &dnsQuery{
		ID:    binary.BigEndian.Uint16(msg[0:]),
		Flags: binary.BigEndian.Uint16(msg[2:]),
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	ns := int(binary.BigEndian.Uint16(msg[8:]))
	ar := int(binary.BigEndian.Uint16(msg[10:]))
	off := 12
	if qd < 1 {
		return nil, errors.New("no question")
	}
	name, noff, err := parseName(msg, off)
	if err != nil {
		return nil, err
	}
	if noff+4 > len(msg) {
		return nil, errShortPacket
	}
	q.Q = dnsQuestion{
		Name:   name,
		QType:  binary.BigEndian.Uint16(msg[noff:]),
		QClass: binary.BigEndian.Uint16(msg[noff+2:]),
	}
	off = noff + 4
	// skip any further questions (there never are, but be safe)
	for i := 1; i < qd; i++ {
		_, off, err = parseName(msg, off)
		if err != nil {
			return nil, err
		}
		off += 4
	}
	// skip answer / authority records
	for i := 0; i < an+ns; i++ {
		_, off, err = parseName(msg, off)
		if err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errShortPacket
		}
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10 + rdlen
	}
	// additional records: look for OPT (type 41) and its options
	for i := 0; i < ar; i++ {
		_, noff, err = parseName(msg, off)
		if err != nil {
			return nil, err
		}
		if noff+10 > len(msg) {
			return nil, errShortPacket
		}
		typ := binary.BigEndian.Uint16(msg[noff:])
		class := binary.BigEndian.Uint16(msg[noff+2:])
		rdlen := int(binary.BigEndian.Uint16(msg[noff+8:]))
		off = noff + 10
		if off+rdlen > len(msg) {
			return nil, errShortPacket
		}
		if typ == 41 {
			q.EdnsPresent = true
			q.EdnsUDPSize = class
		}
		off += rdlen
	}
	return q, nil
}

// buildDNSResponse builds a response that echoes the question and appends the
// given answers (name compressed to the question at offset 12). TTL is 0 so
// recursive resolvers never cache tunnel traffic.
func buildDNSResponse(q *dnsQuery, answers []dnsAnswer, rcode uint16) []byte {
	return buildDNSResponseAuth(q, answers, nil, rcode)
}

// buildDNSResponseAuth also emits authority records (used for SOA on NODATA).
func buildDNSResponseAuth(q *dnsQuery, answers []dnsAnswer, authority []dnsAnswer, rcode uint16) []byte {
	buf := make([]byte, 0, 512)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:], q.ID)
	flags := uint16(0x8000) | uint16(0x0400) | uint16(0x0080) | (q.Flags & 0x0100) | (rcode & 0x000f)
	binary.BigEndian.PutUint16(hdr[2:], flags)
	binary.BigEndian.PutUint16(hdr[4:], 1)
	binary.BigEndian.PutUint16(hdr[6:], uint16(len(answers)))
	binary.BigEndian.PutUint16(hdr[8:], uint16(len(authority)))
	ar := uint16(0)
	if q.EdnsPresent {
		ar = 1
	}
	binary.BigEndian.PutUint16(hdr[10:], ar)
	buf = append(buf, hdr[:]...)

	for _, l := range strings.Split(q.Q.Name, ".") {
		if l == "" {
			continue
		}
		if len(l) > 63 {
			l = l[:63]
		}
		buf = append(buf, byte(len(l)))
		buf = append(buf, l...)
	}
	buf = append(buf, 0)
	var qb [4]byte
	binary.BigEndian.PutUint16(qb[0:], q.Q.QType)
	binary.BigEndian.PutUint16(qb[2:], q.Q.QClass)
	buf = append(buf, qb[:]...)

	appendRR := func(a dnsAnswer, ptr bool) {
		if ptr {
			buf = append(buf, 0xc0, 0x0c) // pointer to question name
		} else {
			for _, l := range strings.Split(a.Name, ".") {
				if l == "" {
					continue
				}
				if len(l) > 63 {
					l = l[:63]
				}
				buf = append(buf, byte(len(l)))
				buf = append(buf, l...)
			}
			buf = append(buf, 0)
		}
		var ah [10]byte
		binary.BigEndian.PutUint16(ah[0:], a.Type)
		binary.BigEndian.PutUint16(ah[2:], 1) // IN
		binary.BigEndian.PutUint32(ah[4:], a.TTL)
		binary.BigEndian.PutUint16(ah[8:], uint16(len(a.Data)))
		buf = append(buf, ah[:]...)
		buf = append(buf, a.Data...)
	}
	for _, a := range answers {
		appendRR(a, true)
	}
	for _, a := range authority {
		appendRR(a, false)
	}

	if q.EdnsPresent {
		size := q.EdnsUDPSize
		if size < 512 {
			size = 512
		}
		buf = append(buf, 0) // root name
		var ob [10]byte
		binary.BigEndian.PutUint16(ob[0:], 41)
		binary.BigEndian.PutUint16(ob[2:], size)
		binary.BigEndian.PutUint32(ob[4:], 0)
		binary.BigEndian.PutUint16(ob[8:], 0)
		buf = append(buf, ob[:]...)
	}
	return buf
}

// encodeName encodes a dotted name as DNS labels.
func encodeName(name string) []byte {
	var out []byte
	for _, l := range strings.Split(name, ".") {
		if l == "" {
			continue
		}
		if len(l) > 63 {
			l = l[:63]
		}
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0)
}

// txtRecords splits payload into TXT rdata (each string <=255 bytes).
func txtRecords(payload []byte) [][]byte {
	var out [][]byte
	for len(payload) > 0 {
		n := len(payload)
		if n > 255 {
			n = 255
		}
		chunk := make([]byte, 0, n+1)
		chunk = append(chunk, byte(n))
		chunk = append(chunk, payload[:n]...)
		out = append(out, chunk)
		payload = payload[n:]
	}
	if len(out) == 0 {
		out = append(out, []byte{0})
	}
	return out
}

// txtRdata builds TXT rdata (a sequence of <=255-byte character-strings) from
// an arbitrary payload, returned as one contiguous rdata blob.
func txtRdata(payload []byte) []byte {
	out := make([]byte, 0, len(payload)+len(payload)/255+1)
	for len(payload) > 0 {
		n := len(payload)
		if n > 255 {
			n = 255
		}
		out = append(out, byte(n))
		out = append(out, payload[:n]...)
		payload = payload[n:]
	}
	if len(out) == 0 {
		out = append(out, 0)
	}
	return out
}

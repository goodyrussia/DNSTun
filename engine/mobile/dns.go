package mobile

// dns.go — local DNS forwarder.
//
// Listens on 127.0.0.1:53 (UDP+TCP) and forwards every query as a TCP stream
// THROUGH THE TUNNEL (SOCKS5 CONNECT -> VPS -> 8.8.8.8:53). DNS-over-TCP rides
// the same verified TCP path as all other traffic: nothing depends on the
// carrier resolver answering the engine directly from inside an active VPN
// (the failure mode that killed v2.8.0 on the phone).
//
// UDP requests are answered over UDP; TCP requests over TCP. A tiny LRU cache
// keeps repeat lookups (the majority on a phone) off the tunnel entirely.

import (
	"fmt"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

type dnsEntry struct {
	msg []byte
	exp time.Time
}

type dnsCache struct {
	mu sync.Mutex
	m  map[string]dnsEntry
}

func (c *dnsCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.exp) {
		return nil, false
	}
	return e.msg, true
}

func (c *dnsCache) put(key string, msg []byte) {
	// TTL from the answer; clamp to [30s, 10min]
	ttl := uint32(300)
	if len(msg) >= 13 {
		// walk to the answer section for the first RR TTL
		qd := int(binary.BigEndian.Uint16(msg[4:6]))
		an := int(binary.BigEndian.Uint16(msg[6:8]))
		off := 12
		for i := 0; i < qd && off < len(msg); {
			l := int(msg[off])
			if l == 0 {
				off += 5
				break
			}
			if l&0xC0 != 0 {
				off += 2
				break
			}
			off += 1 + l
			i++
		}
		off += 4 // qtype+qclass
		if an > 0 && off+10 <= len(msg) {
			ttl = binary.BigEndian.Uint32(msg[off+4 : off+8])
		}
	}
	if ttl < 30 {
		ttl = 30
	}
	if ttl > 600 {
		ttl = 600
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putLocked(key, msg, ttl)
}

func (c *dnsCache) putLocked(key string, msg []byte, ttl uint32) {
	if c.m == nil {
		c.m = map[string]dnsEntry{}
	}
	if len(c.m) >= 512 {
		// drop everything on overflow; phone DNS sets are small and repopulate
		c.m = map[string]dnsEntry{}
	}
	c.m[key] = dnsEntry{msg: msg, exp: time.Now().Add(time.Duration(ttl) * time.Second)}
}

var upDNS = &dnsCache{m: map[string]dnsEntry{}}

// Direct-vs-tunnel DNS resolution.
//
// direct: the query goes straight from the engine's own socket to the carrier
// resolver — the very same socket the tunnel transport uses, so reachability
// is identical to the tunnel itself, one RTT, no stream setup. This is what
// Hamara's pdnsd does and it is the fast path.
// tunnel: DNS-over-TCP through the tunnel. Slower but works whenever the
// tunnel works, so it is the fallback.
var (
	dnsDirectUp  string
	dnsUseDirect bool
)

func (t *Tunnel) resolveQuery(q []byte) ([]byte, error) {
	if dnsUseDirect && dnsDirectUp != "" {
		if a, err := dnsDirectQuery(dnsDirectUp, q); err == nil && len(a) >= 12 {
			return a, nil
		}
	}
	return t.dnsOverTunnel(q)
}

func dnsDirectQuery(up string, q []byte) ([]byte, error) {
	c, err := net.DialTimeout("udp", up, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

// serveDNS runs the UDP and TCP listeners.
func (t *Tunnel) serveDNS(addr string) {
	if strings.HasPrefix(addr, "udp:") {
		go t.dnsUDP(addr[4:])
		go t.dnsTCP(strings.TrimSuffix(addr[4:], "0") + "0") // same port, tcp
		return
	}
	go t.dnsUDP(addr)
	go t.dnsTCP(addr)
}

func (t *Tunnel) dnsUDP(laddr string) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		log.Printf("dns udp listen: %v", err)
		return
	}
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func(q []byte, from net.Addr) {
			key := dnsKey(q)
			if a, ok := upDNS.get(key); ok {
				pc.WriteTo(a, from)
				return
			}
			a, err := t.resolveQuery(q)
			if err != nil || len(a) < 12 {
				log.Printf("dns udp: query failed: %v (len=%d)", err, len(a))
				// SERVFAIL so the app fails fast instead of hanging
				a = servfail(q)
			} else {
				upDNS.put(key, a)
			}
			pc.WriteTo(a, from)
		}(q, from)
	}
}

func (t *Tunnel) dnsTCP(laddr string) {
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		log.Printf("dns tcp listen: %v", err)
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(15 * time.Second))
			var l [2]byte
			if _, err := readFull(c, l[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(l[:]))
			q := make([]byte, n)
			if _, err := readFull(c, q); err != nil {
				return
			}
			key := dnsKey(q)
			var a []byte
			if v, ok := upDNS.get(key); ok {
				a = v
			} else {
				a, err = t.resolveQuery(q)
				if err != nil || len(a) < 12 {
					log.Printf("dns tcp: query failed: %v (len=%d)", err, len(a))
					a = servfail(q)
				} else {
					upDNS.put(key, a)
				}
			}
			r := make([]byte, 2+len(a))
			binary.BigEndian.PutUint16(r[:2], uint16(len(a)))
			copy(r[2:], a)
			c.Write(r)
		}(c)
	}
}

// dnsOverTunnel sends one DNS query as TCP to 8.8.8.8:53 through the tunnel.
func (t *Tunnel) dnsOverTunnel(q []byte) ([]byte, error) {
	c, err := t.dialViaSocks("8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(12 * time.Second))
	w := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(w[:2], uint16(len(q)))
	copy(w[2:], q)
	if _, err := c.Write(w); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := readFull(c, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n == 0 || n > 65535 {
		return nil, fmt.Errorf("bad dns reply length")
	}
	a := make([]byte, n)
	if _, err := readFull(c, a); err != nil {
		return nil, err
	}
	return a, nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	tot := 0
	for tot < len(b) {
		n, err := c.Read(b[tot:])
		tot += n
		if err != nil {
			return tot, err
		}
	}
	return tot, nil
}

func dnsKey(q []byte) string {
	// key on name+type, ignoring the query id
	if len(q) < 12 {
		return string(q)
	}
	// find end of qname
	off := 12
	for off < len(q) {
		l := int(q[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 != 0 {
			off += 2
			break
		}
		off += 1 + l
	}
	if off+4 > len(q) {
		return string(q)
	}
	return strings.ToLower(string(q[12:off])) + string(q[off:off+4])
}

func servfail(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	a := append([]byte(nil), q[:12]...)
	a[2] &= 0x78 // clear QR/opcode-dependent bits we set below
	a[2] = q[2]&0x70 | 0x80
	a[3] = 0x82 // RA, RCODE=2 (SERVFAIL)
	binary.BigEndian.PutUint16(a[6:8], 0)
	return a
}

// ---- fast-path helpers ----------------------------------------------------

// skipQName returns the offset just past a (possibly compressed) QNAME.
func skipQName(q []byte, off int) (int, bool) {
	for off < len(q) {
		l := int(q[off])
		if l == 0 {
			return off + 1, true
		}
		if l&0xC0 == 0xC0 {
			if off+2 > len(q) {
				return 0, false
			}
			return off + 2, true
		}
		if l&0xC0 != 0 || off+1+l > len(q) {
			return 0, false
		}
		off += 1 + l
	}
	return 0, false
}

// isAAAAQuery reports whether the first question asks for AAAA (type 28).
func isAAAAQuery(q []byte) bool {
	off, ok := skipQName(q, 12)
	if !ok || off+2 > len(q) {
		return false
	}
	return binary.BigEndian.Uint16(q[off:off+2]) == 28
}

// noDataAAAA answers an AAAA query with NOERROR/NODATA. The tunnel is
// IPv4-only and the TUN has no IPv6 route, so an AAAA answer can never be
// used; answering instantly makes apps fall back to A with no round trip
// (the same trick SlipNet's DnsUtils uses).
func noDataAAAA(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	off, ok := skipQName(q, 12)
	if !ok || off+4 > len(q) {
		return servfail(q)
	}
	a := append([]byte(nil), q[:off+4]...)
	a[2] = q[2]&0x79 | 0x80 // QR=1, keep opcode + RD
	a[3] = 0x80             // RA=1, RCODE=0 (NOERROR)
	binary.BigEndian.PutUint16(a[6:8], 0)
	binary.BigEndian.PutUint16(a[8:10], 0)
	binary.BigEndian.PutUint16(a[10:12], 0)
	return a
}

// qnameUnder reports whether the first question name ends with "."+zone
// (case-insensitive). Used to recognise our own transport queries.
func qnameUnder(q []byte, zone string) bool {
	if len(q) < 12 || zone == "" {
		return false
	}
	var sb strings.Builder
	off := 12
	for off < len(q) {
		l := int(q[off])
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || off+1+l > len(q) {
			return false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(q[off+1 : off+1+l])
		off += 1 + l
	}
	return strings.HasSuffix(strings.ToLower(sb.String()), "."+strings.ToLower(zone))
}

// buildTXTQuery builds a minimal TXT query for name.
func buildTXTQuery(name string) []byte {
	q := make([]byte, 12, 12+len(name)+5)
	r := rand.Uint32()
	q[0] = byte(r)
	q[1] = byte(r >> 8)
	q[2] = 0x01 // RD
	q[5] = 1    // QDCOUNT
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			continue
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 16, 0, 1) // end of QNAME, QTYPE=TXT, QCLASS=IN
	return q
}

// selfCheck verifies the engine's own UDP sockets are OUTSIDE the VPN
// (addDisallowedApplication on the app UID). It sends a TXT query for a
// random name in our own zone straight to the carrier resolver: the
// authoritative server answers every in-zone TXT, so any reply proves the
// socket is excluded. A captured query would instead come back to our own
// FWD_UDP handler (which drops in-zone names) and time out.
func (t *Tunnel) selfCheck() {
	name := fmt.Sprintf("sc%d.%s", rand.Uint32(), t.zone)
	q := buildTXTQuery(name)
	a, err := dnsDirectQuery(t.resolver, q)
	if err == nil && len(a) >= 12 {
		log.Printf("SELFCHECK excluded=yes resolver=%s reply=%dB", t.resolver, len(a))
		return
	}
	log.Printf("SELFCHECK excluded=NO resolver=%s err=%v", t.resolver, err)
}

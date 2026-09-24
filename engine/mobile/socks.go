package mobile

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// serveSOCKS accepts SOCKS5 CONNECT (TCP), UDP ASSOCIATE and FWD_UDP
// (cmd 0x05, the udp:'tcp' framing hev-socks5-tunnel uses) requests.
func (t *Tunnel) serveSOCKS(addr string) error {
	if err := t.listen(addr); err != nil {
		return err
	}
	return t.serve()
}

// listen binds the SOCKS5 listener so Start() can fail fast on a busy port.
func (t *Tunnel) listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	t.ln = ln
	log.Printf("socks5 listening on %s", addr)
	return nil
}

// serve runs the accept loop until Close().
func (t *Tunnel) serve() error {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.stop:
				return nil
			default:
			}
			return err
		}
		go t.handleSocks(c)
	}
}

func (t *Tunnel) handleSocks(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	// greeting: version, nmethods, methods
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// Accept no-auth and user/pass. No-auth is preferred (loopback only);
	// user/pass is consumed and accepted with any credentials because the
	// app-side bridge chains through here with whatever the profile holds.
	noAuth, userPass := false, false
	for _, m := range methods {
		switch m {
		case 0x00:
			noAuth = true
		case 0x02:
			userPass = true
		}
	}
	switch {
	case noAuth:
		if _, err := c.Write([]byte{5, 0}); err != nil {
			return
		}
	case userPass:
		if _, err := c.Write([]byte{5, 2}); err != nil {
			return
		}
		// RFC 1929: ver(1) ulen(1) uname plen(1) passwd
		ah := make([]byte, 2)
		if _, err := io.ReadFull(c, ah); err != nil || ah[0] != 1 {
			return
		}
		ub := make([]byte, int(ah[1]))
		if _, err := io.ReadFull(c, ub); err != nil {
			return
		}
		pl := make([]byte, 1)
		if _, err := io.ReadFull(c, pl); err != nil {
			return
		}
		pb := make([]byte, int(pl[0]))
		if _, err := io.ReadFull(c, pb); err != nil {
			return
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return
		}
	default:
		c.Write([]byte{5, 0xFF})
		return
	}

	// request: ver, cmd, rsv, atyp, addr, port
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != 5 {
		return
	}
	cmd := req[1]
	var host string
	switch req[3] {
	case 1: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 4: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)

	if cmd == 5 { // FWD_UDP: hev-socks5-tunnel udp:'tcp' (SlipNet recipe)
		t.handleFwdUDP(c)
		return
	}
	if cmd == 3 { // UDP ASSOCIATE: legacy tun2socks path
		t.handleUDPAssociate(c)
		return
	}
	if cmd != 1 { // CONNECT only from here on
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	log.Printf("connect %s", target)

	// success reply, then bridge
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	c.SetDeadline(time.Time{})

	s := t.newStream(target, c)
	defer func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		t.enqueue(&upFrag{streamID: s.id, seq: s.nextSeq, flags: upFIN})
		t.dropStream(s.id)
	}()

	// client -> tunnel
	buf := make([]byte, 8192)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			s.sendUp(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

var _ = fmt.Sprintf

// ---- SOCKS5 UDP ASSOCIATE -------------------------------------------------
//
// hev-socks5-tunnel forwards every UDP datagram (i.e. ALL of Android's DNS) as
// a SOCKS5 UDP ASSOCIATE request. The old engine implemented only CONNECT, so
// every DNS query was rejected with "command not supported" -- the phone
// "connected" but no domain ever resolved and nothing loaded.
//
// DNS is answered DIRECTLY through the carrier resolver (the same one the
// tunnel itself uses), exactly like Hamara Tunnel's Pdnsd design: DNS never
// rides the tunnel, so name resolution is as fast as the carrier allows, and
// carrier + VPS are both UK so CDN answers match the exit region. Only TCP
// (the actual payload) goes through the DNS tunnel. Other UDP (QUIC/443) is
// silently dropped so apps fall back to TCP 443, which the tunnel carries.
var dbgUDPN int

func (t *Tunnel) handleUDPAssociate(c net.Conn) {
	// Bind 0.0.0.0: a 127.0.0.1-bound socket sends the DNS query with a
	// loopback source address, which is unroutable from outside -- the
	// resolver's reply never comes back. 0.0.0.0 lets the kernel pick the
	// real source address per route.
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: nil})
	if err != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer relay.Close()

	// success: BND.ADDR 127.0.0.1, BND.PORT = relay port
	laddr := relay.LocalAddr().(*net.UDPAddr)
	port := laddr.Port
	rep := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	if _, err := c.Write(rep); err != nil {
		return
	}
	c.SetDeadline(time.Time{}) // control conn lives for the whole session

	// TCP control closing ends the association
	go func() {
		io.Copy(io.Discard, c)
		relay.Close()
	}()

	resolver := t.addr()
	log.Printf("udp-assoc open, relay=%s, resolver=%v", relay.LocalAddr(), resolver)
	var clientAddr *net.UDPAddr
	buf := make([]byte, 65536)
	for {
		n, from, err := relay.ReadFromUDP(buf)
		if err != nil {
			log.Printf("udp-assoc relay closed: %v", err)
			return
		}
		if dbgUDPN < 12 {
			dbgUDPN++
			log.Printf("udp-assoc RX %dB from %v (client=%v)", n, from, clientAddr)
		}
		if clientAddr == nil {
			clientAddr = from // the SOCKS client always speaks first
		}
		if n < 4 {
			continue
		}
		if buf[2] != 0 { // FRAG != 0: no fragmentation support needed for DNS
			continue
		}
		// parse the SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) ADDR(n) PORT(2)
		var dport int
		var payload []byte
		switch buf[3] {
		case 1:
			if n < 10 { continue }
			dport = int(binary.BigEndian.Uint16(buf[8:10]))
			payload = buf[10:n]
		case 3:
			l := int(buf[4])
			if n < 7+l+2 { continue }
			dport = int(binary.BigEndian.Uint16(buf[5+l : 7+l]))
			payload = buf[7+l : n]
		case 4:
			if n < 22 { continue }
			dport = int(binary.BigEndian.Uint16(buf[20:22]))
			payload = buf[22:n]
		default:
			continue
		}
		if dport != 53 || len(payload) == 0 {
			continue // drop QUIC etc. -> apps fall back to TCP through the tunnel
		}
		// Resolve ALL port-53 datagrams locally through the tunnel (dns.go):
		// one DNS path, always DNS-over-TCP through the tunnel, no dependence
		// on the carrier answering the engine directly from inside the VPN.
		if clientAddr != nil {
			go func(q []byte, client *net.UDPAddr, id []byte) {
				a, err := t.dnsOverTunnel(q)
				if err != nil || len(a) < 12 {
					log.Printf("udp-assoc dns: %v", err)
					a = servfail(q)
				}
				resp := append(append([]byte(nil), id...), a...)
				relay.WriteToUDP(resp, client)
			}(append([]byte(nil), payload...), clientAddr, buf[:10])
		}
	}
}


// ---- SOCKS5 FWD_UDP (cmd 0x05) --------------------------------------------
//
// hev-socks5-tunnel in udp:'tcp' mode sends every UDP datagram on this
// connection as frames (same wire format SlipNet's bridges implement):
//
//	datLen(2 BE) | hdrLen(1) | addr(hdrLen-3) | payload(datLen)
//
// All of Android's DNS arrives here: the TUN's DNS server is the carrier
// resolver and hev forwards every UDP packet to this connection. DNS is
// answered by resolveQuery (carrier first, tunnel fallback, LRU cache);
// other UDP is dropped so apps fall back to TCP, which the tunnel carries.
func (t *Tunnel) handleFwdUDP(c net.Conn) {
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	log.Printf("fwd-udp session open")

	var wmu sync.Mutex
	sem := make(chan struct{}, 64)

	for {
		hdr := make([]byte, 3)
		if _, err := io.ReadFull(c, hdr); err != nil {
			log.Printf("fwd-udp session end: %v", err)
			return
		}
		datLen := int(binary.BigEndian.Uint16(hdr[0:2]))
		hdrLen := int(hdr[2])
		addrLen := hdrLen - 3
		if addrLen <= 0 || datLen <= 0 {
			log.Printf("fwd-udp bad frame datLen=%d hdrLen=%d", datLen, hdrLen)
			return
		}
		addrBytes := make([]byte, addrLen)
		if _, err := io.ReadFull(c, addrBytes); err != nil {
			return
		}
		payload := make([]byte, datLen)
		if _, err := io.ReadFull(c, payload); err != nil {
			return
		}
		dport := 0
		if addrLen >= 2 {
			dport = int(binary.BigEndian.Uint16(addrBytes[addrLen-2:]))
		}
		if dport != 53 || len(payload) < 12 {
			continue // QUIC etc: dropped -> apps fall back to TCP
		}
		// Never resolve our own transport queries: if they arrive here the
		// VPN captured them (socket-exclusion failure) and resolving would
		// recurse forever. Dropping keeps that failure quiet instead.
		if qnameUnder(payload, t.zone) {
			continue
		}

		sem <- struct{}{}
		go func(q []byte, ab []byte) {
			defer func() { <-sem }()
			var a []byte
			if isAAAAQuery(q) {
				// IPv4-only tunnel: fail AAAA instantly so apps fall back
				// to A without a round trip.
				a = noDataAAAA(q)
			} else {
				key := dnsKey(q)
				if v, ok := upDNS.get(key); ok {
					a = v
				} else {
					var err error
					a, err = t.resolveQuery(q)
					if err != nil || len(a) < 12 {
						log.Printf("fwd-udp dns: %v", err)
						a = servfail(q)
					} else {
						upDNS.put(key, a)
					}
				}
			}
			if len(a) == 0 {
				return
			}
			frame := make([]byte, 3+len(ab)+len(a))
			binary.BigEndian.PutUint16(frame[0:2], uint16(len(a)))
			frame[2] = byte(3 + len(ab))
			copy(frame[3:], ab)
			copy(frame[3+len(ab):], a)
			wmu.Lock()
			_, err := c.Write(frame)
			wmu.Unlock()
			_ = err
		}(payload, addrBytes)
	}
}

// dialViaSocks performs the SOCKS5 CONNECT handshake on our own listener and
// returns the established stream connection (tunnel bridged).
func (t *Tunnel) dialViaSocks(target string) (net.Conn, error) {
	c, err := net.Dial("tcp", t.socksAddr)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil || rep[0] != 5 || rep[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks greeting: %v", err)
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		c.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	ans := make([]byte, 4)
	if _, err := io.ReadFull(c, ans); err != nil {
		c.Close()
		return nil, err
	}
	switch ans[3] {
	case 1:
		ans = make([]byte, 6)
	case 4:
		ans = make([]byte, 18)
	default: // 3
		al := make([]byte, 1)
		if _, err := io.ReadFull(c, al); err != nil {
			c.Close()
			return nil, err
		}
		ans = make([]byte, int(al[0])+2)
	}
	if _, err := io.ReadFull(c, ans); err != nil {
		c.Close()
		return nil, err
	}
	if ans[1] != 0 && len(ans) > 1 {
		c.Close()
		return nil, fmt.Errorf("socks connect failed")
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

// Command e2e exercises the engine the way the Android app drives it:
// start on a local SOCKS5 port, then (1) SOCKS5 CONNECT + HTTP through the
// tunnel, (2) hev's udp:'tcp' FWD_UDP framing carrying a real DNS query.
//
//	go run ./cmd/e2e -resolver 8.8.8.8:53 -zone v.techychi.com -sid g7x2k9
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"dnstun/engine/mobile"
)

func main() {
	resolver := flag.String("resolver", "8.8.8.8:53", "resolver the tunnel queries go to")
	zone := flag.String("zone", "v.techychi.com", "tunnel zone")
	sid := flag.String("sid", "g7x2k9", "session id")
	flag.Parse()

	listen := "127.0.0.1:7301"
	c, err := mobile.NewClient(*resolver, *zone, *sid, listen)
	if err != nil {
		fail("NewClient: %v", err)
	}
	if err := c.Start(); err != nil {
		fail("Start: %v", err)
	}
	defer c.Stop()
	time.Sleep(300 * time.Millisecond)

	ok := true
	if err := testTCP(listen); err != nil {
		fmt.Printf("FAIL tcp: %v\n", err)
		ok = false
	} else {
		fmt.Println("OK   tcp: HTTP through tunnel")
	}
	if err := testFwdUDP(listen); err != nil {
		fmt.Printf("FAIL fwd-udp: %v\n", err)
		ok = false
	} else {
		fmt.Println("OK   fwd-udp: DNS through tunnel")
	}
	if err := testQUICDrop(listen); err != nil {
		fmt.Printf("FAIL quic-drop: %v\n", err)
		ok = false
	} else {
		fmt.Println("OK   quic-drop: non-DNS UDP ignored")
	}
	// What the app's bridge actually does for DNS: DNS-over-TCP through the
	// tunnel (SOCKS CONNECT to a resolver on port 53, 2-byte length prefix).
	if err := testDNSOverTCP(listen); err != nil {
		fmt.Printf("FAIL dns-over-tcp: %v\n", err)
		ok = false
	} else {
		fmt.Println("OK   dns-over-tcp: resolver reachable through tunnel")
	}
	if !ok {
		os.Exit(1)
	}
}

// testDNSOverTCP mirrors DnsttSocksBridge.sendDnsQuery: CONNECT to a resolver
// on :53 through the tunnel and answer a framed DNS query.
func testDNSOverTCP(listen string) error {
	conn, err := dial(listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(45 * time.Second))
	if err := socksConnect(conn, "8.8.8.8", 53); err != nil {
		return err
	}
	query := buildDNSQuery("example.com")
	frame := append([]byte{byte(len(query) >> 8), byte(len(query) & 0xff)}, query...)
	if _, err := conn.Write(frame); err != nil {
		return err
	}
	respLen := make([]byte, 2)
	if _, err := io.ReadFull(conn, respLen); err != nil {
		return fmt.Errorf("read length prefix: %w", err)
	}
	n := int(binary.BigEndian.Uint16(respLen))
	if n < 12 {
		return fmt.Errorf("short response (%d bytes)", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if rcode := resp[3] & 0x0f; rcode != 0 {
		return fmt.Errorf("DNS rcode %d", rcode)
	}
	if binary.BigEndian.Uint16(resp[6:8]) == 0 {
		return fmt.Errorf("DNS response has no answers")
	}
	return nil
}

func fail(format string, a ...any) {
	fmt.Printf("FATAL "+format+"\n", a...)
	os.Exit(2)
}

func dial(listen string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", listen, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// socksConnect performs the greeting + CONNECT and returns the open conn.
func socksConnect(conn net.Conn, host string, port uint16) error {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return err
	}
	if rep[0] != 5 || rep[1] != 0 {
		return fmt.Errorf("greeting reply %v", rep)
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0 {
		return fmt.Errorf("connect reply code %d", resp[1])
	}
	return nil
}

func testTCP(listen string) error {
	conn, err := dial(listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(45 * time.Second))
	if err := socksConnect(conn, "example.com", 80); err != nil {
		return err
	}
	req := "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	buf := make([]byte, 512)
	conn.SetDeadline(time.Now().Add(45 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	head := string(buf[:n])
	if !strings.HasPrefix(head, "HTTP/") {
		return fmt.Errorf("unexpected response: %q", head[:min(60, len(head))])
	}
	return nil
}

// testFwdUDP mimics hev-socks5-tunnel udp:'tcp': cmd 0x05, then frames of
// datLen(2) | hdrLen(1) | atyp+addr+port | payload.
func testFwdUDP(listen string) error {
	conn, err := dial(listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return err
	}
	// FWD_UDP request: cmd 0x05, addr 0.0.0.0:0
	if _, err := conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	ack := make([]byte, 10)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return err
	}
	if ack[1] != 0 {
		return fmt.Errorf("fwd-udp reply code %d", ack[1])
	}

	query := buildDNSQuery("example.com")
	addr := []byte{1, 8, 8, 8, 8, 0, 53} // atyp=1, 8.8.8.8, port 53
	frame := make([]byte, 0, 3+len(addr)+len(query))
	frame = append(frame, byte(len(query)>>8), byte(len(query)&0xff), byte(3+len(addr)))
	frame = append(frame, addr...)
	frame = append(frame, query...)
	if _, err := conn.Write(frame); err != nil {
		return err
	}

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	hdr := make([]byte, 3)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("read reply header: %w", err)
	}
	datLen := int(binary.BigEndian.Uint16(hdr[0:2]))
	hdrLen := int(hdr[2])
	if datLen <= 0 || hdrLen <= 3 {
		return fmt.Errorf("bad reply header datLen=%d hdrLen=%d", datLen, hdrLen)
	}
	rest := make([]byte, hdrLen-3+datLen)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return err
	}
	resp := rest[hdrLen-3:]
	if len(resp) < 12 {
		return fmt.Errorf("short DNS response (%d bytes)", len(resp))
	}
	rcode := resp[3] & 0x0f
	answers := binary.BigEndian.Uint16(resp[6:8])
	if rcode != 0 {
		return fmt.Errorf("DNS rcode %d", rcode)
	}
	if answers == 0 {
		return fmt.Errorf("DNS response has no answers")
	}
	return nil
}

// testQUICDrop checks that a non-DNS UDP datagram is not answered (apps then
// fall back to TCP, which the tunnel carries).
func testQUICDrop(listen string) error {
	conn, err := dial(listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	ack := make([]byte, 10)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return err
	}
	payload := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00} // QUIC-ish
	addr := []byte{1, 8, 8, 8, 8, 0x01, 0xbb}                                  // port 443
	frame := append([]byte{byte(len(payload) >> 8), byte(len(payload) & 0xff), byte(3 + len(addr))}, addr...)
	frame = append(frame, payload...)
	if _, err := conn.Write(frame); err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err == nil {
		return fmt.Errorf("unexpected reply to non-DNS UDP")
	}
	return nil
}

func buildDNSQuery(name string) []byte {
	id := uint16(time.Now().UnixNano() & 0xffff)
	q := make([]byte, 0, 64)
	q = append(q, byte(id>>8), byte(id))
	q = append(q, 0x01, 0x00) // RD
	q = append(q, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, part := range strings.Split(name, ".") {
		q = append(q, byte(len(part)))
		q = append(q, part...)
	}
	q = append(q, 0x00)
	q = append(q, 0x00, 0x01, 0x00, 0x01) // A IN
	return q
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// dnstun-client -- SOCKS5 proxy whose transport is a DNS tunnel.
//
// ARCHITECTURE (the pattern every shipping DNS-tunnel VPN uses):
//
//	VpnService TUN -> hev-socks5-tunnel -> SOCKS5 -> THIS -> DNS -> server
//
// hev-socks5-tunnel owns all packet handling. This program only has to speak
// SOCKS5 on one side and the dnstun stream protocol on the other, which is why
// it is small and has no packet code at all.
//
// TRANSPORT
// ---------
// One UDP socket to the carrier resolver. A pool of queries is kept in flight
// (depth) because throughput = depth / RTT, not because DNS is slow per query.
// Queries carry upstream fragments; replies carry downstream fragments. Both
// directions are sequence-numbered and retransmitted, because DNS drops
// packets silently and a lost fragment must not stall a TCP stream.
package mobile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	upSYN     = 1 << 0
	upFIN     = 1 << 1
	upPureAck = 1 << 2
	// upNACK asks the server for one specific downstream seq (carried in Seq).
	// Without it a single dropped reply freezes the contiguous ack and the
	// stream can never recover while new data keeps arriving.
	upNACK = 1 << 3

	downSYNACK = 1 << 0
	downFIN    = 1 << 1
	downDATA   = 1 << 2

	upHdrLen   = 9 // streamID(2) seq(2) flags(1) ack(2) nonce(2)
	downHdrLen = 7

	// maxUpQueue bounds the pending upstream queue. Past it, writers wait
	// instead of dropping: a silently dropped fragment used to stall the
	// stream permanently because retransmit could not keep up.
	maxUpQueue = 8192
)

const b32alpha = "abcdefghijklmnopqrstuvwxyz234567"

var b32rev = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	up := strings.ToUpper(b32alpha)
	for i := 0; i < len(b32alpha); i++ {
		t[b32alpha[i]] = int8(i)
		t[up[i]] = int8(i)
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
			return nil, errors.New("bad base32")
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

// ---------------------------------------------------------------- fragments

type upFrag struct {
	streamID uint16
	seq      uint16
	flags    uint8
	ack      uint16
	data     []byte
	sentAt   time.Time
	acked    bool
}

type downFrag struct {
	streamID uint16
	seq      uint16
	flags    uint8
	upAck    uint16
	data     []byte
}

func (f upFrag) encode() []byte {
	b := make([]byte, upHdrLen+len(f.data))
	binary.BigEndian.PutUint16(b[0:], f.streamID)
	binary.BigEndian.PutUint16(b[2:], f.seq)
	b[4] = f.flags
	binary.BigEndian.PutUint16(b[5:], f.ack)
	// Nonce: every qname must be unique or a recursive resolver serves the
	// reply from cache and our server never sees the query. Identical poll
	// qnames were being answered from cache, which is why the server logged
	// ~8 queries/s while the client sent thousands per second.
	binary.BigEndian.PutUint16(b[7:], uint16(rand.Intn(65536)))
	copy(b[upHdrLen:], f.data)
	return b
}

func decodeDown(b []byte) (downFrag, error) {
	if len(b) < downHdrLen {
		return downFrag{}, errors.New("short")
	}
	return downFrag{
		streamID: binary.BigEndian.Uint16(b[0:]),
		seq:      binary.BigEndian.Uint16(b[2:]),
		flags:    b[4],
		upAck:    binary.BigEndian.Uint16(b[5:]),
		data:     b[downHdrLen:],
	}, nil
}

func buildName(blob, sid, zone string) string {
	var labels []string
	for len(blob) > 63 {
		labels = append(labels, blob[:63])
		blob = blob[63:]
	}
	if len(blob) > 0 {
		labels = append(labels, blob)
	}
	// "t." prefix: dnsfast treats these as tunnel queries; other names get fat TXT.
	labels = append(append([]string{"t"}, labels...), sid)
	return strings.Join(labels, ".") + "." + zone
}

func buildQuery(name string, qid uint16, edns int) []byte {
	out := make([]byte, 0, 512)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], qid)
	binary.BigEndian.PutUint16(hdr[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(hdr[4:], 1)      // QDCOUNT
	// ARCOUNT must be 1 when we attach the OPT record, and it must be set
	// BEFORE hdr is appended (append copies, so writing to hdr afterwards is a
	// no-op). With ARCOUNT=0 a resolver ignores the OPT entirely, falls back to
	// a 512-byte buffer, and truncates every reply that carries real data --
	// which is why loopback worked and the real resolver path carried nothing.
	if edns > 0 {
		binary.BigEndian.PutUint16(hdr[10:], 1) // ARCOUNT
	}
	out = append(out, hdr...)
	for _, l := range strings.Split(name, ".") {
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	out = append(out, 0)
	out = append(out, 0x00, 0x10) // TXT
	out = append(out, 0x00, 0x01) // IN
	if edns > 0 {
		out = append(out, 0)                           // root
		out = append(out, 0x00, 0x29)                  // OPT
		var c [2]byte                                  //
		binary.BigEndian.PutUint16(c[:], uint16(edns)) //
		out = append(out, c[:]...)                     // udp size
		out = append(out, 0, 0, 0, 0)                  // ttl
		out = append(out, 0, 0)                        // rdlen
	}
	return out
}

// extractTXT pulls the TXT rdata out of a DNS response and concatenates the
// character-strings.
func extractTXT(msg []byte) []byte {
	if len(msg) < 12 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	i := 12
	for k := 0; k < qd; k++ {
		for i < len(msg) {
			l := int(msg[i])
			if l == 0 {
				i++
				break
			}
			if l&0xC0 != 0 {
				i += 2
				goto qdone
			}
			i += 1 + l
		}
	qdone:
		i += 4
	}
	if an == 0 || i+2 > len(msg) {
		return nil
	}
	// answer name
	if msg[i]&0xC0 == 0xC0 {
		i += 2
	} else {
		for i < len(msg) && msg[i] != 0 {
			i += 1 + int(msg[i])
		}
		i++
	}
	if i+10 > len(msg) {
		return nil
	}
	typ := binary.BigEndian.Uint16(msg[i:])
	i += 8
	rdlen := int(binary.BigEndian.Uint16(msg[i:]))
	i += 2
	if typ != 16 || i+rdlen > len(msg) {
		return nil
	}
	rd := msg[i : i+rdlen]
	var out []byte
	for j := 0; j < len(rd); {
		n := int(rd[j])
		j++
		if j+n > len(rd) {
			break
		}
		out = append(out, rd[j:j+n]...)
		j += n
	}
	return out
}

// ---------------------------------------------------------------- the tunnel

var dbgRecvN int64

type Tunnel struct {
	resolver string
	zone     string
	sid      string
	chunk    int
	depth    int // current in-flight window (AIMD-controlled)
	maxDepth int // ceiling for the window: the carrier drops us above its limit
	edns     int

	socksAddr string
	ln        net.Listener
	stop      chan struct{}
	stopOnce  sync.Once

	conn *net.UDPConn

	mu       sync.Mutex
	up       []*upFrag          // pending upstream fragments, oldest first
	inflight map[uint16]*upFrag // qid -> fragment awaiting a reply
	streams  map[uint16]*Stream

	nextStream uint32
	rr         uint32

	// stats
	qSent     int64
	qRecv     int64
	upBytes   int64
	dnBytes   int64
	retrans   int64
	lastRecv  int64
	readErrs  int64
	writeErrs int64
	upDrops   int64
	closed    int32

	// AIMD window accounting (guard with t.mu or use only in control)
	ctlSent int64
	ctlRecv int64
	// lastActive is the last time real payload moved in either direction
	// (not mere poll acks) -- the idle-backoff signal for pump().
	lastActive int64
}

type Stream struct {
	id   uint16
	t    *Tunnel
	conn net.Conn

	mu        sync.Mutex
	nextSeq   uint16
	unacked   map[uint16][]byte // sent upstream, not yet acked
	recvAck   uint16            // highest downstream seq seen
	outOfOrd  map[uint16][]byte // downstream received out of order
	expectDn  uint16
	maxSeen   uint16 // highest downstream seq seen, for gap detection
	upAckSeen uint16 // highest upstream seq the server has confirmed
	target    string // dial target, so the SYN can be retransmitted
	synAcked  bool   // server confirmed the stream exists
	closed    bool
	lastAct   time.Time
}

func NewTunnel(resolver, zone, sid, listenAddr string, chunk, depth, edns int) (*Tunnel, error) {
	c, err := net.ListenUDP("udp", nil)
	if err == nil {
		_ = c.SetReadBuffer(8 << 20)
		_ = c.SetWriteBuffer(8 << 20)
	}
	if err != nil {
		return nil, err
	}
	c.SetReadBuffer(4 << 20)
	c.SetWriteBuffer(4 << 20)
	return &Tunnel{
		resolver:  resolver,
		zone:      zone,
		sid:       sid,
		chunk:     chunk,
		depth:     depth,
		maxDepth:  depth,
		edns:      edns,
		socksAddr: listenAddr,
		stop:      make(chan struct{}),
		conn:      c,
		inflight:  make(map[uint16]*upFrag),
		streams:   make(map[uint16]*Stream),
		// Start stream ids at a random point: the client counts from 1 on every
		// run, and the server may still hold a stream with the same id from the
		// previous run. A collision corrupts the new connection.
		nextStream: uint32(rand.Intn(60000)) + 1,
	}, nil
}

func (t *Tunnel) addr() *net.UDPAddr {
	a, _ := net.ResolveUDPAddr("udp", t.resolver)
	return a
}

// enqueue adds an upstream fragment for transmission.
func (t *Tunnel) enqueue(f *upFrag) {
	if len(f.data) > 0 {
		atomic.StoreInt64(&t.lastActive, time.Now().Unix())
	}
	for {
		t.mu.Lock()
		full := len(t.up) >= maxUpQueue
		if !full || f.data == nil {
			t.up = append(t.up, f)
			t.mu.Unlock()
			return
		}
		t.mu.Unlock()
		// Payload must never be dropped: wait for the pump to drain instead.
		atomic.AddInt64(&t.upDrops, 1)
		if t.closing() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// run drives the query/reply loop. This is the only place that touches the
// socket, so there is no cross-thread blocking to deadlock on.
func (t *Tunnel) run() {
	buf := make([]byte, 4096)
	go func() { // reader
		for {
			n, _, err := t.conn.ReadFromUDP(buf)
			if err != nil {
				if t.closing() {
					return
				}
				atomic.AddInt64(&t.readErrs, 1)
				log.Printf("engine: read err (kept alive): %v", err)
				time.Sleep(20 * time.Millisecond)
				continue
			}
			msg := make([]byte, n)
			copy(msg, buf[:n])
			t.onReply(msg)
		}
	}()

	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	retick := time.NewTicker(300 * time.Millisecond)
	defer retick.Stop()
	stat := time.NewTicker(5 * time.Second)
	defer stat.Stop()
	ctick := time.NewTicker(time.Second)
	defer ctick.Stop()

	for {
		select {
		case <-tick.C:
			t.pump()
		case <-retick.C:
			t.retransmit()
		case <-ctick.C:
			t.control()
		case <-stat.C:
			t.report()
		case <-t.stop:
			return
		}
	}
}

// Close shuts the tunnel down: the SOCKS listener, the UDP transport and the
// background loops. Safe to call more than once.
func (t *Tunnel) Close() {
	atomic.StoreInt32(&t.closed, 1)
	t.stopOnce.Do(func() {
		close(t.stop)
		if t.ln != nil {
			t.ln.Close()
		}
		if t.conn != nil {
			t.conn.Close()
		}
	})
}

// closing reports whether Close has been called (transient socket errors must
// not be confused with shutdown).
func (t *Tunnel) closing() bool {
	return atomic.LoadInt32(&t.closed) == 1
}

// SetDepth sets the ceiling for the in-flight query window. The live window
// is driven by AIMD (see control) so it stays under whatever the resolver on
// the path tolerates.
func (t *Tunnel) SetDepth(d int) {
	t.mu.Lock()
	if d > 0 {
		t.maxDepth = d
		if t.depth > d {
			t.depth = d
		}
	}
	t.mu.Unlock()
}

// SetChunk changes how many upstream bytes ride in one query.
func (t *Tunnel) SetChunk(n int) {
	t.mu.Lock()
	if n >= 16 && n <= 180 {
		t.chunk = n
	}
	t.mu.Unlock()
}

// pump keeps the query pool full.
func (t *Tunnel) pump() {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Idle backoff: keep the full pipeline in flight only while real payload
	// moved within the last 5s. Full depth is how the pipe reaches
	// 6.6 MB/s, but running it 24/7 would hammer the carrier resolver (and
	// the battery) for nothing. Keyed on payload movement only: under loss
	// the in-flight window never fully drains, so a queue-length check here
	// would pin the pipe at full depth forever.
	depth := t.depth
	last := atomic.LoadInt64(&t.lastActive)
	if last == 0 || time.Now().Unix()-last > 5 {
		depth = 8
	}

	for len(t.inflight) < depth {
		var f *upFrag
		if len(t.up) > 0 {
			f = t.up[0]
			t.up = t.up[1:]
		} else if s := t.pickStreamLocked(); s != nil {
			// Idle poll MUST name a stream and carry that stream's ack.
			// A bare stream-0 poll tells the server nothing, so it can never
			// release acked data and can never advance past the oldest
			// unacked fragment -- one lost fragment then stalls the stream
			// forever and bulk transfers die mid-flight.
			s.mu.Lock()
			ack := s.recvAck
			need := uint16(0)
			if seqLessEq(s.expectDn, s.maxSeen) {
				need = s.expectDn // we are missing this exact fragment
			}
			s.mu.Unlock()
			if need != 0 {
				f = &upFrag{streamID: s.id, seq: need, flags: upNACK, ack: ack}
			} else {
				f = &upFrag{streamID: s.id, seq: 0, flags: upPureAck, ack: ack}
			}
		} else {
			f = &upFrag{streamID: 0, seq: 0, flags: 0, ack: 0}
		}
		qid := uint16(0)
		for i := 0; i < 32; i++ {
			cand := uint16(rand.Intn(65535) + 1)
			if _, busy := t.inflight[cand]; !busy {
				qid = cand
				break
			}
		}
		if qid == 0 {
			// Window saturated by collisions: put the fragment back and stop.
			if f.data != nil {
				t.up = append([]*upFrag{f}, t.up...)
			}
			break
		}
		blob := b32Encode(f.encode())
		name := buildName(blob, t.sid, t.zone)
		pkt := buildQuery(name, qid, t.edns)
		if _, err := t.conn.WriteToUDP(pkt, t.addr()); err != nil {
			atomic.AddInt64(&t.writeErrs, 1)
			if atomic.LoadInt64(&t.writeErrs)%200 == 1 {
				log.Printf("engine: udp write err (kept alive): %v", err)
			}
			if f.data != nil {
				t.up = append([]*upFrag{f}, t.up...)
			}
			break
		}
		f.sentAt = time.Now()
		t.inflight[qid] = f
		atomic.AddInt64(&t.qSent, 1)
	}
}

// pickStreamLocked round-robins over live streams so every stream gets polls
// even when another stream is busy. Caller MUST hold t.mu (pump already does;
// Go mutexes are not reentrant, so this must not lock).
func (t *Tunnel) pickStreamLocked() *Stream {
	if len(t.streams) == 0 {
		return nil
	}
	t.rr++
	n := t.rr % uint32(len(t.streams))
	i := uint32(0)
	for _, s := range t.streams {
		if i == n {
			return s
		}
		i++
	}
	return nil
}

func (t *Tunnel) retransmit() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for qid, f := range t.inflight {
		if now.Sub(f.sentAt) > 2*time.Second {
			delete(t.inflight, qid)
			t.up = append([]*upFrag{f}, t.up...) // put it back at the front
			atomic.AddInt64(&t.retrans, 1)
		}
	}
	// Upstream fragments the server has NOT confirmed. A data query is always
	// answered, so the query-level retransmit above never notices a fragment
	// that the server failed to reassemble -- resend the oldest unconfirmed one
	// each tick. The server ignores duplicates (seq < expectSeq), so this is a
	// cheap safety net that stops one lost fragment stalling an upload forever.
	for _, s := range t.streams {
		s.mu.Lock()
		if !s.synAcked && s.target != "" {
			// The SYN carries the dial target and is sent only once. A resolver
			// dropping it used to leave the connection permanently dead, since
			// the server answers every query (including for a stream it never
			// created) and the client could not tell the difference.
			id, tgt := s.id, s.target
			s.mu.Unlock()
			t.up = append(t.up, &upFrag{streamID: id, seq: 0, flags: upSYN, data: []byte(tgt)})
			atomic.AddInt64(&t.retrans, 1)
			continue
		}
		var lowest uint16
		found := false
		for seq := range s.unacked {
			if !seqLessEq(seq, s.upAckSeen) {
				if !found || seqLessEq(seq, lowest) {
					lowest, found = seq, true
				}
			}
		}
		if !found {
			s.mu.Unlock()
			continue
		}
		id := s.id
		ack := s.recvAck
		// Re-queue every fragment above the acked point, in order. One per
		// tick could not keep up with a saturated window, so a single gap
		// stalled an upload forever.
		batch := make([]*upFrag, 0, 64)
		for q := uint16(0); q < 64; q++ {
			seq := lowest + q
			data, ok := s.unacked[seq]
			if !ok {
				break
			}
			batch = append(batch, &upFrag{streamID: id, seq: seq, flags: 0, ack: ack, data: data})
		}
		s.mu.Unlock()
		for _, bf := range batch {
			t.up = append(t.up, bf)
			atomic.AddInt64(&t.retrans, 1)
		}
	}
}

func (t *Tunnel) onReply(msg []byte) {
	if len(msg) < 12 {
		return
	}
	qid := binary.BigEndian.Uint16(msg[0:])
	t.mu.Lock()
	f := t.inflight[qid]
	if f != nil {
		delete(t.inflight, qid)
		if f.streamID != 0 {
			if s := t.streams[f.streamID]; s != nil {
				s.ackUp(f.seq)
			}
		}
	}
	t.mu.Unlock()
	atomic.AddInt64(&t.qRecv, 1)
	atomic.StoreInt64(&t.lastRecv, time.Now().Unix())

	rdata := extractTXT(msg)
	if atomic.AddInt64(&dbgRecvN, 1) <= 30 {
		log.Printf("RX msg=%d rdata=%d", len(msg), len(rdata))
	}
	if len(rdata) < downHdrLen {
		return
	}
	d, err := decodeDown(rdata)
	if err != nil {
		return
	}
	atomic.AddInt64(&t.dnBytes, int64(len(d.data)))
	if d.streamID == 0 {
		return
	}
	t.mu.Lock()
	s := t.streams[d.streamID]
	t.mu.Unlock()
	if s == nil {
		// Data for a stream we already dropped: never counts as activity,
		// or a dead stream's leftovers would keep the pipe at full depth.
		return
	}
	if len(d.data) > 0 {
		atomic.StoreInt64(&t.lastActive, time.Now().Unix())
	}
	s.deliver(d)
}

// control is the congestion loop for the query window. The resolver on the
// path answers a few hundred queries per second and then cuts the client off
// entirely: measured against the Smarty/Three resolver, ~590 q/s is fine while
// a two-second burst at window 8192 (~25k q/s) got the client blackholed
// (qsent climbing, qrecv frozen at zero). So the window walks up while loss is
// low and collapses the moment replies stop.
func (t *Tunnel) control() {
	sent := atomic.LoadInt64(&t.qSent)
	recv := atomic.LoadInt64(&t.qRecv)
	ds := sent - t.ctlSent
	dr := recv - t.ctlRecv
	t.ctlSent, t.ctlRecv = sent, recv

	t.mu.Lock()
	d, maxD := t.depth, t.maxDepth
	t.mu.Unlock()

	changed := false
	switch {
	case ds < 4:
		// Idle: leave the learned window alone, the pump already throttles.
	case dr == 0:
		// Blackout: the resolver has stopped answering us. Drop to a slow
		// probe rate so the block can expire instead of feeding it.
		if d > 8 {
			d = 8
			changed = true
		}
	case ds-dr > ds/5:
		// More than 20% loss: back off a notch.
		d = d * 3 / 4
		if d < 8 {
			d = 8
		}
		changed = true
	case ds-dr < ds/20 && d < maxD:
		// Under 5% loss: walk the window up.
		d += 32
		if d > maxD {
			d = maxD
		}
		changed = true
	}
	if changed {
		t.mu.Lock()
		t.depth = d
		t.mu.Unlock()
		log.Printf("engine: window -> %d (sent/s=%d recv/s=%d ceiling=%d)", d, ds, dr, maxD)
	}
}

func (t *Tunnel) report() {
	last := atomic.LoadInt64(&t.lastRecv)
	ago := "never"
	if last > 0 {
		ago = fmt.Sprintf("%ds", time.Now().Unix()-last)
	}
	t.mu.Lock()
	inflight := len(t.inflight)
	streams := len(t.streams)
	t.mu.Unlock()
	qsent := atomic.LoadInt64(&t.qSent)
	qrecv := atomic.LoadInt64(&t.qRecv)
	warn := ""
	if r, w, d := atomic.LoadInt64(&t.readErrs), atomic.LoadInt64(&t.writeErrs), atomic.LoadInt64(&t.upDrops); r+w+d > 0 {
		warn = fmt.Sprintf(" ERR read=%d write=%d blocked=%d", r, w, d)
	}
	loss := ""
	if qsent > 0 {
		loss = fmt.Sprintf(" loss=%.1f%%", 100*float64(qsent-qrecv)/float64(qsent))
	}
	log.Printf("STATS win=%d up=%.0fKB down=%.0fKB qsent=%d qrecv=%d streams=%d inflight=%d retrans=%d last=%s%s%s",
		func() int { t.mu.Lock(); defer t.mu.Unlock(); return t.depth }(),
		float64(atomic.LoadInt64(&t.upBytes))/1024,
		float64(atomic.LoadInt64(&t.dnBytes))/1024,
		qsent, qrecv, streams, inflight, atomic.LoadInt64(&t.retrans), ago, loss, warn)
}

// newStream registers a stream and sends the SYN carrying the target.
func (t *Tunnel) newStream(target string, c net.Conn) *Stream {
	t.mu.Lock()
	t.nextStream++
	id := uint16(t.nextStream)
	s := &Stream{
		id:       id,
		t:        t,
		conn:     c,
		target:   target,
		nextSeq:  1,
		unacked:  make(map[uint16][]byte),
		outOfOrd: make(map[uint16][]byte),
		expectDn: 1,
		lastAct:  time.Now(),
	}
	t.streams[id] = s
	t.mu.Unlock()
	t.enqueue(&upFrag{streamID: id, seq: 0, flags: upSYN, data: []byte(target)})
	return s
}

func (t *Tunnel) dropStream(id uint16) {
	t.mu.Lock()
	delete(t.streams, id)
	t.mu.Unlock()
}

// sendUp chunks a buffer into fragments and queues them.
func (s *Stream) sendUp(p []byte) {
	total := len(p)
	s.mu.Lock()
	for len(p) > 0 {
		n := s.t.chunk
		if n > len(p) {
			n = len(p)
		}
		seq := s.nextSeq
		s.nextSeq++
		chunk := append([]byte(nil), p[:n]...)
		s.unacked[seq] = chunk
		p = p[n:]
		s.mu.Unlock()
		s.t.enqueue(&upFrag{streamID: s.id, seq: seq, flags: 0, ack: s.recvAck, data: chunk})
		s.mu.Lock()
	}
	s.lastAct = time.Now()
	s.mu.Unlock()
	atomic.AddInt64(&s.t.upBytes, int64(total))
}

// ackUp is deliberately a no-op.
//
// A query being ANSWERED does not mean the server RECEIVED the fragment it
// carried -- the server answers every query whether or not the payload was
// reassembled. Deleting here made a lost fragment unrecoverable, which is why
// uploads stalled unpredictably. Fragments are retired only on the server's
// explicit UpAck (see deliver).
func (s *Stream) ackUp(seq uint16) {
	_ = seq
}

// deliver handles a downstream fragment, writing in-order data to the socket.
func (s *Stream) deliver(d downFrag) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.lastAct = time.Now()
	if d.flags&downSYNACK != 0 {
		s.synAcked = true
	}
	if !seqLessEq(d.seq, s.maxSeen) {
		s.maxSeen = d.seq
	}
	// Retire upstream fragments the server has confirmed it received. Without
	// this the client can never drop a sent fragment, so it cannot retransmit
	// correctly -- and since TCP ACKs travel upstream, that stalls downloads
	// as well as uploads.
	if !seqLessEq(d.upAck, s.upAckSeen) {
		s.upAckSeen = d.upAck
	}
	if d.upAck != 0 {
		for seq := range s.unacked {
			if seqLessEq(seq, d.upAck) {
				delete(s.unacked, seq)
			}
		}
	}
	if seqLessEq(d.seq, s.recvAck) {
		s.mu.Unlock()
		return // duplicate
	}
	if d.seq == s.expectDn {
		s.recvAck = d.seq
		s.expectDn++
		data := d.data
		// drain in-order buffered fragments
		for {
			next, ok := s.outOfOrd[s.expectDn]
			if !ok {
				break
			}
			delete(s.outOfOrd, s.expectDn)
			s.recvAck = s.expectDn
			s.expectDn++
			data = append(data, next...)
		}
		c := s.conn
		s.mu.Unlock()
		if len(data) > 0 && c != nil {
			c.Write(data)
		}
		return
	}
	if len(s.outOfOrd) < 4096 {
		if len(s.outOfOrd) == 0 && d.seq != s.expectDn {
			gap := d.seq - s.expectDn
			log.Printf("stream %d: GAP expecting %d got %d (%d missing)", s.id, s.expectDn, d.seq, gap)
		}
		s.outOfOrd[d.seq] = append([]byte(nil), d.data...)
	}
	s.mu.Unlock()
}

func seqLessEq(a, b uint16) bool {
	d := int32(a) - int32(b)
	return d <= 0 && d > -32768
}

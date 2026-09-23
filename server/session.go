package main

import (
	"encoding/binary"
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxQueueBytes = 8 << 20 // per-session downstream buffer cap
	fragTTL       = 5 * time.Second
)

// enqueueTestData queues n bytes of valid-looking IPv4 packets. Used only by
// the "s<N>" speed-test endpoint so a client can measure downstream throughput
// without needing a real TUN.
func (s *Session) enqueueTestData(n int) {
	const pktSize = 600
	for i := 0; i < n; i += pktSize {
		size := pktSize
		if n-i < size {
			size = n - i
		}
		p := make([]byte, size)
		for j := range p {
			p[j] = 0x41
		}
		if size >= 20 {
			p[0] = 0x45
			binary.BigEndian.PutUint16(p[2:], uint16(size))
			p[8] = 64
			p[9] = 253
			copy(p[12:16], []byte{10, 78, 0, 1})
			copy(p[16:20], []byte{10, 78, 0, 2})
		}
		s.enqueue(p)
	}
}

// ---------------------------------------------------------------------------
// upstream fragment reassembly
// ---------------------------------------------------------------------------

type fragBuf struct {
	parts [][]byte
	total int // 0 = last fragment not seen yet
	seen  time.Time
}

// ---------------------------------------------------------------------------
// session
// ---------------------------------------------------------------------------

type Session struct {
	SID    string
	VIP    netip.Addr
	User   string
	LastIn atomic.Int64 // unix nanos

	mu         sync.Mutex
	queue      [][]byte
	queueBytes int
	downSeq    uint16
	frags      map[uint16]*fragBuf

	UpBytes   atomic.Uint64
	DownBytes atomic.Uint64
	Queries   atomic.Uint64
	DownPkts  atomic.Uint64
	UpPkts    atomic.Uint64
	LostFrags atomic.Uint64
}

func (s *Session) touch() { s.LastIn.Store(time.Now().UnixNano()) }

// enqueue adds one downstream IP packet.
func (s *Session) enqueue(pkt []byte) {
	s.mu.Lock()
	if s.queueBytes+len(pkt) > maxQueueBytes {
		for len(s.queue) > 0 && s.queueBytes+len(pkt) > maxQueueBytes {
			s.queueBytes -= len(s.queue[0])
			s.queue = s.queue[1:]
		}
	}
	s.queue = append(s.queue, pkt)
	s.queueBytes += len(pkt)
	s.mu.Unlock()
}

// drainUpTo removes whole packets while they fit in maxBytes.
func (s *Session) drainUpTo(maxBytes int) ([][]byte, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 || maxBytes <= 0 {
		return nil, s.queueBytes
	}
	used := 0
	n := 0
	for _, p := range s.queue {
		if used+len(p) > maxBytes {
			break
		}
		used += len(p)
		n++
	}
	if n == 0 {
		// The head packet is bigger than this reply can carry. Drop it rather
		// than stalling the queue forever (the peer retransmits at IP level).
		s.queueBytes -= len(s.queue[0])
		s.queue = s.queue[1:]
		return nil, s.queueBytes
	}
	out := s.queue[:n:n]
	s.queue = s.queue[n:]
	s.queueBytes -= used
	return out, s.queueBytes
}

func (s *Session) nextSeq() uint16 {
	s.mu.Lock()
	s.downSeq++
	v := s.downSeq
	s.mu.Unlock()
	return v
}

// addFragment stores one upstream fragment; it returns the reassembled packet
// once every fragment of that frag_id has arrived.
func (s *Session) addFragment(h upHdr, data []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frags == nil {
		s.frags = make(map[uint16]*fragBuf)
	}
	fb := s.frags[h.FragID]
	if fb == nil || time.Since(fb.seen) > fragTTL {
		fb = &fragBuf{total: 0}
		s.frags[h.FragID] = fb
	}
	fb.seen = time.Now()
	idx := int(h.FragIdx)
	if idx > 512 { // sanity: never fragment into more than 512 pieces
		delete(s.frags, h.FragID)
		s.LostFrags.Add(1)
		return nil
	}
	for len(fb.parts) <= idx {
		fb.parts = append(fb.parts, nil)
	}
	if fb.parts[idx] == nil {
		fb.parts[idx] = data
	}
	if h.Flags&flagMore == 0 {
		fb.total = idx + 1
	}
	if fb.total == 0 || len(fb.parts) < fb.total {
		return nil
	}
	size := 0
	for i := 0; i < fb.total; i++ {
		if fb.parts[i] == nil {
			return nil // a fragment is still missing
		}
		size += len(fb.parts[i])
	}
	out := make([]byte, 0, size)
	for i := 0; i < fb.total; i++ {
		out = append(out, fb.parts[i]...)
	}
	delete(s.frags, h.FragID)
	s.UpPkts.Add(1)
	return out
}

// reapFragments drops stale partial reassembly buffers.
func (s *Session) reapFragments() {
	s.mu.Lock()
	for k, fb := range s.frags {
		if time.Since(fb.seen) > fragTTL {
			delete(s.frags, k)
			s.LostFrags.Add(1)
		}
	}
	s.mu.Unlock()
}

func (s *Session) queueLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue)
}

// ---------------------------------------------------------------------------
// manager
// ---------------------------------------------------------------------------

type Manager struct {
	mu     sync.RWMutex
	bySID  map[string]*Session
	byVIP  map[netip.Addr]*Session
	all    []*Session
	reaper *time.Ticker
}

func NewManager(cfg *Config) *Manager {
	m := &Manager{
		bySID: make(map[string]*Session),
		byVIP: make(map[netip.Addr]*Session),
	}
	for i := range cfg.Users {
		u := &cfg.Users[i]
		vip, err := netip.ParseAddr(u.VIP)
		if err != nil {
			log.Fatalf("user %q: bad vip %q: %v", u.Name, u.VIP, err)
		}
		s := &Session{SID: u.SID, VIP: vip, User: u.Name}
		m.bySID[u.SID] = s
		m.byVIP[vip] = s
		m.all = append(m.all, s)
	}
	m.reaper = time.NewTicker(5 * time.Second)
	go func() {
		for range m.reaper.C {
			for _, s := range m.all {
				s.reapFragments()
			}
		}
	}()
	return m
}

// Get returns the session for a sid label (case-insensitive).
func (m *Manager) Get(sid string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bySID[sid]
}

// GetByVIP returns the session that owns a virtual IP.
func (m *Manager) GetByVIP(a netip.Addr) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byVIP[a]
}

func (m *Manager) All() []*Session { return m.all }

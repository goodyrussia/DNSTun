package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

type User struct {
	Name string `json:"name"`
	SID  string `json:"sid"` // 6 chars [a-z0-9]
	VIP  string `json:"vip"` // virtual IP handed to that client
}

type Config struct {
	Domain     string   `json:"domain"`
	NSName     string   `json:"ns_name"`
	Listen     string   `json:"listen"`
	ListenTCP  string   `json:"listen_tcp"`
	TunName    string   `json:"tun_name"`
	TunAddr    string   `json:"tun_addr"`
	ClientNet  string   `json:"client_subnet"`
	TunMTU     int      `json:"tun_mtu"`
	WanIface   string   `json:"wan_iface"`
	MaxUDP     int      `json:"max_udp"` // largest reply we will build
	Workers    int      `json:"workers"`
	Debug      bool     `json:"debug"`
	StateFile  string   `json:"state_file"`
	Users      []User   `json:"users"`
}

type transportKind int

const (
	trUDP transportKind = iota
	trTCP
)

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if cfg.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if cfg.NSName == "" {
		cfg.NSName = "ns." + cfg.Domain
	}
	if cfg.Listen == "" {
		cfg.Listen = ":53"
	}
	if cfg.TunName == "" {
		cfg.TunName = "dnstun0"
	}
	if cfg.TunAddr == "" {
		cfg.TunAddr = "10.77.0.1/24"
	}
	if cfg.ClientNet == "" {
		cfg.ClientNet = "10.78.0.0/24"
	}
	if cfg.TunMTU == 0 {
		cfg.TunMTU = 1280
	}
	if cfg.MaxUDP == 0 {
		cfg.MaxUDP = 1400
	}
	if cfg.Workers == 0 {
		cfg.Workers = 4
	}
	if len(cfg.Users) == 0 {
		return nil, fmt.Errorf("no users configured")
	}
	for i := range cfg.Users {
		u := &cfg.Users[i]
		u.SID = strings.ToLower(strings.TrimSpace(u.SID))
		if len(u.SID) != 6 {
			return nil, fmt.Errorf("user %q: sid must be exactly 6 chars", u.Name)
		}
		if _, err := netip.ParseAddr(u.VIP); err != nil {
			return nil, fmt.Errorf("user %q: bad vip: %v", u.Name, err)
		}
	}
	return &cfg, nil
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

var (
	cfg     *Config
	mgr     *Manager
	handler *Handler
	tun     *Tun

	udpIn     atomic.Uint64
	udpOut    atomic.Uint64
	udpDrops  atomic.Uint64
	byteIn    atomic.Uint64
	byteOut   atomic.Uint64
	startedAt = time.Now()
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to config.json")
	flag.Parse()

	var err error
	cfg, err = loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	mgr = NewManager(cfg)

	tun, err = OpenTun(cfg.TunName)
	if err != nil {
		log.Fatalf("tun: %v", err)
	}
	if err := ConfigureHost(cfg, tun); err != nil {
		log.Fatalf("host network: %v", err)
	}
	handler = NewHandler(cfg, mgr, tun)
	go tun.ReadLoop(mgr, cfg.Debug)

	// UDP listener
	uaddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		log.Fatalf("resolve %s: %v", cfg.Listen, err)
	}
	uc, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		log.Fatalf("listen udp %s: %v", cfg.Listen, err)
	}
	_ = uc.SetReadBuffer(8 << 20)
	_ = uc.SetWriteBuffer(8 << 20)

	for i := 0; i < cfg.Workers; i++ {
		go udpLoop(uc)
	}
	log.Printf("dnstun listening on %s udp (%d workers), zone=%s tun=%s %s users=%d",
		cfg.Listen, cfg.Workers, cfg.Domain, tun.Name(), cfg.TunAddr, len(cfg.Users))

	// stats
	go func() {
		for range time.Tick(30 * time.Second) {
			in := udpIn.Load()
			out := udpOut.Load()
			log.Printf("stats: %d q in / %d replies (%.0f q/s), %.1f KB/s in, %.1f KB/s out, drops=%d",
				in, out, float64(out)/time.Since(startedAt).Seconds(),
				float64(byteIn.Load())/time.Since(startedAt).Seconds()/1024,
				float64(byteOut.Load())/time.Since(startedAt).Seconds()/1024, udpDrops.Load())
			for _, s := range mgr.All() {
				if q := s.Queries.Load(); q > 0 {
					log.Printf("  sid=%s user=%s vip=%s q=%d up=%.1fMB down=%.1fMB queue=%d pkts up=%d down=%d lostfrag=%d",
						s.SID, s.User, s.VIP, q,
						float64(s.UpBytes.Load())/1e6, float64(s.DownBytes.Load())/1e6,
						s.queueLen(), s.UpPkts.Load(), s.DownPkts.Load(), s.LostFrags.Load())
				}
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
}

func udpLoop(uc *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, src, err := uc.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			log.Printf("udp read: %v", err)
			continue
		}
		udpIn.Add(1)
		byteIn.Add(uint64(n))
		msg := buf[:n]
		resp := handler.Handle(msg, trUDP)
		if resp == nil {
			udpDrops.Add(1)
			continue
		}
		if _, err := uc.WriteToUDP(resp, src); err != nil {
			log.Printf("udp write: %v", err)
			continue
		}
		if len(resp) > 120 && cfg.Debug {
			log.Printf("big reply %dB -> %s", len(resp), src)
		}
		udpOut.Add(1)
		byteOut.Add(uint64(len(resp)))
	}
}

func vipFromPacket(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
}

// Package mobile is the gomobile binding of the dnstun engine.
//
// The Android app talks to this package through the same API surface it used
// for the engine it replaced (mobile.Mobile.newClient -> mobile.DnsttClient),
// so the app-side bridge, hev-socks5-tunnel and VpnService wiring stay
// untouched: they only see a local SOCKS5 port.
//
// Underneath, the transport is the dnstun stream protocol against our own
// server (dnsfast): every query is <b32>.<sid>.<zone>, answered with TXT
// payload, no encryption, no obfuscation -- built for speed only.
package mobile

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

const (
	engineVersion = "6.0.2-engine"
	defaultSID    = "g7x2k9"
	defaultChunk  = 56
	defaultDepth  = 8192
	deepDepth     = 12288
	defaultEDNS   = 1000
)

// DnsttClient keeps the type name the app's bridge expects.
type DnsttClient struct {
	t          *Tunnel
	listenAddr string
	running    int32

	authoritative bool
	maxPayload    int64
	resolverMode  string
	rrSpread      int64
	socksProxy    string
}

// NewClient mirrors the signature the app calls:
//
//	dnsAddr      resolver the tunnel queries are sent to ("188.31.250.128:53")
//	tunnelDomain the zone our server is authoritative for ("v.techychi.com")
//	publicKey    session id (this engine has no crypto; the value names the
//	             server-side session, empty = default)
//	listenAddr   local SOCKS5 the app's bridge chains to ("127.0.0.1:7301")
func NewClient(dnsAddr, tunnelDomain, publicKey, listenAddr string) (*DnsttClient, error) {
	resolver := normalizeResolver(dnsAddr)
	if resolver == "" {
		return nil, fmt.Errorf("engine: empty resolver")
	}
	zone := strings.Trim(strings.TrimSpace(tunnelDomain), ".")
	if zone == "" {
		return nil, fmt.Errorf("engine: empty tunnel domain")
	}
	sid := sessionID(publicKey)
	listen := strings.TrimSpace(listenAddr)
	if listen == "" {
		listen = "127.0.0.1:7301"
	}
	t, err := NewTunnel(resolver, zone, sid, listen, defaultChunk, defaultDepth, defaultEDNS)
	if err != nil {
		return nil, err
	}
	log.Printf("engine: resolver=%s zone=%s sid=%s listen=%s", resolver, zone, sid, listen)
	return &DnsttClient{t: t, listenAddr: listen}, nil
}

// SetLogPath routes the engine's log to <dir>/engine.log as well as stderr.
// Without it nothing the engine logs is visible on a device: an in-process
// gomobile library writes to stderr, which Android throws away. The app calls
// this before Start with getExternalFilesDir().
func (c *DnsttClient) SetLogPath(dir string) string {
	if dir == "" {
		return ""
	}
	path := filepath.Join(dir, "engine.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("engine: cannot open log %s: %v", path, err)
		return ""
	}
	if st, err := f.Stat(); err == nil && st.Size() > 2<<20 {
		f.Truncate(0)
		f.Seek(0, io.SeekStart)
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	log.Printf("engine: log -> %s", path)
	return path
}

// Version is bumped by hand on every engine change so a device log says which
// build produced it.
func (c *DnsttClient) Version() string { return engineVersion }

// Start binds the SOCKS5 listener and launches the transport loops. It fails
// fast when the port is busy so the app can surface a real error instead of
// waiting for a socket that never appears.
func (c *DnsttClient) Start() error {
	if atomic.LoadInt32(&c.running) == 1 {
		return nil
	}
	if err := c.t.listen(c.listenAddr); err != nil {
		return err
	}
	go c.t.run()
	go c.t.selfCheck()
	go c.t.serve()
	atomic.StoreInt32(&c.running, 1)
	log.Printf("engine: started, socks5 on %s", c.listenAddr)
	return nil
}

// Stop tears everything down; safe to call twice.
func (c *DnsttClient) Stop() {
	if atomic.SwapInt32(&c.running, 0) == 0 {
		return
	}
	c.t.Close()
	log.Printf("engine: stopped")
}

// IsRunning reports whether the engine is up (the app polls this).
func (c *DnsttClient) IsRunning() bool {
	return atomic.LoadInt32(&c.running) == 1
}

// Stats is a one-line diagnostic for the app's status line.
func (c *DnsttClient) Stats() string {
	if c.t == nil {
		return "engine: down"
	}
	t := c.t
	t.mu.Lock()
	inflight := len(t.inflight)
	streams := len(t.streams)
	t.mu.Unlock()
	return fmt.Sprintf("up=%dKB down=%dKB q=%d/%d inflight=%d streams=%d",
		atomic.LoadInt64(&t.upBytes)>>10, atomic.LoadInt64(&t.dnBytes)>>10,
		atomic.LoadInt64(&t.qSent), atomic.LoadInt64(&t.qRecv),
		inflight, streams)
}

// ---- knobs the app sets -------------------------------------------------
//
// The app still carries the profile fields of the engine it replaced. The
// ones that map onto this transport do something; the rest are accepted and
// ignored so the bridge code needs no changes.

// SetAuthoritativeMode raises the in-flight query window (our own server,
// so aggressive rates are safe and this is the throughput lever).
func (c *DnsttClient) SetAuthoritativeMode(enabled bool) {
	c.authoritative = enabled
	if enabled {
		c.t.SetDepth(deepDepth)
	} else {
		c.t.SetDepth(defaultDepth)
	}
}

// SetMaxPayload maps the old KCP MTU cap onto the upstream bytes per query.
func (c *DnsttClient) SetMaxPayload(size int64) {
	c.maxPayload = size
	if size > 0 && size < 400 {
		c.t.SetChunk(int(size))
	}
}

func (c *DnsttClient) SetNoizMode(enabled bool)              {}
func (c *DnsttClient) SetStealthMode(enabled bool)           {}
func (c *DnsttClient) SetDeviceManufacturer(name string)     {}
func (c *DnsttClient) SetSocksCredentials(user, pass string) {}
func (c *DnsttClient) SetEDNS0Size(size int64)               {}
func (c *DnsttClient) SetUTLSFingerprint(fp string)          {}

func (c *DnsttClient) SetResolverMode(mode string) { c.resolverMode = mode }
func (c *DnsttClient) SetRRSpreadCount(n int64)    { c.rrSpread = n }

// SetSOCKS5Proxy would chain the transport through another proxy; the tunnel
// here is already the last hop, so the value is only recorded.
func (c *DnsttClient) SetSOCKS5Proxy(addr, user, pass string) { c.socksProxy = addr }

// ---- helpers ------------------------------------------------------------

// normalizeResolver accepts what the app's profile can hold ("ip", "ip:53",
// "udp://ip:53", "tcp://ip:53", "tls://…", "https://…") and returns a plain
// host:port for the UDP transport this engine speaks.
func normalizeResolver(in string) string {
	s := strings.TrimSpace(in)
	if s == "" {
		return ""
	}
	for _, p := range []string{"udp://", "tcp://", "tls://", "dot://", "https://", "http://"} {
		s = strings.TrimPrefix(s, p)
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if !strings.Contains(s, ":") {
		s += ":53"
	}
	return s
}

// sessionID keeps a short alphanumeric id; anything else falls back to the
// default so a base64 public key pasted into the profile cannot break the
// query-name layout.
func sessionID(in string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(in) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
		if b.Len() >= 16 {
			break
		}
	}
	if b.Len() == 0 {
		return defaultSID
	}
	return b.String()
}

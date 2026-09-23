package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// TUN device (Linux)
// ---------------------------------------------------------------------------

const (
	tunSetIff = 0x400454ca
	iffTun    = 0x0001
	iffNoPI   = 0x1000
	ifnamsiz  = 16
)

type ifreqFlags struct {
	name  [ifnamsiz]byte
	flags uint16
	_     [22]byte // padding to sizeof(struct ifreq)
}

type Tun struct {
	name string
	f    *os.File
	rd   atomic.Uint64
	wr   atomic.Uint64
}

func OpenTun(name string) (*Tun, error) {
	if len(name) >= ifnamsiz {
		return nil, errors.New("tun name too long")
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req ifreqFlags
	copy(req.name[:], name)
	req.flags = iffTun | iffNoPI
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(tunSetIff), uintptr(unsafe.Pointer(&req))); errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %v", errno)
	}
	actual := strings.TrimRight(string(req.name[:]), "\x00")
	return &Tun{name: actual, f: os.NewFile(uintptr(fd), "/dev/net/tun")}, nil
}

func (t *Tun) Name() string { return t.name }

func (t *Tun) Write(pkt []byte) error {
	n, err := t.f.Write(pkt)
	if err == nil {
		t.wr.Add(uint64(n))
	}
	return err
}

func (t *Tun) Read(buf []byte) (int, error) {
	n, err := t.f.Read(buf)
	if err == nil {
		t.rd.Add(uint64(n))
	}
	return n, err
}

// ReadLoop feeds packets read from the TUN to the session that owns the dst IP.
func (t *Tun) ReadLoop(mgr *Manager, debug bool) {
	buf := make([]byte, 65535)
	for {
		n, err := t.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			log.Printf("tun read: %v", err)
			continue
		}
		if n < 20 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		dst, ok := vipFromPacket(pkt)
		if !ok {
			continue
		}
		s := mgr.GetByVIP(dst)
		if s == nil {
			if debug {
				log.Printf("tun: no session for dst %s (len=%d)", dst, len(pkt))
			}
			continue
		}
		if debug {
			log.Printf("tun: pkt dst=%s len=%d -> sid=%s queued", dst, len(pkt), s.SID)
		}
		s.enqueue(pkt)
	}
}

// ---------------------------------------------------------------------------
// Host network configuration (ip / iptables / sysctl)
// ---------------------------------------------------------------------------

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ConfigureHost(cfg *Config, t *Tun) error {
	// bring the interface up and give it the gateway address
	if err := runCmd("ip", "addr", "add", cfg.TunAddr, "dev", t.Name()); err != nil {
		// ignore "already exists"
		if !strings.Contains(err.Error(), "File exists") {
			return err
		}
	}
	if err := runCmd("ip", "link", "set", t.Name(), "up"); err != nil {
		return err
	}
	if cfg.TunMTU > 0 {
		_ = runCmd("ip", "link", "set", t.Name(), "mtu", fmt.Sprint(cfg.TunMTU))
	}
	// forwarding
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)

	wan := cfg.WanIface
	if wan == "" {
		wan = detectWan()
	}
	if wan != "" {
		subnet := cfg.ClientNet
		if subnet == "" {
			subnet = subnetOf(cfg.TunAddr)
		}
		// replies to client virtual IPs must go back into the tunnel
		if err := runCmd("ip", "route", "add", subnet, "dev", t.Name()); err != nil &&
			!strings.Contains(err.Error(), "File exists") {
			log.Printf("warning: route %s dev %s: %v", subnet, t.Name(), err)
		}
		// NAT tunnel traffic out to the internet (idempotent: never duplicate rules)
		ensureRule("nat", "POSTROUTING", "-s", subnet, "-o", wan, "-j", "MASQUERADE")
		ensureRule("", "FORWARD", "-s", subnet, "-j", "ACCEPT")
		ensureRule("", "FORWARD", "-d", subnet, "-j", "ACCEPT")
		log.Printf("host configured: %s %s, NAT %s -> %s", t.Name(), cfg.TunAddr, subnet, wan)
	}
	return nil
}

// ensureRule adds an iptables rule only when an identical one is not present.
func ensureRule(table string, args ...string) {
	with := func(op string) []string {
		var out []string
		if table != "" {
			out = append(out, "-t", table)
		}
		out = append(out, op)
		return append(out, args...)
	}
	if runCmd("iptables", with("-C")...) == nil {
		return // already installed
	}
	if err := runCmd("iptables", with("-A")...); err != nil {
		log.Printf("warning: iptables -A %s: %v", strings.Join(args, " "), err)
	}
}

func detectWan() string {
	out, err := exec.Command("ip", "-o", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func subnetOf(addr string) string {
	// "10.66.0.1/16" -> "10.66.0.0/16"
	i := strings.Index(addr, "/")
	if i < 0 {
		return addr
	}
	ip := addr[:i]
	bits := addr[i+1:]
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return addr
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		var v int
		fmt.Sscanf(parts[i], "%d", &v)
		b[i] = byte(v)
	}
	var mask int
	fmt.Sscanf(bits, "%d", &mask)
	for i := 0; i < 4; i++ {
		keep := mask - i*8
		if keep >= 8 {
			continue
		}
		if keep <= 0 {
			b[i] = 0
		} else {
			b[i] &= byte(0xff << (8 - keep))
		}
	}
	return fmt.Sprintf("%d.%d.%d.%d/%d", b[0], b[1], b[2], b[3], mask)
}

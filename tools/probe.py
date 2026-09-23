#!/usr/bin/env python3
# DNSTun network probe - measures what your carrier's DNS path really allows.
# Termux:  python3 ~/probe.py       (~2 minutes, paste the whole output back)
import random, socket, string, struct, threading, time

RESOLVER = "188.31.250.128"   # Three/Smarty resolver (only reachable thing on the SIM)
SERVER   = "217.154.33.118"   # our server
ZONE     = "v.techychi.com"
OUT      = []
def P(*a):
    line = " ".join(str(x) for x in a)
    print(line, flush=True); OUT.append(line)
def rnd(n): return "".join(random.choice(string.ascii_lowercase) for _ in range(n))

def mkq(name, qtype=16, edns=4096, qid=None):
    if qid is None: qid = random.randint(1, 65535)
    out = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1 if edns else 0)
    for lab in name.split("."):
        out += bytes([len(lab)]) + lab.encode()
    out += b"\x00" + struct.pack(">HH", qtype, 1)
    if edns:
        out += b"\x00" + struct.pack(">HHIH", 41, edns, 0, 0)
    return out

def udp(server, name, qtype=16, edns=4096, timeout=3.0, port=53):
    q = mkq(name, qtype, edns)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(q, (server, port))
        d, _ = s.recvfrom(65535)
        return dict(size=len(d), ms=(time.time()-t0)*1000, rcode=d[3] & 0xF, tc=bool(d[2] & 0x02))
    except Exception as e:
        return dict(size=0, ms=(time.time()-t0)*1000, rcode=None, tc=None, err=type(e).__name__)
    finally:
        s.close()

def tcp(server, name, qtype=16, edns=4096, timeout=5.0, port=53):
    q = mkq(name, qtype, edns)
    t0 = time.time()
    try:
        s = socket.create_connection((server, port), timeout=timeout); s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(q)) + q)
        h = s.recv(2)
        if len(h) < 2: raise IOError("short header")
        ln = struct.unpack(">H", h)[0]; buf = b""
        while len(buf) < ln:
            c = s.recv(ln - len(buf))
            if not c: break
            buf += c
        s.close()
        return dict(size=len(buf), ms=(time.time()-t0)*1000, rcode=(buf[3] & 0xF) if buf else None, tc=bool(buf[2] & 0x02) if buf else None)
    except Exception as e:
        return dict(size=0, ms=(time.time()-t0)*1000, rcode=None, tc=None, err=type(e).__name__)

def name_of_len(L):
    """build a query name of exactly L chars ending in .ZONE"""
    suffix = "." + ZONE
    rem = L - len(suffix)
    if rem < 1: return None
    k = 1
    while k * 63 + (k - 1) < rem:
        k += 1
        if k > 8: return None
    lens = [1] * k
    extra = rem - (sum(lens) + (k - 1))
    for i in range(k):
        add = min(62, extra); lens[i] += add; extra -= add
        if extra <= 0: break
    return ".".join(rnd(n) for n in lens) + suffix

def hdr(t):
    P(""); P("=" * 52); P(t); P("=" * 52)

P("DNSTun probe   resolver=%s  server=%s  zone=%s" % (RESOLVER, SERVER, ZONE))
P("time: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))

# which network are we on? (must be mobile data, not wifi)
def active_iface():
    try:
        for line in open("/proc/net/route"):
            f = line.split()
            if len(f) > 3 and f[1] == "00000000" and f[3] != "0000":
                return f[0]
    except Exception:
        pass
    return "?"
IF = active_iface()
P("active network interface: %s" % IF)
if IF.startswith("wlan") or IF.startswith("eth"):
    P("")
    P("!! WARNING: you are on WiFi. Turn WiFi OFF and run this on mobile data,")
    P("!! otherwise it measures the wrong DNS server and the numbers are useless.")
    P("")

# ---- A: can the phone reach our server directly (no resolver in between)? ----
hdr("A. DIRECT reach to our server (does your SIM allow DNS to anywhere?)")
r = udp(SERVER, "reach." + ZONE, edns=512, timeout=4)
P("  UDP %s:53  -> %s" % (SERVER, ("reply %dB in %.0fms" % (r["size"], r["ms"])) if r["size"] else "BLOCKED (%s)" % r.get("err")))
r2 = tcp(SERVER, "reach." + ZONE, edns=512, timeout=5)
P("  TCP %s:53  -> %s" % (SERVER, ("reply %dB in %.0fms" % (r2["size"], r2["ms"])) if r2["size"] else "BLOCKED (%s)" % r2.get("err")))
direct = bool(r["size"])

# ---- B: resolver baseline ----
hdr("B. Carrier resolver baseline (UDP)")
r = udp(RESOLVER, "example.com", qtype=1, edns=512)
P("  example.com A -> %s" % (("reply %dB in %.0fms rcode=%s" % (r["size"], r["ms"], r["rcode"])) if r["size"] else "FAIL (%s)" % r.get("err")))

# ---- C: TCP/53 to the resolver ----
hdr("C. TCP/53 support at the resolver (fast transport option)")
r = tcp(RESOLVER, "example.com", qtype=1, edns=512, timeout=6)
P("  TCP %s:53 -> %s" % (RESOLVER, ("reply %dB in %.0fms" % (r["size"], r["ms"])) if r["size"] else "NOT SUPPORTED (%s)" % r.get("err")))
tcp_ok = bool(r["size"])

# ---- D: how long a query name does the resolver forward? ----
hdr("D. Max query-name length forwarded (upstream bytes per query)")
best = 0
for L in (100, 150, 190, 220, 240, 250, 253):
    nm = name_of_len(L)
    r = udp(RESOLVER, nm, edns=512, timeout=4)
    ok = r["size"] > 0
    if ok: best = max(best, L)
    P("  name %3d chars -> %s" % (L, "forwarded (%dB)" % r["size"] if ok else "DROPPED (%s)" % r.get("err")))

# ---- E: how big a response can the resolver deliver? (THE key number) ----
hdr("E. Max downstream payload per reply (resolver -> phone)")
sizes = (300, 512, 700, 1000, 1232, 1400, 1600, 2000, 3000, 4000)
maxpay = 0; rtts = []
for n in sizes:
    r = udp(RESOLVER, "s%d.%s" % (n, ZONE), edns=4096, timeout=4)
    if r["size"]:
        pay = max(0, r["size"] - 60)
        maxpay = max(maxpay, min(n, pay)); rtts.append(r["ms"])
        P("  ask %4d B payload -> got %4d B reply (%4d B payload) tc=%s %.0fms" % (n, r["size"], pay, r["tc"], r["ms"]))
    else:
        P("  ask %4d B payload -> DROPPED (%s)" % (n, r.get("err")))
if tcp_ok:
    P("  -- same over TCP --")
    for n in (2000, 4000, 8000):
        r = tcp(RESOLVER, "s%d.%s" % (n, ZONE), edns=4096, timeout=8)
        P("  ask %4d B payload -> %s" % (n, ("got %4dB reply (%dB payload) %.0fms" % (r["size"], max(0, r["size"]-60), r["ms"])) if r["size"] else "DROPPED (%s)" % r.get("err")))

# ---- F: burst rate (how many queries/second does it tolerate) ----
hdr("F. Query rate tolerance (drives the speed ceiling)")
t0 = time.time(); ok = 0; err = 0
for i in range(40):
    r = udp(RESOLVER, "r%d%s.%s" % (i, rnd(4), ZONE), edns=512, timeout=2)
    if r["size"]: ok += 1; rtts.append(r["ms"])
    else: err += 1
d1 = time.time() - t0
P("  sequential: %d ok / %d lost in %.1fs -> %.0f q/s" % (ok, err, d1, 40 / d1))

def worker(idx, per, res):
    o = e = 0
    for i in range(per):
        r = udp(RESOLVER, "p%d%d%s.%s" % (idx, i, rnd(3), ZONE), edns=512, timeout=2)
        if r["size"]: o += 1; res.append(r["ms"])
        else: e += 1
    res.append(-o); res.append(-e)
res = []
t0 = time.time()
ths = [threading.Thread(target=worker, args=(i, 20, res)) for i in range(8)]
[t.start() for t in ths]; [t.join() for t in ths]
d2 = time.time() - t0
oks = -sum(x for x in res if x < 0 and x > -100); losses = -sum(x for x in res if x < -100)
P("  8 parallel: %d ok / %d lost in %.1fs -> %.0f q/s  (%.0f q/s per stream)" % (oks, losses, d2, 160 / d2, 160 / d2 / 8))

rtts = [x for x in rtts if x > 0]
if rtts:
    rtts.sort()
    p50 = rtts[len(rtts)//2]; p95 = rtts[int(len(rtts)*0.95)-1]
else:
    p50 = p95 = 0

# ---- summary ----
hdr("SUMMARY")
P("  direct to server (UDP) : %s" % ("YES" if direct else "NO - must relay through carrier resolver"))
P("  resolver TCP/53        : %s" % ("YES" if tcp_ok else "NO"))
P("  max query-name length  : %d chars -> ~%d B upstream payload/query" % (best, int(max(0, best - len(ZONE) - 8) * 5 / 8)))
P("  max downstream payload : %d B per reply" % maxpay)
P("  resolver RTT           : p50 %.0f ms  p95 %.0f ms" % (p50, p95))
P("  query rate             : %.0f/s sequential, %.0f/s with 8 parallel" % (40 / d1, 160 / d2))
if p50 > 0 and maxpay > 0:
    P("")
    P("  PROJECTION (downstream):")
    for par in (8, 16, 32):
        kbs = par * (maxpay / (p50 / 1000.0)) / 1024
        P("    %2d parallel queries -> ~%.0f KB/s (~%.1f Mbps)" % (par, kbs, kbs * 8 / 1024))
P("")
P("--- END OF PROBE OUTPUT (paste everything above) ---")

#!/usr/bin/env python3
# DNSTun probe 2 - UDP vs TCP throughput, and how far parallelism scales.
# Termux:  python3 ~/probe2.py      (~2.5 minutes, paste the whole output back)
import random, socket, string, struct, time

RESOLVER = "188.31.250.128"
ZONE     = "v.techychi.com"
OUT = []
def P(*a):
    line = " ".join(str(x) for x in a); print(line, flush=True); OUT.append(line)
def rnd(n): return "".join(random.choice(string.ascii_lowercase) for _ in range(n))
def hdr(t):
    P(""); P("=" * 52); P(t); P("=" * 52)

def mkq(name, qtype=16, edns=4096, qid=None):
    if qid is None: qid = random.randint(1, 65535)
    out = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1 if edns else 0)
    for lab in name.split("."):
        out += bytes([len(lab)]) + lab.encode()
    out += b"\x00" + struct.pack(">HH", qtype, 1)
    if edns:
        out += b"\x00" + struct.pack(">HHIH", 41, edns, 0, 0)
    return out, qid

P("DNSTun probe 2   resolver=%s  zone=%s" % (RESOLVER, ZONE))
P("time: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))

# ============ 1. UDP: sustained pipeline at increasing depth ============
hdr("1. UDP - keep N queries in flight, replies carry 1232B payload")
def udp_pipe(depth, seconds=10.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.5)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
    except Exception: pass
    inflight = {}; got = lost = 0; bytes_in = 0
    t0 = time.time(); t_end = t0 + seconds
    def send_one():
        q, qid = mkq("%s.s1232.%s" % (rnd(8), ZONE), edns=4096)
        inflight[qid] = time.time(); s.sendto(q, (RESOLVER, 53))
    for _ in range(depth): send_one()
    while time.time() < t_end:
        try: d, _ = s.recvfrom(65535)
        except socket.timeout: d = None
        if d:
            qid = struct.unpack(">H", d[:2])[0]
            if qid in inflight:
                del inflight[qid]; got += 1; bytes_in += len(d)
        now = time.time()
        for k in [k for k, v in inflight.items() if now - v > 3.0]:
            del inflight[k]; lost += 1
        while len(inflight) < depth and time.time() < t_end: send_one()
    dt = time.time() - t0; s.close()
    qps = (got + lost) / dt
    P("  depth %3d: %4.0f q/s, %6.1f KB/s down, loss %.1f%%" % (depth, qps, bytes_in / dt / 1024, 100.0 * lost / max(1, got + lost)))
    return bytes_in / dt / 1024

udp_res = {d: udp_pipe(d) for d in (16, 32, 64, 128)}

# ============ 2. TCP: bigger replies (4000B), sequential / pipelined / multi ============
hdr("2. TCP - replies carry 4000B payload (6x more per query than UDP)")
def tcp_run(conns, depth, payload, seconds=10.0):
    socks = []
    for _ in range(conns):
        c = socket.create_connection((RESOLVER, 53), timeout=6); c.settimeout(0.4)
        socks.append(c)
    got = lost = 0; bytes_in = 0; inflight = {}; buf = [b""] * conns
    t0 = time.time(); t_end = t0 + seconds
    def send_one(i):
        q, qid = mkq("%s.s%d.%s" % (rnd(8), payload, ZONE), edns=4096)
        try: socks[i].sendall(struct.pack(">H", len(q)) + q)
        except Exception: return
        inflight[qid] = (time.time(), i)
    per = max(1, depth // conns)
    for i in range(conns):
        for _ in range(per): send_one(i)
    while time.time() < t_end:
        for i, c in enumerate(socks):
            try: chunk = c.recv(65535)
            except socket.timeout: chunk = b""
            except Exception: chunk = b""
            if not chunk: continue
            buf[i] += chunk
            while len(buf[i]) >= 2:
                ln = struct.unpack(">H", buf[i][:2])[0]
                if len(buf[i]) < 2 + ln: break
                msg = buf[i][2:2 + ln]; buf[i] = buf[i][2 + ln:]
                qid = struct.unpack(">H", msg[:2])[0]
                if qid in inflight:
                    del inflight[qid]; got += 1; bytes_in += len(msg)
        now = time.time()
        for k in [k for k, v in inflight.items() if now - v[0] > 4.0]:
            lost += 1; del inflight[k]
        if time.time() < t_end:
            for i in range(conns):
                mine = sum(1 for v in inflight.values() if v[1] == i)
                while mine < per:
                    send_one(i); mine += 1
    dt = time.time() - t0
    for c in socks:
        try: c.close()
        except Exception: pass
    qps = (got + lost) / dt
    P("  %d conn x depth %2d: %4.0f q/s, %6.1f KB/s down, loss %.1f%%" % (conns, depth, qps, bytes_in / dt / 1024, 100.0 * lost / max(1, got + lost)))
    return bytes_in / dt / 1024

tcp_res = {}
tcp_res["1x1"]   = tcp_run(1, 1, 4000)
tcp_res["1x8"]   = tcp_run(1, 8, 4000)
tcp_res["4x4"]   = tcp_run(4, 16, 4000)
tcp_res["8x2"]   = tcp_run(8, 16, 4000)
tcp_res["16x1"]  = tcp_run(16, 16, 4000)

# ============ 3. stability: best TCP mode, 25s ============
best_tcp = max(tcp_res, key=lambda k: tcp_res[k])
bc, bd = best_tcp.split("x")
hdr("3. STABILITY - TCP %s conn x depth %s for 25s" % (bc, bd))
tcp_run(int(bc), int(bd) * int(bc), 4000, seconds=25.0)

# ============ summary ============
best_udp = max(udp_res, key=lambda k: udp_res[k])
hdr("SUMMARY")
P("  UDP best : depth %d -> %.0f KB/s (%.1f Mbps)" % (best_udp, udp_res[best_udp], udp_res[best_udp] * 8 / 1024))
P("  TCP best : %s     -> %.0f KB/s (%.1f Mbps)" % (best_tcp, tcp_res[best_tcp], tcp_res[best_tcp] * 8 / 1024))
P("  all TCP  : " + ", ".join("%s->%.0f" % (k, v) for k, v in tcp_res.items()))
winner = "TCP" if tcp_res[best_tcp] > udp_res[best_udp] else "UDP"
P("  WINNER   : %s" % winner)
P("")
P("--- END OF PROBE 2 OUTPUT (paste everything above) ---")

#!/usr/bin/env python3
"""DNSTun reference client - mirrors exactly what the Android app does.

Creates a TUN device, tunnels IPv4 packets inside DNS queries, and keeps
`DEPTH` queries in flight at all times (that is what makes it fast).

  ZONE=v.techychi.com SID=k7m2p9 SERVER=127.0.0.1 PORT=15353 python3 client.py
"""
import base64, fcntl, os, random, socket, struct, sys, threading, time
from collections import deque

ZONE   = os.environ.get("ZONE", "v.techychi.com")
SID    = os.environ.get("SID", "k7m2p9")
SERVER = os.environ.get("SERVER", "127.0.0.1")
PORT   = int(os.environ.get("PORT", "15353"))
TUN    = os.environ.get("TUN", "dtun0")
TUNIP  = os.environ.get("TUNIP", "10.77.0.2")
DEPTH  = int(os.environ.get("DEPTH", "64"))
EDNS   = int(os.environ.get("EDNS", "1300"))
MTU    = int(os.environ.get("MTU", "1200"))
FRAG   = int(os.environ.get("FRAG", "140"))
VERBOSE = os.environ.get("VERBOSE", "0") == "1"

# ---- stats ----
st = dict(sent=0, recv=0, lost=0, up=0, down=0, pkts_up=0, pkts_down=0, t0=time.time(), rx=0, rx_to=0, rx_err=0, badqid=0)

def log(*a):
    if VERBOSE:
        print(*a, flush=True)

# ---------------------------------------------------------------------------
# TUN
# ---------------------------------------------------------------------------

def open_tun(name):
    TUNSETIFF = 0x400454ca
    IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
    f = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(f, TUNSETIFF, ifr)
    return f

def sh(cmd):
    if os.system(cmd) != 0:
        print("warn: command failed:", cmd, file=sys.stderr)

def setup_tun(fd, name):
    sh("ip addr add %s/32 dev %s 2>/dev/null" % (TUNIP, name))
    sh("ip link set %s up" % name)
    sh("ip link set %s mtu %d" % (name, MTU))
    for r in os.environ.get("ROUTE", "").split(","):
        if r.strip():
            sh("ip route replace %s dev %s" % (r.strip(), name))

# ---------------------------------------------------------------------------
# protocol
# ---------------------------------------------------------------------------

def b32(data: bytes) -> str:
    return base64.b32encode(data).decode().lower().rstrip("=")

def build_name(hdr: bytes, payload: bytes) -> str:
    blob = b32(hdr + payload)
    labels = [blob[i:i + 63] for i in range(0, len(blob), 63)]
    labels.append(SID)
    return ".".join(labels) + "." + ZONE

def mk_query(name, qid, edns=EDNS):
    out = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    for lab in name.split("."):
        out += bytes([len(lab)]) + lab.encode()
    out += b"\x00" + struct.pack(">HH", 16, 1)          # TXT IN
    out += b"\x00" + struct.pack(">HHIH", 41, edns, 0, 0)  # OPT
    return out

def parse_response(msg):
    """returns payload bytes (without the 3-byte header) or None"""
    if len(msg) < 12:
        return None
    qd = struct.unpack(">H", msg[4:6])[0]
    an = struct.unpack(">H", msg[6:8])[0]
    off = 12
    for _ in range(qd):                       # skip questions
        while off < len(msg) and msg[off] != 0:
            off += 1 + msg[off]
        off += 5
    for _ in range(an):
        if msg[off] & 0xc0 == 0xc0:
            off += 2
        else:
            while off < len(msg) and msg[off] != 0:
                off += 1 + msg[off]
            off += 1
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        off += rdlen
        if rtype == 16:                        # TXT
            payload = b""
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                payload += rdata[i + 1:i + 1 + ln]
                i += 1 + ln
            return payload
    return None

def split_ip_packets(buf):
    """split a concatenated IPv4 packet stream into packets"""
    out = []
    i = 0
    while i + 20 <= len(buf):
        if buf[i] >> 4 != 4:
            break
        total = struct.unpack(">H", buf[i + 2:i + 4])[0]
        if total < 20 or i + total > len(buf):
            break
        out.append(buf[i:i + total])
        i += total
    return out

# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------

frag_q = deque()          # fragments waiting to be sent
frag_lock = threading.Lock()
running = True
frag_id = 0
frag_id_lock = threading.Lock()

def tun_reader(fd):
    """read packets from the TUN, fragment them, queue for sending"""
    global frag_id
    while running:
        try:
            pkt = os.read(fd, 65535)
        except OSError:
            return
        if len(pkt) < 20 or pkt[0] >> 4 != 4:
            continue
        with frag_id_lock:
            fid = frag_id = (frag_id + 1) & 0xffff
        n = (len(pkt) + FRAG - 1) // FRAG
        for i in range(n):
            chunk = pkt[i * FRAG:(i + 1) * FRAG]
            flags = 0x01 if i < n - 1 else 0x00
            hdr = struct.pack(">HBB", fid, i, flags)
            with frag_lock:
                frag_q.append((hdr, chunk))
        st["pkts_up"] += 1

def run():
    fd = open_tun(TUN)
    setup_tun(fd, TUN)
    threading.Thread(target=tun_reader, args=(fd,), daemon=True).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.05)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    except Exception:
        pass

    inflight = {}
    last_stat = time.time()
    print("tunnel up: %s mtu=%d depth=%d -> %s:%d sid=%s" % (TUN, MTU, DEPTH, SERVER, PORT, SID), flush=True)

    sock.setblocking(False)
    while running:
        now = time.time()

        # ---- refill the pipeline ----
        while len(inflight) < DEPTH:
            with frag_lock:
                item = frag_q.popleft() if frag_q else None
            if item:
                hdr, chunk = item
                name = build_name(hdr, chunk)
                st["up"] += len(chunk)
            else:
                name = build_name(struct.pack(">HBB", 0, 0, 0), b"")  # poll
            qid = random.randint(1, 65535)
            try:
                sock.sendto(mk_query(name, qid), (SERVER, PORT))
            except OSError:
                continue
            inflight[qid] = now
            st["sent"] += 1

        # ---- drain every pending response (never let the rx buffer fill) ----
        drained = 0
        while drained < 4096:
            try:
                msg, _ = sock.recvfrom(65535)
            except (BlockingIOError, socket.timeout):
                break
            except OSError:
                break
            drained += 1
            if len(msg) > 100:
                st["big"] = st.get("big", 0) + 1
            st["rx"] += 1
            qid = struct.unpack(">H", msg[:2])[0]
            if qid in inflight:
                del inflight[qid]
                st["recv"] += 1
            else:
                st["badqid"] += 1
            payload = parse_response(msg)
            if payload and len(payload) > 3:
                st["down"] += len(payload) - 3
                for p in split_ip_packets(payload[3:]):
                    try:
                        os.write(fd, p)
                        st["pkts_down"] += 1
                    except OSError:
                        pass

        # ---- timeouts ----
        for qid in [k for k, v in inflight.items() if now - v > 3.0]:
            del inflight[qid]
            st["lost"] += 1

        if now - last_stat >= 2.0:
            dt = now - st["t0"]
            print("stats: q=%d/s loss=%.2f%% | UP %d pkts / %d B | DOWN %d pkts / %d B | inflight=%d badqid=%d big=%d"
                  % (st["recv"] / dt, 100.0 * st["lost"] / max(1, st["sent"]),
                     st["pkts_up"], st["up"], st["pkts_down"], st["down"], len(inflight), st["badqid"],
                     st.get("big", 0)),
                  flush=True)
            last_stat = now

        if drained == 0:
            time.sleep(0.0002)

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        running = False
        dt = time.time() - st["t0"]
        print("\nfinal: up=%.2f MB down=%.2f MB in %.1fs -> down %.1f KB/s (%.1f Mbps), pkts %d up / %d down, loss %.1f%%"
              % (st["up"] / 1e6, st["down"] / 1e6, dt, st["down"] / dt / 1024, st["down"] / dt * 8 / 1e6 / 1024,
                 st["pkts_up"], st["pkts_down"], 100.0 * st["lost"] / max(1, st["sent"])))

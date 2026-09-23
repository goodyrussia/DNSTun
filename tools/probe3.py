#!/usr/bin/env python3
"""DNSTun speed test - run in Termux, no root needed.

Measures the real downstream speed of the DNSTun tunnel through your carrier's
DNS resolver by keeping N queries in flight and asking the server to stream
test payloads back.

    python3 probe3.py                 # uses 188.31.250.128 (Smarty/Three)
    RESOLVER=1.1.1.1 python3 probe3.py
"""
import base64
import os
import random
import socket
import struct
import sys
import time

ZONE = os.environ.get("ZONE", "v.techychi.com")
SID = os.environ.get("SID", "g7x2k9")
RESOLVER = os.environ.get("RESOLVER", "188.31.250.128")
PORT = int(os.environ.get("PORT", "53"))
EDNS = int(os.environ.get("EDNS", "1300"))
PRIME = int(os.environ.get("PRIME", "8000000"))   # bytes queued before each run
DEPTHS = [int(x) for x in os.environ.get("DEPTHS", "32,64,128,192").split(",")]
SECONDS = int(os.environ.get("SECONDS", "10"))
WARMUP = float(os.environ.get("WARMUP", "2"))


def b32(b):
    return base64.b32encode(b).decode().lower().rstrip("=")


def mkq(name, qid):
    o = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    for l in name.split("."):
        o += bytes([len(l)]) + l.encode()
    return o + b"\x00" + struct.pack(">HH", 16, 1) + b"\x00" + struct.pack(">HHIH", 41, EDNS, 0, 0)


POLL_NAME = b32(b"\x00\x00\x00") + "." + SID + "." + ZONE
PRIME_NAME = "s%d.%s.%s" % (PRIME, SID, ZONE)


def parse_payload(msg):
    """pull the TXT rdata out of a response, concatenating its strings"""
    if len(msg) < 12:
        return None
    qd = struct.unpack(">H", msg[4:6])[0]
    an = struct.unpack(">H", msg[6:8])[0]
    off = 12
    for _ in range(qd):
        while off < len(msg) and msg[off] != 0:
            off += 1 + msg[off]
        off += 5
    for _ in range(an):
        if off + 2 > len(msg):
            return None
        if (msg[off] >> 6) == 3:
            off += 2
        else:
            while off < len(msg) and msg[off] != 0:
                off += 1 + msg[off]
            off += 1
        if off + 10 > len(msg):
            return None
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        off += rdlen
        if rtype == 16:
            payload = b""
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                payload += rdata[i + 1:i + 1 + ln]
                i += 1 + ln
            return payload
    return None


def run_depth(depth):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    dst = (RESOLVER, PORT)

    sock.sendto(mkq(PRIME_NAME, random.randint(1, 65535)), dst)
    time.sleep(0.4)

    sent = recv = 0
    total = 0
    t0 = time.time()
    last_rx = last_prime = t0
    warm = None
    warm_bytes = 0

    while True:
        now = time.time()
        if now - t0 >= SECONDS:
            break
        if warm is None and now - t0 >= WARMUP:
            warm = now
            warm_bytes = total

        while sent - recv < depth:
            sock.sendto(mkq(POLL_NAME, random.randint(1, 65535)), dst)
            sent += 1

        got = False
        while True:
            try:
                msg = sock.recvfrom(65535)[0]
            except (BlockingIOError, socket.timeout):
                break
            recv += 1
            got = True
            p = parse_payload(msg)
            if p and len(p) > 3:
                total += len(p) - 3

        if got:
            last_rx = now
        elif now - last_rx > 2.0:
            recv = sent          # assume the whole window was dropped

        if now - last_prime > 1.0:
            sock.sendto(mkq(PRIME_NAME, random.randint(1, 65535)), dst)
            sent += 1
            last_prime = now

        if not got:
            time.sleep(0.0002)

    sock.close()
    dt = time.time() - (warm or t0)
    measured = total - warm_bytes
    kbs = measured / dt / 1024.0
    qps = recv / max(0.001, time.time() - t0)
    loss = 100.0 * (sent - recv) / max(1, sent)
    return kbs, qps, loss, measured


def main():
    print("DNSTun speed test   resolver=%s zone=%s sid=%s" % (RESOLVER, ZONE, SID))
    print("time: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    print("")
    print("=" * 56)
    print(" downstream: %d queries in flight, replies carry ~1.2KB each" % DEPTHS[0])
    print("=" * 56)
    best = (0, 0, 0)
    for d in DEPTHS:
        try:
            kbs, qps, loss, nb = run_depth(d)
        except Exception as e:
            print("  depth %4d: FAILED (%s: %s)" % (d, type(e).__name__, e))
            continue
        print("  depth %4d: %6.1f q/s, %7.1f KB/s down (%4.2f Mbps), loss %4.1f%%"
              % (d, qps, kbs, kbs * 8 / 1024.0, loss))
        if kbs > best[0]:
            best = (kbs, d, loss)
    print("")
    print("=" * 56)
    print(" SUMMARY")
    print("=" * 56)
    print("  best : depth %d -> %.1f KB/s (%.2f Mbps), loss %.1f%%"
          % (best[1], best[0], best[0] * 8 / 1024.0, best[2]))
    print("")
    print("--- END OF DNSTUN SPEED TEST (paste everything above) ---")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)

import socket, sys
LP = int(sys.argv[1]); SP = int(sys.argv[2])
MAX = int(sys.argv[3]) if len(sys.argv) > 3 else 523
DROP = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
import random
UP = ("127.0.0.1", SP)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", LP))
n = 0
c = 0
m = 0
while True:
    data, addr = s.recvfrom(4096)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(3)
    try:
        if DROP > 0 and random.random() < DROP:
            continue
        u.sendto(data, UP)
        r, _ = u.recvfrom(65535)
        if len(r) > m:
            m = len(r)
        c += 1
        if c % 1000 == 0:
            print("replies", c, "maxsize", m, flush=True)
        if len(r) > MAX:
            r = r[:MAX]
            n += 1
            if n % 25 == 1: print("TRUNC", len(data), "->", MAX, flush=True)
        s.sendto(r, addr)
    except Exception:
        pass
    finally:
        u.close()

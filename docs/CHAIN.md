# The chain, in detail

Everything below was measured against the distributed TES3MP 0.8.1 Linux server binary
(`tes3mp-server.x86_64`) running on Ubuntu 24.04 (glibc 2.39), not inferred from source alone.

## Target mitigations

Measured with `readelf` on the shipped binary:

```
GNU_RELRO   0x2b5680 .. 0x2c3000       <- ends exactly where .got.plt begins
.got.plt    RVA 0x2c3000   flags WA    <- writable for the whole process lifetime
JUMP_SLOT   301 entries
```

### The RELRO line is a distro accident, not a decision (MEASURED 2026-08-23)

TES3MP's `CMakeLists.txt` sets **no hardening flags at all** (only `-Wall -Wextra -Wundef -pedantic`,
`:578`), so whether a given server is exposed is decided entirely by whose toolchain built it.
Measured with a plain `g++ -O2` on a trivial file, no flags added, on the fuzz pool:

| Host | Compiler | `GNU_RELRO` | `BIND_NOW` | `.got.plt` | Result |
|---|---|---|---|---|---|
| Ubuntu 24.04 | g++ 13 | yes | **yes** | **absent** | **full RELRO: immune** |
| Debian 12 | g++ 12 | yes | no | present | partial RELRO: **exposed** |
| shipped 0.8.1 release | Debian GCC 8.3 | yes | no | present | partial RELRO: **exposed** |

So the same source, built by two people on two current distributions, produces one server this chain
cannot touch and one it owns. The shipped release binary is on the exposed side, which is the only
reason any of this works.

Two consequences worth stating plainly. For an operator who cannot patch, **rebuilding from source on
a modern Ubuntu is a complete mitigation on its own**, at zero code change, because the toolchain
default alone removes the writable GOT. And for anyone writing a detector: testing whether `.got.plt`
falls inside `GNU_RELRO` is **not sufficient**, because a full-RELRO link commonly emits no `.got.plt`
section at all (eager binding leaves no lazy slots, so what remains folds into `.got`). The
authoritative signal is `DT_BIND_NOW`, `DT_FLAGS & DF_BIND_NOW`, or `DT_FLAGS_1 & DF_1_NOW` in the
dynamic table. `tes3mp-rce --server-bin` checks those and refuses.

PIE and NX are on (toolchain defaults). Stack canary, FORTIFY and full RELRO are absent. `system` is
**not** imported, so it has to come from libc, which is why a libc leak is needed at all.

## Step 1 - out-of-bounds read (the original defect)

`PacketPlayerEquipment::Packet()` reads a client-supplied `equipmentIndex` and uses it without a bounds
check (`components/openmw-mp/Packets/Player/PacketPlayerEquipment.cpp:42`). Sibling packets already do
this correctly (`Attribute >= 8`, `Skill >= 27`, `StatsDynamic >= 3`), so the intent is written down
elsewhere in the same codebase.

Truncating the packet immediately after the index means `RW(item.count, ...)` fails on an exhausted
stream. Its return value is **discarded**, so processing continues and the server relays
`equipmentItems[idx].count|charge` unchanged to every client in the cell. Those two `int`s are simply
whatever memory lies at `equipmentItems + 80*idx + 32`.

At index 25 that lands on `chatMessage._M_p`, giving a live heap pointer.

Note this is not the base of anything useful: `chatMessage` is heap-allocated within moments of joining,
because CoreScripts assigns login prompts and a "player joined" broadcast to it, and both exceed the
15-character small-string threshold. The value is used only as *a valid writable address*.

## Step 2 - grooming, and why it is necessary

Index 28's `refId` lives at `BasePlayer + 5856`, so the string **object** written by the assignment starts
32 bytes earlier, at `BasePlayer + 5824`, which is `animation.mode` and `animation.count`.

`std::string::operator=(const char*)` on that fake object calls
`_M_replace(0, size(), s, traits_type::length(s))`. Assigning an empty string takes the **in-place**
branch (`new_size <= capacity()`), which ends in:

```cpp
_M_set_length(0);   // -> traits_type::assign(_M_data()[0], '\0')
```

That is a NUL **write** through `_M_p`. If `_M_p` is null it faults. So the widely-repeated rule
"`_M_p == NULL` is free-safe because `operator delete(NULL)` is a no-op" is **wrong for this path**: no
free happens at all, and the terminating NUL still needs a writable destination.

`animation.mode` and `animation.count` are attacker-settable via `ID_PLAYER_ANIM_PLAY`
(`PacketPlayerAnimPlay.cpp:13-16`), so writing the leaked heap pointer into them makes that NUL land
harmlessly inside the chat buffer.

## Step 3 - the object base

With the clobber survivable, a truncated index 28 relays `creatureRefId._M_p`. That string is never
assigned anything long, so it stays in small-string form and its `_M_p` **points at its own buffer**:
a self-pointer, and therefore an absolute address of a known field.

```
base = leaked - 0x16F0      # creatureRefId at 5856, + 16 for the SSO buffer = 5872 = 0x16F0
```

Layout confirmed in gdb: `equipmentItems = Player + 0xE08`, `BasePlayer = Player + 8` (Itanium ABI: vptr
at offset 0, non-polymorphic base subobject after it).

## Steps 4-5 - arbitrary read, image base, libc base

Planting a fake `std::string{_M_p = target, _M_len = 8}` into an equipment `refId` and then triggering
`ID_PLAYER_CELL_CHANGE` makes the server re-serialize the whole equipment array *from storage* to every
client in the cell. The send path only **reads** `refId`, so the plant survives, and 8 bytes from `target`
arrive at the other client.

Two gotchas, both of which cost real time to find:

* **The write used to plant is `strlen`-truncated.** The server does `chatMessage = rstr.C_String()`, so
  anything after an internal NUL is not written. Multi-byte values must be planted byte by byte.
* **`EncodeString` calls `strlen(input)` with no zero guard** (`StringCompressor.cpp:96-107`). If the
  target's first byte is `0x00` the wire gets an 8-bit empty string, which is indistinguishable from a
  failed read. Read only memory the server does not continually rewrite: a vtable slot is ideal, whereas
  the position fields and the equipment array itself are rewritten constantly.

`*(base-8)` is the `Player` vtable pointer (`info symbol` prints `vtable for Player + 16`, the Itanium
address point), giving the image base. The result is asserted page-aligned, so a partial or stale read is
discarded rather than used.

For libc, read a **resolved GOT entry**. Use `malloc@got`, **not** `strlen@got`: `strlen` is an **IFUNC**,
so its GOT holds the selected implementation (`__strlen_avx2`) rather than the nominal symbol, and the
offset arithmetic would be silently wrong. This also replaces an earlier approach that abused the
allocator, which means **the final chain corrupts no heap metadata at all**, a large part of why the
server survives long enough to be exploited.

## Steps 6-7 - GOT overwrite and the trigger

Aim `eq[7].refId` at `strlen@got` and set its `capacity` field high enough that the assignment takes the
in-place branch. If capacity were too small, `_M_replace` would reallocate and `free()` the GOT address.

Then a **single** equipment packet carrying **two in-bounds items**:

```
item 7:  refId = <6 bytes of system>     -> assignment writes system into strlen@got
item 5:  refId = "<payload command>"     -> assignment calls the hijacked strlen ON THE PAYLOAD
```

The second half works because `operator=(const char*)` measures its **source** with
`traits_type::length()`, i.e. `strlen`, at the main binary's own call site, and therefore through the
main binary's GOT. `strlen(payload)` is now `system(payload)`.

Both halves inside one deserialize is what makes it reliable. Every attempt that overwrote the GOT and
then triggered with a *separate* packet died first inside `TimedLog::print`, where `__ostream_insert`
memcpy's using `strlen`'s return value, which is now a shell exit status (32512 for "command not found").

For the same reason the payload should **exit 0**.

## Why other targets do not work

* **`fopen@got`**: a GOT overwrite only intercepts calls made *from the object whose GOT was patched*.
  The main binary has 5 `fopen` call sites, all server-side paths; `data/player/<account>.json` is written
  through **libluajit's** GOT.
* **boost::filesystem paths** (which do take the account name) resolve through libboost's GOT, and the
  bundled boost objects were built with **full RELRO**.
* **Indices 32 / 34 / 38** are the only other candidates whose count|charge holds a self-pointer, but they
  all sit inside the `ESM::Cell` sub-object, so corrupting them crashes the next cell operation.

## Fix

Bounds-check `equipmentIndex` against `[0, 19)`. This alone breaks step 1 and therefore everything after
it. Then check `RW()` return values and abandon the packet on a short read. Then build with full RELRO,
`-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, `_GLIBCXX_ASSERTIONS`, and strip release binaries.

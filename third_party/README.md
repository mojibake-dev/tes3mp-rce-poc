# Third-party dependencies

## `tes3mp/components/openmw-mp/NetworkMessages.hpp` (vendored)

The packet-ID enum, copied verbatim from TES3MP at tag `tes3mp-0.8.1`
(commit `68954091c54d0596037c4fb54d2812313b7582a1`), <https://github.com/TES3MP/TES3MP>.

It is the only file this exploit needs from the TES3MP tree — it includes nothing but RakNet's
`MessageIdentifiers.h` — so it is vendored rather than making you clone a 200 MB game engine to get
one enum. **TES3MP is GPLv3**, which is why this repository is also GPLv3.

To refresh it against another release:

```sh
curl -o third_party/tes3mp/components/openmw-mp/NetworkMessages.hpp \
  https://raw.githubusercontent.com/TES3MP/TES3MP/tes3mp-0.8.1/components/openmw-mp/NetworkMessages.hpp
```

## `CrabNet/` (fetched by `make deps`, not vendored)

TES3MP's RakNet fork, <https://github.com/TES3MP/CrabNet>, pinned to commit
`19e66190e83f53bcdcbcd6513238ed2e54878a21`. **BSD licensed** (Oculus VR, 2014).

Fetched rather than vendored because the exploit has to *link* it, and the useful artefact is a
17 MB `libRakNetLibStatic.a` built for your platform — not something that belongs in git. `make deps`
clones it at the pinned commit and builds only the static library target.

The pin matters: the wire format, the reliability layer and the Huffman string compressor all have to
match what the target server links, or nothing connects.

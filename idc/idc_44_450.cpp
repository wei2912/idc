#include <bitset>
#include <iostream>
#include <map>
#include "idc.h"

extern "C" {
#include "../some_cipher.h"
}

void decrypt_r(const uint16_t *input, uint16_t *output, const uint16_t *ki) {
    output[0] = input[0] ^ ki[0];
    output[1] = input[1] ^ ki[1];
    output[2] = input[2] ^ ki[2];

    uint16_t s0, s1, s2;
    s0 = output[0];
    s1 = output[1];
    s2 = output[2];
    output[0] = TD0[s0 >> 12]
        ^ TD1[s0 >> 8 & 0xF]
        ^ TD2[s1 >> 4 & 0xF]
        ^ TD3[s2 & 0xF];
    output[1] = TD0[s1 >> 12]
        ^ TD1[s1 >> 8 & 0xF]
        ^ TD2[s2 >> 4 & 0xF]
        ^ TD3[s0 & 0xF];
    output[2] = TD0[s2 >> 12]
        ^ TD1[s2 >> 8 & 0xF]
        ^ TD2[s0 >> 4 & 0xF]
        ^ TD3[s1 & 0xF];
}

static bool has_192(const uint16_t *xs, const uint16_t *ys) {
    // only need to check for middle column
    return (
        // check for passive nibbles
        (xs[1] & 0x00FF) == (ys[1] & 0x00FF) &&

        // check for active nibbles
        (xs[1] & 0xF000) != (ys[1] & 0xF000) &&
        (xs[1] & 0x0F00) != (ys[1] & 0x0F00)
    );
}

static bool has_208(const uint16_t *xs, const uint16_t *ys) {
    // only need to check for middle column
    return (
        // check for passive nibbles
        (xs[1] & 0x00F0) == (ys[1] & 0x00F0) &&

        // check for active nibbles
        (xs[1] & 0xF000) != (ys[1] & 0xF000) &&
        (xs[1] & 0x0F00) != (ys[1] & 0x0F00) &&
        (xs[1] & 0x000F) != (ys[1] & 0x000F)
    );
}

static bool has_224(const uint16_t *xs, const uint16_t *ys) {
    // only need to check for middle column
    return (
        // check for passive nibbles
        (xs[1] & 0x00F0) == (ys[1] & 0x00F0) &&

        // check for active nibbles
        (xs[1] & 0xF000) != (ys[1] & 0xF000) &&
        (xs[1] & 0x0F00) != (ys[1] & 0x0F00) &&
        (xs[1] & 0x00F0) != (ys[1] & 0x00F0)
    );
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " [start] [end]" << std::endl;
        std::cerr << "start and end are 16-bit values indicating the range of partial subkeys to test" << std::endl;
        return 2;
    }

    uint32_t start = std::stoull(argv[1]);
    uint32_t end = std::stoull(argv[2]);

    // 1. Create a map of partial K6s from start to end, to a bitset of omega5s.
    // If pks[k6][omega5] == 0, the pair (k6, omega5) is eliminated.
    pks_t pks;
    for (uint32_t pk6 = start; pk6 <= end; ++pk6) {
        std::bitset<256> bs;
        bs.set();
        pks[pk6] = bs;
    }

    // 2. Read in plaintext-ciphertext pairs.
    uint16_t ct0[3], ct1[3];
    uint64_t pt0_hex, ct0_hex, pt1_hex, ct1_hex;
    while (std::cin >> std::hex >> pt0_hex >> ct0_hex >> pt1_hex >> ct1_hex) {
        ct0[0] = ct0_hex >> 32;
        ct0[1] = ct0_hex >> 16 & 0xFFFF;
        ct0[2] = ct0_hex & 0xFFFF;

        ct1[0] = ct1_hex >> 32;
        ct1[1] = ct1_hex >> 16 & 0xFFFF;
        ct1[2] = ct1_hex & 0xFFFF;

        // 3. For each plaintext-ciphertext pair, iterate through the vector of partial subkeys for round 6.
        // Decrypt the ciphertexts and check if they have the following differences:
        // 010
        // 010
        // 000
        for (auto it = pks.begin(); it != pks.end(); ++it) {
            // construct full k6 from pk6.
            // (value of fixed nibbles do not matter)
            uint16_t pk6 = it->first;
            uint16_t k6[3];
            k6[0] = pk6 >> 12;
            k6[1] = pk6 << 4 & 0xFF00;
            k6[2] = pk6 << 4 & 0x00F0;

            uint16_t state0[3], state1[3];
            decrypt_r(ct0, state0, k6);
            decrypt_r(ct1, state1, k6);

            if (has_192(state0, state1)) {
                // 4. Go through all the possible omega5s.
                // Decrypt the ciphertexts with each omega5 and check if they have the following differences:
                // 010
                // 010
                // 000
                // 010
                // or
                // 010
                // 010
                // 010
                // 000

                for (uint16_t po5 = 0; po5 < 256; ++po5) {
                    // check if key has already been eliminated
                    if (it->second[po5] == 0) continue;

                    uint16_t o5[3];
                    o5[1] = po5 << 8;

                    uint16_t state2[3], state3[3];
                    decrypt_r(state0, state2, o5);
                    decrypt_r(state1, state3, o5);

                    // 5. If omega5 has met the impossible differential, eliminate it.
                    if (has_208(state2, state3) || has_224(state2, state3)) it->second[po5] = 0;
                }
            }

            // 6. Check if the number of bits is 0.
            // If so, it means k6 has been eliminated, so delete it from the map.
            if (it->second.count() == 0) it = pks.erase(it);
        }

        // 7. Break when all (k6, o5) pairs except for one have been eliminated.
        if (pks.size() == 1 && pks.begin()->second.count() == 1) break;
    }

    // 8. Print out all (k6, o5) pairs.
    for (auto it = pks.begin(); it != pks.end(); ++it) {
        uint16_t pk6 = it->first;
        for (int po5 = 0; po5 < 256; ++po5) {
            if (it->second[po5] == 1) std::printf("%04x %02x\n", pk6, po5);
        }
    }

    return 0;
}


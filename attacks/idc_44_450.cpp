#include <algorithm>
#include <bitset>
#include <cstdio>
#include <iostream>
#include <iterator>
#include <vector>

extern "C" {
#include "../some_cipher.h"
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
        (xs[1] & 0x000F) == (ys[1] & 0x000F) &&

        // check for active nibbles
        (xs[1] & 0xF000) != (ys[1] & 0xF000) &&
        (xs[1] & 0x0F00) != (ys[1] & 0x0F00) &&
        (xs[1] & 0x00F0) != (ys[1] & 0x00F0)
    );
}

int main(int argc, char *argv[]) {
    // 1. Create a bitset representing pairs of partial k6s and omega5s,
    // and an index. The bitset keeps track of which pairs are eliminated,
    // the index keeps track of which partial k6s to iterate through.
    // If pks[(k6 << 8) | omega5] == 0, the pair (k6, omega5) is eliminated.
    std::bitset<16777216> pks;
    std::vector<uint16_t> index;
    pks.set();
    index.reserve(65536);
    for (int pk6 = 0; pk6 < 65536; ++pk6) index.push_back(pk6);

    // 2. Read in plaintext-ciphertext pairs.
    int n = 16777216;
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
        // 000

        auto it = index.begin();
        while (it != index.end()) {
            // construct full k6 from pk6.
            // (value of fixed nibbles do not matter)
            uint16_t pk6 = *it;
            uint16_t k6[3] = {};
            k6[0] = pk6 >> 12;
            k6[1] = pk6 << 4 & 0xFF00;
            k6[2] = pk6 << 4 & 0x00F0;

            uint16_t state0[3], state1[3];

            add_key(ct0, state0, k6);
            decrypt_r(state0, state0);

            add_key(ct1, state1, k6);
            decrypt_r(state1, state1);

            bool is_eliminated = false;
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

                is_eliminated = true;
                for (int po5 = 0; po5 < 256; ++po5) {
                    uint32_t pos = (((uint32_t) pk6) << 8) | po5;
                    if (pks[pos] == 0) continue;

                    uint16_t o5[3] = {};
                    o5[1] = po5 << 8;

                    uint16_t state2[3], state3[3];

                    add_key(state0, state2, o5);
                    decrypt_r(state2, state2);

                    add_key(state1, state3, o5);
                    decrypt_r(state3, state3);

                    // 5. If omega5 has met the impossible differential, eliminate it.
                    if (has_208(state2, state3) || has_224(state2, state3)) {
                        pks[pos] = 0;
                        --n;
                    // ...else, we mark pk6 as not eliminated.
                    } else is_eliminated = false;
                }
            }

            // 6. If pk6 has been eliminated, delete it from the index.
            if (is_eliminated) it = index.erase(it);
            else ++it;
        }

        if (n <= 1) break;
    }

    // 7. Print out all (k6, o5) pairs.
    for (auto &pk6 : index) {
        for (uint16_t po5 = 0; po5 < 256; ++po5) {
            if (pks[(pk6 << 8) | po5] == 1) std::printf("%04x %02x\n", pk6, po5);
        }
    }

    return 0;
}


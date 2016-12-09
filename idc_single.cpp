#include <bitset>
#include <iostream>
#include <map>
#include <vector>

extern "C" {
#include "some_cipher.h"
}

// MC_INV_0 = x . [8, 12, 7, 7]
const uint16_t MC_INV_0[16] = {
    0x0000, 0x8B77, 0x35EE, 0xBE99,
    0x6AFF, 0xE188, 0xF155, 0xD466,
    0xC7DD, 0x4CAA, 0xF233, 0x7944,
    0xAD22, 0x2655, 0x96CC, 0x1388
};

// MC_INV_1 = x . [12, 7, 7, 8]
const uint16_t MC_INV_1[16] = {
    0x0000, 0xB77B, 0x5EE3, 0xE99B,
    0xAFF6, 0x188E, 0x155F, 0x466D,
    0x7DDC, 0xCAA4, 0x233F, 0x9447,
    0xD22A, 0x6552, 0x6CC9, 0x3881
};

// MC_INV_2 = x . [7, 7, 8, 12]
const uint16_t MC_INV_2[16] = {
    0x0000, 0x778B, 0xEE35, 0x99BE,
    0xFF6A, 0x88E1, 0x55F1, 0x66D4,
    0xDDC7, 0xAA4C, 0x33F2, 0x4479,
    0x22AD, 0x5526, 0xCC96, 0x8813
};

// MC_INV_3 = x . [7, 8, 12, 7]
const uint16_t MC_INV_3[16] = {
    0x0000, 0x78B7, 0xE35E, 0x9BE9,
    0xF6AF, 0x8E18, 0x5F15, 0x6D46,
    0xDC7D, 0xA4CA, 0x3F23, 0x4794,
    0x2AD2, 0x5265, 0xC96C, 0x8138
};

static void decrypt_r(const uint16_t *input, uint16_t *output, const uint16_t *ki) {
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

static void derive_master(const uint16_t *k6, uint16_t *output, std::bitset<256> bs) {
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
    std::map<uint32_t, std::bitset<256>> pks;
    for (uint32_t pk6 = start; pk6 <= end; ++pk6) {
        std::bitset<256> bs;
        bs.set();
        pks[pk6] = bs;
    }

    // 2. Read in plaintext-ciphertext pairs.
    uint16_t pt0[3], ct0[3], ct1[3];
    uint64_t pt0_hex, ct0_hex, pt1_hex, ct1_hex;
    while (std::cin >> std::hex >> pt0_hex >> ct0_hex >> pt1_hex >> ct1_hex) {
        pt0[0] = pt0_hex >> 32;
        pt0[1] = pt0_hex >> 16 & 0xFFFF;
        pt0[2] = pt0_hex & 0xFFFF;

        ct0[0] = ct0_hex >> 32;
        ct0[1] = ct0_hex >> 16 & 0xFFFF;
        ct0[2] = ct0_hex & 0xFFFF;

        // no need for pt1
        // as we only need the CT for the attack
        // and one PT-CT for the brute force

        ct1[0] = ct1_hex >> 32;
        ct1[1] = ct1_hex >> 16 & 0xFFFF;
        ct1[2] = ct1_hex & 0xFFFF;

        /*
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

                for (uint16_t po5 = 0; po5 < 256; ++po5) {
                    // check if key has already been eliminated
                    if (it->second[po5] == 0) continue;

                    uint16_t o5[3];
                    o5[1] = po5 << 8;

                    uint16_t state2[3], state3[3];
                    decrypt_r(state0, state2, o5);
                    decrypt_r(state1, state3, o5);

                    // 5. If omega5 has met the impossible differential, eliminate it.
                    if (has_208(state2, state3)) it->second[po5] = 0;
                }
            }

            // 6. Check if the number of bits is 0.
            // If so, it means k6 has been eliminated, so delete it from the map.
            if (it->second.count() == 0) it = pks.erase(it);
        }
        */
    }

    // 7. After filtering for partial subkeys of round 6,
    // construct subkeys for round 6 and derive the master key.
    // Brute force on a plaintext-ciphertext pair.
    for (uint64_t i = 0; i < 4294967296; ++i) {
        for (auto it = pks.begin(); it != pks.end(); ++it) {
            uint16_t pk6 = it->first;
            uint16_t k6[3];
            k6[0] = (i >> 36 & 0xFFF0) | (pk6 >> 12);
            k6[1] = (pk6 << 4 & 0xFF00) | (i >> 12 & 0x00FF);
            k6[2] = (i << 4 & 0xFF00) | (pk6 << 4 & 0x00F0) | (i & 0x000F);

            // 8. Derive k5 from k6 and check that the key nibbles of omega5 do not match up with an eliminated pair.
            uint16_t k5[3];
            k5[1] = k6[0] ^ k6[1]; // obtain just the middle column to check if it's eliminated
            uint16_t po5;
            po5 = (MC_INV_0[k5[1] >> 12]
                ^ MC_INV_1[k5[1] >> 8 & 0xF]
                ^ MC_INV_2[k5[1] >> 4 & 0xF]
                ^ MC_INV_3[k5[1] & 0xF]) >> 8;
            if (it->second[po5] == 0) continue;
            
            // 9. Derive the rest of k5 and up to the master key.
            k5[2] = k6[1] ^ k6[2];
            uint16_t last_col = (k5[2] << 4) ^ (k5[2] >> 12);
            k5[0] = (
                (TE4[last_col >> 12] ^ RCONS[5]) << 12
                ^ TE4[last_col >> 8 & 0xF] << 8
                ^ TE4[last_col >> 4 & 0xF] << 4
                ^ TE4[last_col & 0xF]
            ) ^ k6[0];

            uint16_t key[3], k0[3];
            key[0] = k5[0];
            key[1] = k5[1];
            key[2] = k5[2];

            for (int i = ROUNDS - 1; i >= 0; --i) {
                k0[2] = key[1] ^ key[2];
                k0[1] = key[0] ^ key[1];

                uint16_t last_col = (k0[2] << 4) ^ (k0[2] >> 12);
                k0[0] = (
                    (TE4[last_col >> 12] ^ RCONS[i]) << 12
                    ^ TE4[last_col >> 8 & 0xF] << 8
                    ^ TE4[last_col >> 4 & 0xF] << 4
                    ^ TE4[last_col & 0xF]
                ) ^ key[0];

                key[0] = k0[0];
                key[1] = k0[1];
                key[2] = k0[2];
            }

            std::printf("%04x%04x%04x\n", k0[0], k0[1], k0[2]);
            std::printf("%04x%04x%04x\n", k5[0], k5[1], k5[2]);
            std::printf("%04x%04x%04x\n", k6[0], k6[1], k6[2]);
            std::cout << "---" << std::endl;

            // 9. Try to encrypt a plaintext with the master key and see if it matches.
            uint16_t output[3];
            encrypt(pt0, output, k0);

            if (output[0] == ct0[0] &&
                output[1] == ct0[1] &&
                output[2] == ct0[2]) {
                std::printf("%04x%04x%04x\n", k0[0], k0[1], k0[2]);
                return 0;
            }
        }
    }

    return 1;
}


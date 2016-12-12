#include <bitset>
#include <iostream>
#include <map>
#include <vector>

extern "C" {
#include "../some_cipher.h"
}

// MC_INV_0 = x . [8, 12, 7, 7]
const uint16_t MC_INV_0[16] = {
    0x0000, 0x8C77, 0x3BEE, 0xB799,
    0x65FF, 0xE988, 0xFE11, 0xD266,
    0xCADD, 0x46AA, 0xF133, 0x7D44,
    0xAF22, 0x2355, 0x94CC, 0x18BB
};

// MC_INV_1 = x . [12, 7, 7, 8]
const uint16_t MC_INV_1[16] = {
    0x0000, 0xC778, 0xBEE3, 0x799B,
    0x5FF6, 0x988E, 0xE115, 0x266D,
    0xADDC, 0x6AA4, 0x133F, 0xD447,
    0xF22A, 0x3552, 0x4CC9, 0x8BB1
};

// MC_INV_2 = x . [7, 7, 8, 12]
const uint16_t MC_INV_2[16] = {
    0x0000, 0x778C, 0xEE3B, 0x99B7,
    0xFF65, 0x88E9, 0x115E, 0x66D2,
    0xDDCA, 0xAA46, 0x33F1, 0x447D,
    0x22AF, 0x5523, 0xCC94, 0xBB18
};

// MC_INV_3 = x . [7, 8, 12, 7]
const uint16_t MC_INV_3[16] = {
    0x0000, 0x78C7, 0xE3BE, 0x9B79,
    0xF65F, 0x8E98, 0x15E1, 0x6D26,
    0xDCAD, 0xA46A, 0x3F13, 0x47D4,
    0x2AF2, 0x5235, 0xC94C, 0xB18B
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

std::map<uint32_t, std::bitset<256>> filter_keys(std::map<uint32_t, std::bitset<256>> pks, std::function<bool(uint16_t *, uint16_t *)> has_r5_diff, std::function<bool(uint16_t *, uint16_t *)> has_r4_diff, uint16_t *ct0, uint16_t *ct1) {
    // 1. For each plaintext-ciphertext pair, iterate through the vector of partial subkeys for round 6.
    // Decrypt the ciphertexts and check if they meet the differences.
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

        if (has_r5_diffs(state0, state1)) {
            // 2. Go through all the possible omega5s.
            // Decrypt the ciphertexts with each omega5 and check if they have the differences.
            for (uint16_t po5 = 0; po5 < 256; ++po5) {
                // check if key has already been eliminated
                if (it->second[po5] == 0) continue;

                uint16_t o5[3];
                o5[1] = po5 << 8;

                uint16_t state2[3], state3[3];
                decrypt_r(state0, state2, o5);
                decrypt_r(state1, state3, o5);

                // 5. If omega5 has met the impossible differential, eliminate it.
                if (has_r6_diffs(state2, state3)) it->second[po5] = 0;
            }
        }

        // 6. Check if the number of bits is 0.
        // If so, it means k6 has been eliminated, so delete it from the map.
        if (it->second.count() == 0) it = pks.erase(it);
    }
    return pks;
}

int main(int argc, char *argv[]) {

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


        // 7. Break when all (k6, o5) pairs except for one have been eliminated.
        if (pks.size() == 1 && pks.begin()->second.count() == 1) break;
    }

    // 8. After filtering for partial subkeys of round 6,
    // construct subkeys for round 6 and derive the master key.
    // Brute force on a plaintext-ciphertext pair.
    for (auto it = pks.begin(); it != pks.end(); ++it) {
        uint16_t pk6 = it->first;

        for (uint64_t i = 0; i < 4294967296; ++i) {
            uint16_t k6[3];
            k6[0] = (i >> 16 & 0xFFF0) | (pk6 >> 12);
            k6[1] = (pk6 << 4 & 0xFF00) | (i >> 12 & 0x00FF);
            k6[2] = (i << 4 & 0xFF00) | (pk6 << 4 & 0x00F0) | (i & 0x000F);

            // 8. Derive k5 from k6 and check that the key nibbles of omega5 do not match up with an eliminated pair.
            uint16_t k5[3];
            k5[1] = k6[0] ^ k6[1]; // obtain just the middle column to check if it's eliminated
            uint16_t po5 = (MC_INV_0[k5[1] >> 12]
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

            for (int i = 4; i >= 0; --i) {
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


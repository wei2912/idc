#include <iostream>
#include <vector>

extern "C" {
#include "some_cipher.h"
}

/*
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
        ^ TD3[s2 & 0xF]
        ^ ki[0];
    output[1] = TD0[s1 >> 12]
        ^ TD1[s1 >> 8 & 0xF]
        ^ TD2[s2 >> 4 & 0xF]
        ^ TD3[s0 & 0xF]
        ^ ki[1];
    output[2] = TD0[s2 >> 12]
        ^ TD1[s2 >> 8 & 0xF]
        ^ TD2[s0 >> 4 & 0xF]
        ^ TD3[s1 & 0xF]
        ^ ki[2];
}
*/

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

static void derive_master(const uint16_t *k6, uint16_t *output) {
    uint16_t key[3];
    
    key[0] = k6[0];
    key[1] = k6[1];
    key[2] = k6[2];
    for (int i = ROUNDS; i >= 0; --i) {
        output[2] = key[1] ^ key[2];
        output[1] = key[0] ^ key[1];

        uint16_t last_col = (output[2] << 4) ^ (output[2] >> 12);
        output[0] = (
            (TE4[last_col >> 12] ^ RCONS[i]) << 12
            ^ TE4[last_col >> 8 & 0xF] << 8
            ^ TE4[last_col >> 4 & 0xF] << 4
            ^ TE4[last_col & 0xF]
        ) ^ key[0];

        key[0] = output[0];
        key[1] = output[1];
        key[2] = output[2];
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " [start] [end]" << std::endl;
        std::cerr << "start and end are 16-bit values indicating the range of partial subkeys to test" << std::endl;
        return 2;
    }

    uint32_t start = std::stoull(argv[1]);
    uint32_t end = std::stoull(argv[2]);

    // 1. Create a vector of partial subkeys from start to end.
    std::vector<uint16_t> p_k6s;
    for (uint32_t p_k6 = start; p_k6 <= end; ++p_k6) p_k6s.push_back(p_k6);

    // 2. Read in plaintext-ciphertext pairs.
    int i = 0;
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

        // 3. For each plaintext-ciphertext pair, iterate through the vector of partial subkeys.
        // Decrypt the ciphertexts and check if they have the following differences:
        // 010
        // 010
        // 000
        for (auto it = p_k6s.begin(); it != p_k6s.end(); ++it) {
            // construct full key from partial subkey
            // (value of fixed nibbles do not matter)
            uint16_t p_k6 = *it;
            uint16_t k6[3];
            k6[0] = p_k6 >> 12;
            k6[1] = p_k6 << 4 & 0xFF00;
            k6[2] = p_k6 << 4 & 0x00F0;

            uint16_t state0[3], state1[3];
            decrypt_r(ct0, state0, k6);
            decrypt_r(ct1, state1, k6);

            if (has_192(state0, state1)) {
                // 4. Go through all the possible equivalent partial subkeys for round 5.
                // Decrypt the ciphertexts with each partial subkey and check if they have the following differences:
                // 010
                // 010
                // 000
                // 010

                bool throw_away = true;
                for (uint16_t p_k5 = 0; p_k5 < 256; ++p_k5) {
                    uint16_t k5[3];
                    k5[1] = p_k5 << 8;

                    uint16_t state2[3], state3[3];
                    decrypt_r(state0, state2, k5);
                    decrypt_r(state1, state3, k5);

                    if (!has_208(state2, state3)) {
                        throw_away = false;
                        break;
                    }
                }

                // 5. The partial subkey has met the impossible differential.
                // Throw it away, by swapping with last element and popping from the back.
                if (throw_away) {
                    std::swap(*it, p_k6s.back());
                    p_k6s.pop_back();
                    --it; // prevent skipping of elements
                }
            }
        }

        ++i;
        std::cout << "Round " << i << ": " << p_k6s.size() << std::endl;
    }

    // 6. After filtering for partial subkeys of round 6,
    // construct subkeys for round 6 and derive the master key.
    // Brute force on a plaintext-ciphertext pair.
    for (uint64_t i = 0; i < 4294967296; ++i) {
        for (auto &p_k6 : p_k6s) {
            uint16_t k6[3];
            k6[0] = (i >> 36 & 0xFFF0) | (p_k6 >> 12);
            k6[1] = (p_k6 << 4 & 0xFF00) | (i >> 12 & 0x00FF);
            k6[2] = (i << 4 & 0xFF00) | (p_k6 << 4 & 0x00F0) | (i & 0x000F);

            uint16_t k0[3];
            derive_master(k6, k0);

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


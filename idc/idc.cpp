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

void derive_from_k5(const uint16_t *k5, uint16_t *output) {
    uint16_t prev_key[3];
    prev_key[0] = k5[0];
    prev_key[1] = k5[1];
    prev_key[2] = k5[2];

    for (int i = 4; i >= 0; --i) {
        output[2] = prev_key[1] ^ prev_key[2];
        output[1] = prev_key[0] ^ prev_key[1];

        uint16_t last_col = (output[2] << 4) ^ (output[2] >> 12);
        output[0] = (
            (TE4[last_col >> 12] ^ RCONS[i]) << 12
            ^ TE4[last_col >> 8 & 0xF] << 8
            ^ TE4[last_col >> 4 & 0xF] << 4
            ^ TE4[last_col & 0xF]
        ) ^ prev_key[0];

        prev_key[0] = output[0];
        prev_key[1] = output[1];
        prev_key[2] = output[2];
    }
}


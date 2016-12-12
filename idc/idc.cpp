#include "idc.h"

extern "C" {
#include "../some_cipher.h"
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

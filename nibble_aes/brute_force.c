#include <stdint.h>
#include <string.h>
#include "brute_force.h"
#include "nibble_aes.h"

int brute_force(const uint16_t *pt, const uint16_t *ct, uint16_t *key, const uint64_t start, const uint64_t end) {
    uint64_t i;
    uint16_t state[4] = {0};

    for (i = start; i < end; ++i) {
        convert_array(i, key);
        decrypt(ct, state, key);
        if (state[0] == pt[0] &&
            state[1] == pt[1] &&
            state[2] == pt[2] &&
            state[3] == pt[3]) {
            return 0;
        }
    }

    return 1;
}


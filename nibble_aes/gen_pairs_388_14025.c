/* Generates PT-CT pairs of distinguishers with (388, 14025):
 * START: 0000 0001 1000 0100
 * END: 0011 0110 1100 1001
 */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nibble_aes.h"

#define END_INACTIVE_MASK 0xFF00F00F00FF0FF0

typedef struct {
    uint64_t pt;
    uint64_t ct;
} pt_ct_t;

static int compare_inactive_nibbles(const void* a, const void* b) {
    pt_ct_t* ptcta = (pt_ct_t*) a;
    pt_ct_t* ptctb = (pt_ct_t*) b;

    // only compare inactive nibbles
    uint64_t inta = ptcta->ct & END_INACTIVE_MASK;
    uint64_t intb = ptctb->ct & END_INACTIVE_MASK;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diffs(const pt_ct_t a, const pt_ct_t b) {
    return (
        (a.pt >> 32 & 0xF) != (b.pt >> 32 & 0xF) &&
        (a.pt >> 28 & 0xF) != (b.pt >> 28 & 0xF) &&
        (a.pt >> 8 & 0xF) != (b.pt >> 8 & 0xF) &&

        (a.ct >> 52 & 0xF) != (b.ct >> 52 & 0xF) &&
        (a.ct >> 48 & 0xF) != (b.ct >> 48 & 0xF) &&
        (a.ct >> 40 & 0xF) != (b.ct >> 40 & 0xF) &&
        (a.ct >> 36 & 0xF) != (b.ct >> 36 & 0xF) &&
        (a.ct >> 28 & 0xF) != (b.ct >> 28 & 0xF) &&
        (a.ct >> 24 & 0xF) != (b.ct >> 24 & 0xF) &&
        (a.ct >> 12 & 0xF) != (b.ct >> 12 & 0xF) &&
        (a.ct & 0xF) != (b.ct & 0xF)
    );
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s [key] [number of PT-CT pairs]\n", argv[0]);
        return 1;
    }

    uint16_t key[4] = {0};
    convert_array(strtoull(argv[1], NULL, 10), key);
    const uint64_t num = strtoull(argv[2], NULL, 10);

    uint64_t i;
    int j0, j1, j2, k, l;
    uint64_t count = 0;

    pt_ct_t ptcts[4096] = {0};
    uint16_t pt[4], ct[4];

    for (i = 0; i < 0xFFFFFFFFFFFFFUL; ++i) {
        // fix passive nibbles
        pt[0] = i >> 36;
        pt[1] = i >> 24 & 0xFFF << 4;
        pt[2] = i >> 12 & 0xFFF;
        pt[3] = (i >> 8 & 0xF << 12) | (i & 0xFF);

        // generate list of all possible ciphertexts
        // by iterating through active nibbles
        for (j0 = 0; j0 < 16; ++j0) {
            pt[1] &= 0xFFF0;
            pt[1] |= j0;
            for (j1 = 0; j1 < 16; ++j1) {
                pt[2] &= 0x0FFF;
                pt[2] |= j1 << 12;
                for (j2 = 0; j2 < 16; ++j2) {
                    pt[3] &= 0xF0FF;
                    pt[3] |= j2 << 8;
                    encrypt(pt, ct, key);

                    pt_ct_t pt_ct = {0};
                    pt_ct.pt = convert_int(pt);
                    pt_ct.ct = convert_int(ct);
                    ptcts[j0 << 8 | j1 << 4 | j2] = pt_ct;
                }
            }
        }

        // sort list of all ciphertexts
        qsort(ptcts, 4096, sizeof(pt_ct_t), compare_inactive_nibbles);

        // go through list of ciphertexts in groups
        // and pair them up
        for (k = 0; k < 4096; ++k) {
            uint64_t inactive_nibs = ptcts[k].ct & END_INACTIVE_MASK;
            for (l = k + 1; l < 4096; ++l) {
                // reached end of group of CTs with same inactive nibbles
                if ((ptcts[l].ct & END_INACTIVE_MASK) != inactive_nibs) break;

                if (is_match_diffs(ptcts[k], ptcts[l])) {
                    printf(
                        "%lu %lu %lu %lu\n",
                        ptcts[k].pt,
                        ptcts[k].ct,
                        ptcts[l].pt,
                        ptcts[l].ct
                    );
                    ++count;
                }
            }
        }

        if (count >= num) return 0;
    }
}


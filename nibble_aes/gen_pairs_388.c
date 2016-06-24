#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "nibble_aes.h"

typedef struct {
    uint64_t pt;
    uint64_t ct;
} pt_ct_t;

typedef short (*match_diff_t)(const uint64_t a, const uint64_t b);


#define MASK_14025 0xff00f00f00ff0ff0
#define MASK_23130 0xf0f00f0ff0f00f0f
#define MASK_27795 0xf00f00ff0ff0ff00
#define MASK_37740 0xff0ff00f00f00ff
#define MASK_42405 0xf0ff0f00f0ff0f0
#define MASK_51510 0xff0ff0ff00f00f

static short is_match_diff_388(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF)
    );
}

static int cmp_passive_14025(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14025;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14025;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14025(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_23130(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23130;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23130;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23130(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27795(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27795;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27795;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27795(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_37740(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37740;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37740;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37740(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42405(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42405;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42405;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42405(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51510(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51510;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51510;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51510(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}


static void gen_pt_cts(pt_ct_t *ptcts, const uint16_t *key, const uint64_t i) {
    uint16_t pt[4], ct[4];
    pt[0] = i >> 36 & 0xFFFF;
    pt[1] = i >> 24 & 0xFFF << 4;
    pt[2] = i >> 12 & 0xFFF;
    pt[3] = (i >> 8 & 0xF << 12) | (i >> 0 & 0xFF);

    uint16_t i0, i1, i2;
    for (i0 = 0; i0 < 16; ++i0) {
    for (i1 = 0; i1 < 16; ++i1) {
    for (i2 = 0; i2 < 16; ++i2) {
    pt[1] &= 0xfff0;
    pt[1] |= i0;
    pt[2] &= 0xfff;
    pt[2] |= i1 << 12;
    pt[3] &= 0xf0ff;
    pt[3] |= i2 << 8;
    encrypt(pt, ct, key);

    pt_ct_t pt_ct = {};
    pt_ct.pt = convert_int(pt);
    pt_ct.ct = convert_int(ct);
    ptcts[i0 << 8 | i1 << 4 | i2 << 0] = pt_ct;
    }
    }
    }
}

static void print_pairs(pt_ct_t *ptcts, uint16_t end, uint64_t mask, match_diff_t f) {
    uint32_t k, l;
    uint64_t inactive_nibs;
    for (k = 0; k < 4096; ++k) {
        inactive_nibs = ptcts[k].ct & mask;
        l = k + 1;
        while ((ptcts[l].ct & mask) == inactive_nibs) {
            if (
                is_match_diff_388(ptcts[k].pt, ptcts[l].pt) &&
                f(ptcts[k].ct, ptcts[l].ct)
            ) {
                printf(
                    "%05d %016" PRIx64 " %016" PRIx64 " %016" PRIx64  " %016" PRIx64 "\n",
                    end,
                    ptcts[k].pt,
                    ptcts[k].ct,
                    ptcts[l].pt,
                    ptcts[l].ct
                );
            }
            ++l;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        printf("Usage: %s [key] [start] [end]\n", argv[0]);
        return 1;
    }

    uint16_t key[4] = {};
    convert_array(strtoull(argv[1], NULL, 10), key);
    uint64_t start = strtoull(argv[2], NULL, 10);
    uint64_t end = strtoull(argv[3], NULL, 10);

    uint64_t i;
    pt_ct_t ptcts[4096] = {};
    for (i = start; i < end; ++i) {
        gen_pt_cts(ptcts, key, i);
        
        qsort(ptcts, 4096, sizeof(pt_ct_t), cmp_passive_14025);
        print_pairs(ptcts, 14025, MASK_14025, is_match_diff_14025);
        qsort(ptcts, 4096, sizeof(pt_ct_t), cmp_passive_23130);
        print_pairs(ptcts, 23130, MASK_23130, is_match_diff_23130);
        qsort(ptcts, 4096, sizeof(pt_ct_t), cmp_passive_27795);
        print_pairs(ptcts, 27795, MASK_27795, is_match_diff_27795);
        qsort(ptcts, 4096, sizeof(pt_ct_t), cmp_passive_37740);
        print_pairs(ptcts, 37740, MASK_37740, is_match_diff_37740);
        qsort(ptcts, 4096, sizeof(pt_ct_t), cmp_passive_42405);
        print_pairs(ptcts, 42405, MASK_42405, is_match_diff_42405);
        qsort(ptcts, 4096, sizeof(pt_ct_t), cmp_passive_51510);
        print_pairs(ptcts, 51510, MASK_51510, is_match_diff_51510);
    }

    return 0;
}


#include <stdint.h>
#include <string.h>
#include "some_cipher.h"

const uint16_t RCONS[16] = {
    0x1, 0x2, 0x4, 0x8,
    0x3, 0x6, 0xC, 0xB,
    0x5, 0xA, 0x7, 0xE,
    0xF, 0xD, 0x9, 0x1
};

// TE0 = S[x] . [1, 1, 4, 9]
const uint16_t TE0[16] = {
    0xEED7, 0x4432, 0xDD1F, 0x1149,
    0x2281, 0xFF9E, 0xBBAC, 0x8864,
    0x33C8, 0xAAE5, 0x66B3, 0xCC56,
    0x557B, 0x992D, 0x0000, 0x77FA
};

// TE1 = S[x] . [1, 4, 9, 1]
const uint16_t TE1[16] = {
    0xED7E, 0x4324, 0xD1FD, 0x1491,
    0x2812, 0xF9EF, 0xBACB, 0x8648,
    0x3C83, 0xAE5A, 0x6B36, 0xC56C,
    0x57B5, 0x92D9, 0x0000, 0x7FA7
};

// TE2 = S[x] . [4, 9, 1, 1]
const uint16_t TE2[16] = {
    0xD7EE, 0x3244, 0x1FDD, 0x4911,
    0x8122, 0x9EFF, 0xACBB, 0x6488,
    0xC833, 0xE5AA, 0xB366, 0x56CC,
    0x7B55, 0x2D99, 0x0000, 0xFA77
};

// TE3 = S[x] . [9, 1, 1, 4]
const uint16_t TE3[16] = {
    0x7EED, 0x2443, 0xFDD1, 0x9114,
    0x1228, 0xEFF9, 0xCBBA, 0x4886,
    0x833C, 0x5AAE, 0x366B, 0x6CC5,
    0xB557, 0xD992, 0x0000, 0xA77F
};

// TE4 = S[x]
const uint16_t TE4[16] = {
    0xE, 0x4, 0xD, 0x1,
    0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC,
    0x5, 0x9, 0x0, 0x7
};

// TD0 = Si[x] . [8, 12, 7, 7]
const uint16_t TD0[16] = {
    0x94CC, 0xB799, 0x65FF, 0xCADD,
    0x8C77, 0xAF22, 0xF133, 0x18BB,
    0xD266, 0x2355, 0x46AA, 0x5E11,
    0x7D44, 0x3BEE, 0x0000, 0xE988
};

// TD1 = Si[x] . [12, 7, 7, 8]
const uint16_t TD1[16] = {
    0x4CC9, 0x799B, 0x5FF6, 0xADDC,
    0xC778, 0xF22A, 0x133F, 0x8BB1,
    0x266D, 0x3552, 0x6AA4, 0xE115,
    0xD447, 0xBEE3, 0x0000, 0x988E
};

// TD2 = Si[x] . [7, 7, 8, 12]
const uint16_t TD2[16] = {
    0xCC94, 0x99B7, 0xFF65, 0xDDCA,
    0x778C, 0x22AF, 0x33F1, 0xBB18,
    0x66D2, 0x5523, 0xAA46, 0x115E,
    0x447D, 0xEE3B, 0x0000, 0x88E9
};

// TD3 = Si[x] . [7, 8, 12, 7]
const uint16_t TD3[16] = {
    0xC94C, 0x9B79, 0xF65F, 0xDCAD,
    0x78C7, 0x2AF2, 0x3F13, 0xB18B,
    0x6D26, 0x5235, 0xA46A, 0x15E1,
    0x47D4, 0xE3BE, 0x0000, 0x8E98
};

// TD4 = Si[x]
const uint16_t TD4[16] = {
    0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF,
    0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5
};

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


static uint16_t ks[ROUNDS+1][3] = {};
static void gen_keys(const uint16_t *k0) {
    ks[0][0] = k0[0];
    ks[0][1] = k0[1];
    ks[0][2] = k0[2];

    for (int i = 1; i <= ROUNDS; ++i) {
        uint16_t last_col = (ks[i-1][2] << 4) ^ (ks[i-1][2] >> 12);
        ks[i][0] = (
            (TE4[last_col >> 12] ^ RCONS[i-1]) << 12
            ^ TE4[last_col >> 8 & 0xF] << 8
            ^ TE4[last_col >> 4 & 0xF] << 4
            ^ TE4[last_col & 0xF]
        ) ^ ks[i-1][0];
        ks[i][1] = ks[i][0] ^ ks[i-1][1];
        ks[i][2] = ks[i][1] ^ ks[i-1][2];
    }
}

void encrypt(const uint16_t *input, uint16_t *output, const uint16_t *key) {
    gen_keys(key);

    output[0] = input[0] ^ ks[0][0];
    output[1] = input[1] ^ ks[0][1];
    output[2] = input[2] ^ ks[0][2];

    uint16_t s0, s1, s2;
    uint8_t i;
    for (i = 1; i < ROUNDS; ++i) {
        s0 = output[0];
        s1 = output[1];
        s2 = output[2];
        output[0] = TE0[s0 >> 12]
            ^ TE1[s0 >> 8 & 0xF]
            ^ TE2[s2 >> 4 & 0xF]
            ^ TE3[s1 & 0xF]
            ^ ks[i][0];
        output[1] = TE0[s1 >> 12]
            ^ TE1[s1 >> 8 & 0xF]
            ^ TE2[s0 >> 4 & 0xF]
            ^ TE3[s2 & 0xF]
            ^ ks[i][1];
        output[2] = TE0[s2 >> 12]
            ^ TE1[s2 >> 8 & 0xF]
            ^ TE2[s1 >> 4 & 0xF]
            ^ TE3[s0 & 0xF]
            ^ ks[i][2];
    }

    s0 = output[0];
    s1 = output[1];
    s2 = output[2];
    output[0] = (TE0[s0 >> 12] & 0xF000)
        ^ (TE3[s0 >> 8 & 0xF] & 0x0F00)
        ^ (TE2[s2 >> 4 & 0xF] & 0x00F0)
        ^ (TE1[s1 & 0xF] & 0x000F)
        ^ ks[ROUNDS][0];
    output[1] = (TE0[s1 >> 12] & 0xF000)
        ^ (TE3[s1 >> 8 & 0xF] & 0x0F00)
        ^ (TE2[s0 >> 4 & 0xF] & 0x00F0)
        ^ (TE1[s2 & 0xF] & 0x000F)
        ^ ks[ROUNDS][1];
    output[2] = (TE0[s2 >> 12] & 0xF000)
        ^ (TE3[s2 >> 8 & 0xF] & 0x0F00)
        ^ (TE2[s1 >> 4 & 0xF] & 0x00F0)
        ^ (TE1[s0 & 0xF] & 0x000F)
        ^ ks[ROUNDS][2];
}

void decrypt(const uint16_t* input, uint16_t *output, const uint16_t* key) {
    gen_keys(key);

    output[0] = input[0] ^ ks[ROUNDS][0];
    output[1] = input[1] ^ ks[ROUNDS][1];
    output[2] = input[2] ^ ks[ROUNDS][2];

    uint16_t s0, s1, s2;
    uint16_t k0, k1, k2;
    uint8_t i;
    for (i = ROUNDS - 1; i > 0; --i) {
        k0 = TD0[TE1[ks[i][0] >> 12] & 0xF]
            ^ TD1[TE1[ks[i][0] >> 8 & 0xF] & 0xF]
            ^ TD2[TE1[ks[i][0] >> 4 & 0xF] & 0xF]
            ^ TD3[TE1[ks[i][0] & 0xF] & 0xF];
        k1 = TD0[TE1[ks[i][1] >> 12] & 0xF]
            ^ TD1[TE1[ks[i][1] >> 8 & 0xF] & 0xF]
            ^ TD2[TE1[ks[i][1] >> 4 & 0xF] & 0xF]
            ^ TD3[TE1[ks[i][1] & 0xF] & 0xF];
        k2 = TD0[TE1[ks[i][2] >> 12] & 0xF]
            ^ TD1[TE1[ks[i][2] >> 8 & 0xF] & 0xF]
            ^ TD2[TE1[ks[i][2] >> 4 & 0xF] & 0xF]
            ^ TD3[TE1[ks[i][2] & 0xF] & 0xF];

        s0 = output[0];
        s1 = output[1];
        s2 = output[2];
        output[0] = TD0[s0 >> 12]
            ^ TD1[s0 >> 8 & 0xF]
            ^ TD2[s1 >> 4 & 0xF]
            ^ TD3[s2 & 0xF]
            ^ k0;
        output[1] = TD0[s1 >> 12]
            ^ TD1[s1 >> 8 & 0xF]
            ^ TD2[s2 >> 4 & 0xF]
            ^ TD3[s0 & 0xF]
            ^ k1;
        output[2] = TD0[s2 >> 12]
            ^ TD1[s2 >> 8 & 0xF]
            ^ TD2[s0 >> 4 & 0xF]
            ^ TD3[s1 & 0xF]
            ^ k2;
    }

    // last round
    s0 = output[0];
    s1 = output[1];
    s2 = output[2];
    output[0] = TD4[s0 >> 12] << 12
        ^ TD4[s0 >> 8 & 0xF] << 8
        ^ TD4[s1 >> 4 & 0xF] << 4
        ^ TD4[s2 & 0xF]
        ^ ks[0][0];
    output[1] = TD4[s1 >> 12] << 12
        ^ TD4[s1 >> 8 & 0xF] << 8
        ^ TD4[s2 >> 4 & 0xF] << 4
        ^ TD4[s0 & 0xF]
        ^ ks[0][1];
    output[2] = TD4[s2 >> 12] << 12
        ^ TD4[s2 >> 8 & 0xF] << 8
        ^ TD4[s0 >> 4 & 0xF] << 4
        ^ TD4[s1 & 0xF]
        ^ ks[0][2];
}

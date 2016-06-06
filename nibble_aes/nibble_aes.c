#include <stdint.h>
#include "nibble_aes.h"

static const uint8_t SBOX[16] = {
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
};

static const uint8_t INV_SBOX[16] = {
    0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF,
    0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5
};

static const uint8_t M1[16] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};

static const uint8_t M4[16] = {
    0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF,
    0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9
};

static const uint8_t M7[16] = {
    0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6,
    0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB
};

static const uint8_t M8[16] = {
    0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD,
    0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1
};

static const uint8_t M9[16] = {
    0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA,
    0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE
};

static const uint8_t M12[16] = {
    0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2,
    0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8
};

/* Private variables and functions. */

typedef uint8_t state_t[16];
static state_t* state;
static const uint8_t* master_key;

static void nibble_sub() {
    uint8_t i;
    for (i = 0; i < 16; ++i) (*state)[i] = SBOX[(*state)[i]];
}

static void inv_nibble_sub() {
    uint8_t i;
    for (i = 0; i < 16; ++i) (*state)[i] = INV_SBOX[(*state)[i]];
}

static void shift_row() {
    uint8_t tmp;

    // second row
    tmp = (*state)[1];
    (*state)[1] = (*state)[5];
    (*state)[5] = (*state)[9];
    (*state)[9] = (*state)[13];
    (*state)[13] = tmp;
    // third row
    tmp = (*state)[2];
    (*state)[2] = (*state)[10];
    (*state)[10] = tmp;

    tmp = (*state)[6];
    (*state)[6] = (*state)[14];
    (*state)[14] = tmp;
    // fourth row
    tmp = (*state)[15];
    (*state)[15] = (*state)[11];
    (*state)[11] = (*state)[7];
    (*state)[7] = (*state)[3];
    (*state)[3] = tmp;
}

static void inv_shift_row() {
    uint8_t tmp;

    // second row
    tmp = (*state)[13];
    (*state)[13] = (*state)[9];
    (*state)[9] = (*state)[5];
    (*state)[5] = (*state)[1];
    (*state)[1] = tmp;
    // third row
    tmp = (*state)[2];
    (*state)[2] = (*state)[10];
    (*state)[10] = tmp;

    tmp = (*state)[6];
    (*state)[6] = (*state)[14];
    (*state)[14] = tmp;
    // fourth row
    tmp = (*state)[3];
    (*state)[3] = (*state)[7];
    (*state)[7] = (*state)[11];
    (*state)[11] = (*state)[15];
    (*state)[15] = tmp;
}

static void mix_column() {
    uint8_t i;
    uint8_t n0, n1, n2, n3;
    uint8_t tmp0, tmp1, tmp2, tmp3;
    for (i = 0; i < 4; ++i) {
        n0 = (*state)[4*i];
        n1 = (*state)[4*i+1];
        n2 = (*state)[4*i+2];
        n3 = (*state)[4*i+3];
        tmp0 = M1[n0] ^ M1[n1] ^ M4[n2] ^ M9[n3];
        tmp1 = M1[n0] ^ M4[n1] ^ M9[n2] ^ M1[n3];
        tmp2 = M4[n0] ^ M9[n1] ^ M1[n2] ^ M1[n3];
        tmp3 = M9[n0] ^ M1[n1] ^ M1[n2] ^ M4[n3];
        (*state)[4*i] = tmp0;
        (*state)[4*i+1] = tmp1;
        (*state)[4*i+2] = tmp2;
        (*state)[4*i+3] = tmp3;
    }
}

static void inv_mix_column() {
    uint8_t i;
    uint8_t n0, n1, n2, n3;
    uint8_t tmp0, tmp1, tmp2, tmp3;
    for (i = 0; i < 4; ++i) {
        n0 = (*state)[4*i];
        n1 = (*state)[4*i+1];
        n2 = (*state)[4*i+2];
        n3 = (*state)[4*i+3];
        tmp0 = M8[n0] ^ M12[n1] ^ M7[n2] ^ M7[n3];
        tmp1 = M12[n0] ^ M7[n1] ^ M7[n2] ^ M8[n3];
        tmp2 = M7[n0] ^ M7[n1] ^ M8[n2] ^ M12[n3];
        tmp3 = M7[n0] ^ M8[n1] ^ M12[n2] ^ M7[n3];
        (*state)[4*i] = tmp0;
        (*state)[4*i+1] = tmp1;
        (*state)[4*i+2] = tmp2;
        (*state)[4*i+3] = tmp3;
    }
}

static void key_addition() {
    uint8_t i;
    for (i = 0; i < 16; ++i) (*state)[i] = (*state)[i] ^ master_key[i];
}

static void run_round(uint8_t num) {
    nibble_sub();
    shift_row();
    if (num != ROUNDS - 1) mix_column();
    key_addition();
}

static void run_inv_round(uint8_t num) {
    key_addition();
    if (num != 0) inv_mix_column();
    inv_shift_row();
    inv_nibble_sub();
}

static void run_encrypt() {
    uint8_t num;
    key_addition();
    for (num = 0; num < ROUNDS; ++num) run_round(num);
}

static void run_decrypt() {
    uint8_t num;
    for (num = 0; num < ROUNDS; ++num) run_inv_round(num);
    key_addition();
}

/* Public functions. */

void encrypt_round(uint8_t* input, const uint8_t* key, uint8_t num) {
    state = (state_t*) input;
    master_key = key;
    run_round(num);
}

void decrypt_round(uint8_t* input, const uint8_t* key, uint8_t num) {
    state = (state_t*) input;
    master_key = key;
    run_inv_round(num);
}

void encrypt(uint8_t* input, const uint8_t* key) {
    state = (state_t*) input;
    master_key = key;
    run_encrypt();
}

void decrypt(uint8_t* input, const uint8_t* key) {
    state = (state_t*) input;
    master_key = key;
    run_decrypt();
}


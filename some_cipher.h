#ifndef SOME_CIPHER_H
#define SOME_CIPHER_H

#include <stdint.h>

#define ROUNDS 6

const uint16_t RCONS[16] = {
    0x1, 0x2, 0x4, 0x8,
    0x3, 0x6, 0xC, 0xB,
    0x5, 0xA, 0x7, 0xE,
    0xF, 0xD, 0x9, 0x1
};

typedef struct {
    uint16_t pt0[3];
    uint16_t pt1[3];
    uint16_t ct0[3];
    uint16_t ct1[3];
} pair_t;

void encrypt(const uint16_t *input, uint16_t *output, const uint16_t *key);
void decrypt(const uint16_t *input, uint16_t *output, const uint16_t *key);

#endif

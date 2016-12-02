#ifndef SOME_CIPHER_H
#define SOME_CIPHER_H

#include <stdint.h>

#define ROUNDS 6

typedef struct {
    uint16_t pt0[3];
    uint16_t pt1[3];
    uint16_t ct0[3];
    uint16_t ct1[3];
} pair_t;

void encrypt(const uint16_t *input, uint16_t *output, const uint16_t *key);
void decrypt(const uint16_t *input, uint16_t *output, const uint16_t *key);

#endif

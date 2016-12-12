#ifndef SOME_CIPHER_H
#define SOME_CIPHER_H

#include <stdint.h>

#define ROUNDS 6

extern const uint16_t RCONS[];
extern const uint16_t TE0[16], TE1[16], TE2[16], TE3[16], TE4[16];
extern const uint16_t TD0[16], TD1[16], TD2[16], TD3[16], TD4[16];
extern const uint16_t MC_INV_0[16], MC_INV_1[16], MC_INV_2[16], MC_INV_3[16];

void encrypt(const uint16_t *input, uint16_t *output, const uint16_t *key);
void decrypt(const uint16_t *input, uint16_t *output, const uint16_t *key);

#endif

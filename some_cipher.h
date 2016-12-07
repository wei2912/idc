#ifndef SOME_CIPHER_H
#define SOME_CIPHER_H

#include <stdint.h>

#define ROUNDS 6

extern const uint16_t RCONS[];

void encrypt(const uint16_t *input, uint16_t *output, const uint16_t *key);
void decrypt(const uint16_t *input, uint16_t *output, const uint16_t *key);

#endif

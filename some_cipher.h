#ifndef SOME_CIPHER_H
#define SOME_CIPHER_H

#include <stdint.h>

#define ROUNDS 6

const uint16_t RCONS[16] = {
	0x8d, 0x01, 0x02, 0x04, 
	0x08, 0x10, 0x20, 0x40, 
	0x80, 0x1b, 0x36, 0x6c, 
	0xd8, 0xab, 0x4d, 0x9a
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

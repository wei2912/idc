#ifndef NIBBLE_AES_H
#define NIBBLE_AES_H

#include <stdint.h>

#define ROUNDS 6

typedef struct {
    uint16_t pt0[4];
    uint16_t pt1[4];
    uint16_t ct0[4];
    uint16_t ct1[4];
} pair_t;

void encrypt(const uint16_t *input, uint16_t *output, const uint16_t *key);
void decrypt(const uint16_t *input, uint16_t *output, const uint16_t *key);
uint64_t convert_int(const uint16_t *input);
void convert_array(const uint64_t input, uint16_t *output);
uint16_t diffs(const uint64_t a, const uint64_t b);

#endif

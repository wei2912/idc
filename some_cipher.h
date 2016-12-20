#ifndef SOME_CIPHER_H
#define SOME_CIPHER_H

#include <stdint.h>

#define ROUNDS 6

extern const uint16_t RCONS[];
extern const uint16_t TE0[16], TE1[16], TE2[16], TE3[16], TE4[16];
extern const uint16_t TD0[16], TD1[16], TD2[16], TD3[16], TD4[16];

uint16_t mc_inv(const uint16_t input);
void next_key(const uint16_t *prev_k, uint16_t *cur_k, const int i);
void prev_key(const uint16_t *cur_k, uint16_t *prev_k, const int i);

void decrypt(const uint16_t *input, uint16_t *output, const uint16_t *k0);
void decrypt_r(const uint16_t *input, uint16_t *output);
void decrypt_last_r(const uint16_t *input, uint16_t *output);

void encrypt(const uint16_t *input, uint16_t *output, const uint16_t *k0);
void encrypt_r(const uint16_t *input, uint16_t *output);
void encrypt_last_r(const uint16_t *input, uint16_t *output);


#endif

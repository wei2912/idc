#ifndef SOME_CIPHER_H
#define SOME_CIPHER_H

#include <stdint.h>

#define ROUNDS 6

extern const uint16_t RCONS[];
extern const uint16_t TE0[16], TE1[16], TE2[16], TE3[16], TE4[16];
extern const uint16_t TD0[16], TD1[16], TD2[16], TD3[16], TD4[16];

uint16_t mc_inv(const uint16_t input);
void add_key(const uint16_t input[3], uint16_t output[3], const uint16_t ki[3]);
void next_key(const uint16_t prev_k[3], uint16_t cur_k[3], const int i);
void prev_key(const uint16_t cur_k[3], uint16_t prev_k[3], const int i);

void decrypt(const uint16_t input[3], uint16_t output[3], const uint16_t k0[3]);
void decrypt_with_keys(const uint16_t input[3], uint16_t output[3], const uint16_t ks[3][3]);
void decrypt_r(const uint16_t input[3], uint16_t output[3]);
void decrypt_last_r(const uint16_t input[3], uint16_t output[3]);

void encrypt(const uint16_t input[3], uint16_t output[3], const uint16_t k0[3]);
void encrypt_with_keys(const uint16_t input[3], uint16_t output[3], const uint16_t ks[3][3]);
void encrypt_r(const uint16_t input[3], uint16_t output[3]);
void encrypt_last_r(const uint16_t input[3], uint16_t output[3]);


#endif

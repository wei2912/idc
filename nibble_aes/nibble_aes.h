#ifndef NIBBLE_AES_H
#define NIBBLE_AES_H

#include <stdint.h>

#define ROUNDS 6

void encrypt_round(uint8_t* input, const uint8_t* key, const uint8_t num);
void decrypt_round(uint8_t* input, const uint8_t* key, const uint8_t num);

void encrypt(uint8_t* input, const uint8_t* key);
void decrypt(uint8_t* input, const uint8_t* key);

#endif

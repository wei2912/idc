#ifndef NIBBLE_AES_H
#define NIBBLE_AES_H

#include <stdint.h>

#define ROUNDS 6

void encrypt(uint16_t* input, const uint16_t* key);
void decrypt(uint16_t* input, const uint16_t* key);

#endif

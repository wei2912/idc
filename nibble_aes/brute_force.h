#ifndef BRUTE_FORCE_H
#define BRUTE_FORCE_H

#include <stdint.h>
#include "nibble_aes.h"

int brute_force(const uint16_t* pt, const uint16_t* ct, uint16_t* key, const uint64_t start, const uint64_t end);

#endif

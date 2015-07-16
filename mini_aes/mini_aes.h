#include <inttypes.h>

uint16_t nibble_sub(uint16_t x);
uint16_t inv_nibble_sub(uint16_t x);

uint16_t shift_row(uint16_t x);
uint16_t inv_shift_row(uint16_t x);

uint16_t mix_column(uint16_t x);
uint16_t inv_mix_column(uint16_t x);

uint16_t key_addition(uint16_t key, uint16_t x);
uint16_t inv_key_addition(uint16_t key, uint16_t x);


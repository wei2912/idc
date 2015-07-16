#include <inttypes.h>
#include <stdio.h>
#include "mini_aes.h"

const uint16_t SBOX[16] = {
    0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08,
    0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07
};

const uint16_t INV_SBOX[16] = {
    0x0E, 0x03, 0x04, 0x08, 0x01, 0x0C, 0x0A, 0x0F,
    0x07, 0x0D, 0x09, 0x06, 0x0B, 0x02, 0x00, 0x05
};

uint16_t nibble_sub(const uint16_t x) {
    return (SBOX[x >> 12] << 12
        | SBOX[x >> 8 & 0x0F] << 8
        | SBOX[x >> 4 & 0x0F] << 4
        | SBOX[x & 0x0F]);
}

uint16_t inv_nibble_sub(const uint16_t x) {
    return (INV_SBOX[x >> 12] << 12
        | INV_SBOX[x >> 8 & 0x0F] << 8
        | INV_SBOX[x >> 4 & 0x0F] << 4
        | INV_SBOX[x & 0x0F]);
}

uint16_t shift_row(const uint16_t x) {
    return ((x & 0xF0F0)
        | (x & 0x0F) << 8
        | (x >> 8 & 0x0F));
}

uint16_t inv_shift_row(const uint16_t x) {
    return shift_row(x);
}

int main(int argc, char *argv[]) {
    uint16_t x = 0;

    scanf("%hx", &x); 
    printf("%x\n", nibble_sub(x));

    scanf("%hx", &x);
    printf("%x\n", shift_row(x));
}


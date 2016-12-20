#include <cstdio>
#include <cstdlib>
#include <iostream>

extern "C" {
#include "../some_cipher.h"
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " [start] [end]" << std::endl;
        std::cerr << "start and end are 64-bit values that represent the range of keys to be brute forced, inclusive of start and end" << std::endl;
        return 2;
    }

    uint64_t start = std::stoull(argv[1]);
    uint64_t end = std::stoull(argv[2]);

    // 1. Take in a plaintext and ciphertext as a hexadecimal string.
    uint64_t pt_hex, ct_hex;
    std::cin >> std::hex >> pt_hex >> ct_hex;

    uint16_t pt[3], ct[3];

    pt[0] = pt_hex >> 32;
    pt[1] = pt_hex >> 16 & 0xFFFF;
    pt[2] = pt_hex & 0xFFFF;

    ct[0] = ct_hex >> 32;
    ct[1] = ct_hex >> 16 & 0xFFFF;
    ct[2] = ct_hex & 0xFFFF;

    // 2. Begin brute forcing on the key.
    uint16_t guess_key[3];
    uint16_t output[3] = {};

    for (uint64_t i = start; i <= end; ++i) {
        guess_key[0] = i >> 32;
        guess_key[1] = i >> 16 & 0xFFFF;
        guess_key[2] = i & 0xFFFF;
        decrypt(ct, output, guess_key);
        if (output[0] == pt[0] &&
            output[1] == pt[1] &&
            output[2] == pt[2]) {
            std::printf("%04x%04x%04x\n", guess_key[0], guess_key[1], guess_key[2]);
            return 0;
        }
    }

    return 1;
}


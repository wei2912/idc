#include <iostream>
#include <string>

extern "C" {
#include "some_cipher.h"
}

bool brute_force(const uint16_t *pt, const uint16_t *ct, const uint64_t start, const uint64_t end, uint16_t *guess_key) {
    uint64_t i;
    uint16_t output[3] = {};

    for (i = start; i < end; ++i) {
        guess_key[0] = i >> 32;
        guess_key[1] = i >> 16 & 0xFFFF;
        guess_key[2] = i & 0xFFFF;
        decrypt(ct, output, guess_key);
        if (output[0] == pt[0] &&
            output[1] == pt[1] &&
            output[2] == pt[2]) {
            return true;
        }
    }

    return false;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " [start] [end]" << std::endl;
        return 2;
    }

    uint64_t start = std::stoull(argv[1]);
    uint64_t end = std::stoull(argv[2]);

    // 1. Take in a plaintext as a hexadecimal string.
    uint16_t pt[3];
    uint64_t pt_hex;
    std::cin >> std::hex >> pt_hex;
    pt[0] = pt_hex >> 32;
    pt[1] = pt_hex >> 16 & 0xFFFF;
    pt[2] = pt_hex & 0xFFFF;

    // 2. Take in a ciphertext as a hexadecimal string.
    uint16_t ct[3];
    uint64_t ct_hex;
    std::cin >> std::hex >> ct_hex;
    ct[0] = ct_hex >> 32;
    ct[1] = ct_hex >> 16 & 0xFFFF;
    ct[2] = ct_hex & 0xFFFF;

    uint16_t guess_key[3];
    if (brute_force(pt, ct, start, end, guess_key)) {
        std::printf("%04x%04x%04x\n", guess_key[0], guess_key[1], guess_key[2]);
    }
}


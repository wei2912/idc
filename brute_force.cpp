#include <iostream>
#include <string>

extern "C" {
#include "some_cipher.h"
}

static int convert_int(const uint64_t input, uint16_t *output) {
    output[0] = input >> 32;
    output[1] = input >> 16 & 0xFFFF;
    output[2] = input & 0xFFFF;
    return 0;
}

int brute_force(const uint16_t *pt, const uint16_t *ct, const uint64_t start, const uint64_t end, uint16_t *guess_key) {
    uint64_t i;
    uint16_t output[3] = {};

    for (i = start; i < end; ++i) {
        convert_int(i, guess_key);
        decrypt(ct, output, guess_key);
        if (output[0] == pt[0] &&
            output[1] == pt[1] &&
            output[2] == pt[2]) {
            return 0;
        }
    }

    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " [start] [end]" << std::endl;
        return 2;
    }

    uint64_t start = std::stoull(argv[1]);
    uint64_t end = std::stoull(argv[2]);

    uint64_t pt_num;
    uint64_t key_num;
    std::cin >> std::hex >> pt_num;
    std::cin >> std::hex >> key_num;

    uint16_t pt[3];
    uint16_t key[3];
    convert_int(pt_num, pt);
    convert_int(key_num, key);

    uint16_t ct[3];
    encrypt(pt, ct, key);

    uint16_t guess_key[3];
    if (brute_force(pt, ct, start, end, guess_key) == 0) {
        if (guess_key[0] == key[0] &&
            guess_key[1] == key[1] &&
            guess_key[2] == key[2]) {
            std::cout << "Correct key found." << std::endl;
            return 0;
        } else {
            std::cout << "ERROR: Brute forced key does not match up with actual key!" << std::endl;
            return 2;
        }
    } else {
        std::cout << "Unable to find correct key." << std::endl;
        return 1;
    }
}


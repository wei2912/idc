#include <cstring>
#include <iostream>
#include <random>

extern "C" {
#include "brute_force.h"
#include "nibble_aes.h"
}

int main() {
    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 65535);

    for (int i = 0; i < 10000; ++i) {
        uint16_t key[4], pt[4], ct[4];
        for (int i = 0; i < 4; ++i) key[i] = d(g);
        for (int i = 0; i < 4; ++i) pt[i] = d(g);
        encrypt(pt, ct, key);

        uint64_t start = ((uint64_t) key[0]) << 48 | ((uint64_t) key[1]) << 32 | ((uint64_t) key[2]) << 16;
        uint64_t end = start | 0xFFFF;

        uint16_t found_key[4] = {0};
        int code = brute_force(pt, ct, found_key, start, end);
        if (code == 1) {
            std::cout << "ERROR: Brute force could not find key." << std::endl;
        }

        for (int i = 0; i < 4; ++i) {
            if (key[i] != found_key[i]) {
                std::cout << "ERROR: Brute forced key does not match actual key." << std::endl;
                return 1;
            }
        }
    }

    return 0;
}

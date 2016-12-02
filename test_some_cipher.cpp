#include <cstdio>
#include <iostream>
#include <random>

extern "C" {
#include "some_cipher.h"
}

int main() {
    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 65535);

    for (int i = 0; i < 16777216; ++i) {
        uint16_t key[3];
        uint16_t pt[3];
        for (int i = 0; i < 3; ++i) key[i] = d(g);
        for (int i = 0; i < 3; ++i) pt[i] = d(g);

        uint16_t ct[3], n_pt[3];
        encrypt(pt, ct, key);
        decrypt(ct, n_pt, key);

        for (int i = 0; i < 3; ++i) {
            if (pt[i] != n_pt[i]) {
                std::cout << "ERROR: Decrypted ciphertext does not match the plaintext." << std::endl;
                return 1;
            }
        }
    }

    return 0;
}

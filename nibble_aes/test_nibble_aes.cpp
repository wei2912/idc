#include <iostream>
#include <random>

extern "C" {
#include "nibble_aes.h"
}

int main() {
    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 65535);

    for (int i = 0; i < 100000000; ++i) {
        uint16_t key[4];
        uint16_t pt[4];
        for (int i = 0; i < 4; ++i) key[i] = d(g);
        for (int i = 0; i < 4; ++i) pt[i] = d(g);

        uint16_t ct[4], n_pt[4];
        encrypt(pt, ct, key);
        decrypt(ct, n_pt, key);

        for (int i = 0; i < 4; ++i) {
            if (pt[i] != n_pt[i]) {
                std::cout << "ERROR: Decrypted ciphertext does not match the plaintext." << std::endl;
                return 1;
            }
        }
    }

    return 0;
}

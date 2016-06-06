#include <iostream>
#include <random>

extern "C" {
#include "nibble_aes.h"
}

int main() {
    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 15);

    for (int i = 0; i < 10000000; ++i) {
        uint8_t ks[16];
        uint8_t ps[16];
        for (int i = 0; i < 16; ++i) ks[i] = d(g);
        for (int i = 0; i < 16; ++i) ps[i] = d(g);

        uint8_t cs[16];
        for (int i = 0; i < 16; ++i) cs[i] = ps[i];
        encrypt(cs, ks);
        decrypt(cs, ks);

        for (int i = 0; i < 16; ++i) {
            if (ps[i] != cs[i]) {
                std::cout << "ERROR: Decrypted ciphertext does not match the plaintext." << std::endl;
                return 1;
            }
        }
    }

    return 0;
}

#include <iostream>
#include <random>

#include "nibble_aes.h"

int main() {
    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 15);

    for (int i = 0; i < 1000000; ++i) {
        nibs ks, ps;
        for (int i = 0; i < 16; ++i) ks[i] = d(g);
        for (int i = 0; i < 16; ++i) ps[i] = d(g);

        nibs cs = encrypt_block(ks, ps);
        nibs ds = decrypt_block(ks, cs);

        if (ps != ds) {
            std::cout << "ERROR: Decrypted ciphertext does not match the plaintext." << std::endl;
            return 1;
        }
    }

    return 0;
}

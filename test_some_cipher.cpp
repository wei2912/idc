#include <cstdio>
#include <cstring>
#include <iostream>
#include <random>

extern "C" {
#include "some_cipher.h"
}

#define N 16777216

int main(int argc, char *argv[]) {
    enum State{TST, ENC, DEC};
    State s = TST;
    if (argc == 1) std::cout << "Testing " << N << " trials for reversibility of cipher." << std::endl;
    else if (argc == 2) {
        if (std::strcmp(argv[1], "encrypt") == 0) {
            std::cout << "Encrypting " << N << " plaintexts." << std::endl;
            s = ENC;
        } else if (std::strcmp(argv[1], "decrypt") == 0) {
            std::cout << "Decrypting " << N << " ciphertexts." << std::endl;
            s = DEC;
        }
    }

    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 65535);
    for (int i = 0; i < N; ++i) {
        uint16_t key[3];
        uint16_t pt[3];
        for (int j = 0; j < 3; ++j) key[j] = d(g);
        for (int j = 0; j < 3; ++j) pt[j] = d(g);

        uint16_t ct[3], n_pt[3];
        if (s == TST) {
            encrypt(pt, ct, key);
            decrypt(ct, n_pt, key);

            for (int j = 0; j < 3; ++j) {
                if (pt[j] != n_pt[j]) {
                    std::cout << "ERROR: Decrypted ciphertext does not match the plaintext." << std::endl;
                    return 1;
                }
            }
        }
        else if (s == ENC) encrypt(pt, ct, key);
        else if (s == DEC) decrypt(pt, ct, key);
    }

    return 0;
}

#include <iostream>
#include <random>

#include "some_cipher.h"

int main() {
    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 15);

    nibs ks, cs;
    int x;
    for (int i = 0; i < 12; ++i) {
        std::cin >> x;
        ks[i] = x;
    }
    for (int i = 0; i < 12; ++i) {
        std::cin >> x;
        cs[i] = x;
    }
    nibs ps = decrypt_block(ks, cs);
    for (auto &p : ps) std::cout << +p << " ";
    std::cout << std::endl;

/*
    for (int i = 0; i < 1000000; ++i) {
        nibs ks, ps;
        for (int i = 0; i < 12; ++i) ks[i] = d(g);
        for (int i = 0; i < 12; ++i) ps[i] = d(g);

        std::cout << "Key: ";
        for (auto &k : ks) std::cout << +k << " ";
        std::cout << std::endl;

        std::cout << "Plaintext: ";
        for (auto &p : ps) std::cout << +p << " ";
        std::cout << std::endl;

        nibs cs = encrypt_block(ks, ps);
        std::cout << "Ciphertext: ";
        for (auto &c : cs) std::cout << +c << " ";
        std::cout << std::endl;

        nibs ds = decrypt_block(ks, cs);
        std::cout << "Decrypted ciphertext: ";
        for (auto &d : ds) std::cout << +d << " ";
        std::cout << std::endl;

        if (ps != ds) {
            std::cout << "ERROR: Decrypted ciphertext does not match the plaintext." << std::endl;
            return 1;
        }
    }
*/

    return 0;
}

#include <iostream>
#include <random>

#include "some_cipher.h"

int main() {
    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 15);

    nibs ks, ps;
    for (int i = 0; i < 12; ++i) ks[i] = d(g);
    for (int i = 0; i < 12; ++i) ps[i] = d(g);

    std::cout << "Key: ";
    for (int i = 0; i < 12; ++i) std::cout << +ks[i] << " ";
    std::cout << std::endl;

    std::cout << "Plaintext: ";
    for (int i = 0; i < 12; ++i) std::cout << +ps[i] << " ";
    std::cout << std::endl;

    nibs cs = encrypt_block(ks, ps);
    std::cout << "Ciphertext: ";
    for (int i = 0; i < 12; ++i) std::cout << +cs[i] << " ";
    std::cout << std::endl;

    nibs ds = decrypt_block(ks, cs);
    std::cout << "Decrypted ciphertext: ";
    for (int i = 0; i < 12; ++i) std::cout << +ds[i] << " ";
    std::cout << std::endl;

    if (ps == ds) std::cout << "Decrypted ciphertext is the plaintext." << std::endl;
    else std::cout << "ERROR: Decrypted ciphertext does not match the plaintext." << std::endl;

    return 0;
}

#include <cstdint>
#include <fstream>
#include <iostream>
#include <random>

#include "some_cipher.h"

int main() {
    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 15);

    // generate key and plaintext
    nibs ks;
    for (int i = 0; i < 12; ++i) ks[i] = d(g);
    nibs ps;
    for (int i = 0; i < 12; ++i) ps[i] = d(g);
    // encrypt plaintext to get ciphertext
    nibs cs = encrypt_block(ks, ps);

    std::ofstream outfile("bf.txt");

    // print out key on first line
    for (auto &k : ks) outfile << +k << " ";
    outfile << std::endl;

    // print out plaintext-ciphertext pair
    for (auto &p : ps) outfile << +p << " ";
    for (auto &c : cs) outfile << +c << " ";
    outfile << std::endl;

    // construct integer representing key during key guessing
    long key_int = ks[0] << 24 | ks[1] << 20 | ks[2] << 16 | ks[3] << 12 | ks[4] << 8 | ks[5] << 4 | ks[6];
    std::cout << "Integer representing key: " << key_int << std::endl;

    return 0;
}

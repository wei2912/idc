#include <fstream>
#include <functional>
#include <iostream>
#include <random>
#include <sstream>

#include "some_cipher.h"

/* Generate plaintext pairs by iterating through list of plaintexts. Check that
 * differences in plaintext and ciphertext correspond. */
void print_data(const nibs ks, const int num_pairs) {
    std::stringstream ss;
    ss << "pairs1_" << num_pairs << ".txt";
    std::ofstream outfile(ss.str());

    // print out key on first line
    for (auto &k : ks) outfile << +k << " ";
    outfile << std::endl;

    int iters = 0;
    int pairs = 0;
    nibs ps0{0}, ps1{0};
    nibs cs0{0}, cs1{0};

    /* distinguisher used:
     * 45 ... X ... 237 <- 237 <- 127 <- 862 with probability 7.033563070652695e-06, 6 rounds
     */

    // passive key nibbles: 0, 1, 2, 3, 4, 5, 7, 10
    // active key nibbles: 6, 8, 9, 11
    pairs = 0;
    for (unsigned long x = 0; x < 4294967296 && pairs < num_pairs; ++x) {
        ps0[0] = x >> 28 & 0xF;
        ps0[1] = x >> 24 & 0xF;
        ps0[2] = x >> 20 & 0xF;
        ps0[3] = x >> 16 & 0xF;
        ps0[4] = x >> 12 & 0xF;
        ps0[5] = x >> 8 & 0xF;
        ps0[7] = x >> 4 & 0xF;
        ps0[10] = x & 0xF;

        ps1 = ps0;

        for (long y = 0; y < 65536 && pairs < num_pairs; ++y) {
            ps0[6] = y >> 12 & 0xF;
            ps0[8] = y >> 8 & 0xF;
            ps0[9] = y >> 4 & 0xF;
            ps0[11] = y & 0xF;
            cs0 = encrypt_block(ks, ps0);

            for (long z = y + 1; z < 65536 && pairs < num_pairs; ++z) {
                ps1[6] = z >> 12 & 0xF;
                ps1[8] = z >> 8 & 0xF;
                ps1[9] = z >> 4 & 0xF;
                ps1[11] = z & 0xF;
                cs1 = encrypt_block(ks, ps1);

                ++iters;

                if (differences(ps0, ps1) != diffs {0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1}) continue;
                if (differences(cs0, cs1) != diffs {0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0}) continue;

                ++pairs;

                for (auto &p : ps0) outfile << +p << " ";
                for (auto &p : ps1) outfile << +p << " ";
                for (auto &c : cs0) outfile << +c << " ";
                for (auto &c : cs1) outfile << +c << " ";
                outfile << std::endl;
            }
        }
    }

    // construct integer representing key during key guessing
    long key_int = ks[3] << 24 | ks[10] << 20 | ks[2] << 16 | ks[5] << 12 | ks[5] << 12 | ks[7] << 8 | ks[8] << 4 | ks[9];
    std::cout << "Integer representing key: " << key_int << std::endl;
    std::cout << "Number of PT-CT pairs the program went through: " << iters << std::endl;
}

int main(const int argc, const char *argv[]) {
    if (argc != 2) {
        std::cerr << "Wrong number of arguments. Please pass in the number of filtered PT-CT pairs." << std::endl;
        return 1;
    }

    long num_pairs = std::atol(argv[1]);

    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 15);

    // generate key
    nibs ks;
    for (int i = 0; i < 12; ++i) ks[i] = d(g);

    // print out pairs
    print_data(ks, num_pairs);
}


#include <functional>
#include <iostream>
#include <random>

#include "some_cipher.h"

/* Generate plaintext pairs by iterating through list of plaintexts. Check that
 * differences in plaintext and ciphertext correspond. */
void gen_pairs(const std::function<nibs(nibs)> f) {
    int pairs;
    nibs ps0{0}, ps1{0};
    nibs cs0{0}, cs1{0};

    /* distinguisher used:
     * 45 ... X ... 237 <- 237 <- 255 <- 990 with probability 7.033563070652695e-06, 6 rounds
     */

    pairs = 0;
    for (long x = 0; x < 65536 && pairs < 16384; ++x) {
        // iterate through key nibbles 6, 8, 9, 11, and fix the rest
        ps0[6] = x >> 12 & 0xF;
        ps0[8] = x >> 8 & 0xF;
        ps0[9] = x >> 4 & 0xF;
        ps0[11] = x & 0xF;
        cs0 = f(ps0);

        for (long y = x + 1; y < 65536 && pairs < 16384; ++y) {
            ps1[6] = y >> 12 & 0xF;
            ps1[8] = y >> 8 & 0xF;
            ps1[9] = y >> 4 & 0xF;
            ps1[11] = y & 0xF;
            cs1 = f(ps1);

            if (differences(ps0, ps1) != diffs {0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1}) continue;
            if (differences(cs0, cs1) != diffs {0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0}) continue;

            ++pairs;

            for (auto &p : ps0) std::cout << +p << " ";
            for (auto &p : ps1) std::cout << +p << " ";
            for (auto &c : cs0) std::cout << +c << " ";
            for (auto &c : cs1) std::cout << +c << " ";
            std::cout << std::endl;
        }
    }
}

int main() {
    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 15);

    // generate key
    nibs ks;
    for (int i = 0; i < 12; ++i) ks[i] = d(g);

    // function for encrypting plaintext
    std::function<nibs(nibs)> f = [ks](nibs ps) {
        return encrypt_block(ks, ps);
    };

    // print out key on first line
    for (auto &k : ks) std::cout << +k << " ";
    std::cout << std::endl;

    // print out PT-CT pairs on each line after the first line
    gen_pairs(f);
}


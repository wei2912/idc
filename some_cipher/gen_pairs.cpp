#include <functional>
#include <iostream>
#include <random>

#include "some_cipher.h"

/* Generate plaintexts by iterating through key nibbles 6, 8, 9 and 11 and
 * fixing the rest of the nibbles to 0. */
std::vector<nibs> gen_plaintexts() {
    std::vector<nibs> pss;
    for (long x = 0; x < 65536; ++x) {
        nibs ps{0};
        ps[6] = x >> 12 & 0xF;
        ps[8] = x >> 8 & 0xF;
        ps[9] = x >> 4 & 0xF;
        ps[11] = x & 0xF;
        pss.push_back(ps);
    }
    return pss;
}

/* Generate plaintext pairs by iterating through list of plaintexts. Check that
 * differences in plaintext and ciphertext correspond. */
std::vector<pair> gen_pairs(const std::vector<nibs> pss, const std::function<nibs(nibs)> f) {
    std::vector<pair> pairs;
    for (unsigned int i = 0; i < pss.size(); ++i) {
        auto ps0 = pss[i];
        auto cs0 = f(ps0);
        for (unsigned int j = i + 1; j < pss.size(); ++j) {
            auto ps1 = pss[j];
            if (differences(ps0, ps1) != diffs {0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1}) continue;

            auto cs1 = f(ps1);
            if (differences(cs0, cs1) != diffs {0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0}) continue;

            pair p;
            p.ps0 = ps0;
            p.ps1 = ps1;
            p.cs0 = cs0;
            p.cs1 = cs1;
            pairs.push_back(p);
        }
    }
    return pairs;
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

    // get list of PT-CT pairs
    std::vector<pair> pairs = gen_pairs(gen_plaintexts(), f);

    // print out key on first line
    // print out PT-CT pairs on each line after the first line
    // ps0 ps1 cs0 cs1
    for (nib &k : ks) std::cout << +k << " ";
    std::cout << std::endl;

    for (auto &p : pairs) {
        for (int i = 0; i < 12; ++i) std::cout << +p.ps0[i] << " ";
        for (int i = 0; i < 12; ++i) std::cout << +p.ps1[i] << " ";
        for (int i = 0; i < 12; ++i) std::cout << +p.cs0[i] << " ";
        for (int i = 0; i < 12; ++i) std::cout << +p.cs1[i] << " ";
        std::cout << std::endl;
    }
}


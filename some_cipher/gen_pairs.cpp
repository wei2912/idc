#include <functional>
#include <iostream>
#include <random>

#include "some_cipher.h"

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

int main() {
    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 15);

    // generate and print out key
    nibs ks;
    for (int i = 0; i < 12; ++i) ks[i] = d(g);
    for (nib &k : ks) std::cout << +k << " ";
    std::cout << std::endl;

    // print out PT-CT pairs on each line
    // ps0 ps1 cs0 cs1
    std::function<nibs(nibs)> f = [ks](nibs ps) {
        return encrypt_block(ks, ps);
    };

    std::vector<nibs> pss = gen_plaintexts();
    for (unsigned int i = 0; i < pss.size(); ++i) {
        auto ps0 = pss[i];
        auto cs0 = f(ps0);
        for (unsigned int j = i + 1; j < pss.size(); ++j) {
            auto ps1 = pss[j];
            if (differences(ps0, ps1) != diffs {0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1}) continue;

            auto cs1 = f(ps1);
            if (differences(cs0, cs1) != diffs {0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0}) continue;

            for (nib &p : ps0) std::cout << +p << " ";
            for (nib &p : ps1) std::cout << +p << " ";
            for (nib &c : cs0) std::cout << +c << " ";
            for (nib &c : cs1) std::cout << +c << " ";
            std::cout << std::endl;
        }
    }
}


#include <functional>
#include <iostream>
#include <sstream>
#include <vector>

#include "some_cipher.h"

typedef struct {
    nibs ps0;
    nibs ps1;
    nibs cs0;
    nibs cs1;
} pair;

std::vector<nibs> gen_keys() {
    nibs ks{0};
    std::vector<nibs> kss;
    for (long x = 0; x < 268435456; ++x) {
        ks[2] = x >> 24 & 0xF;
        ks[3] = x >> 20 & 0xF;
        ks[5] = x >> 16 & 0xF;
        ks[7] = x >> 12 & 0xF;
        ks[8] = x >> 8 & 0xF;
        ks[9] = x >> 4 & 0xF;
        ks[10] = x & 0xF;
        kss.push_back(ks);
    }
    return kss;
}

int main() {
    std::string line;

    // read the key
    nibs correct_ks;
    std::getline(std::cin, line);
    std::istringstream iss(line);
    for (int i = 0; i < 12; ++i) {
        int x;
        iss >> x;
        correct_ks[i] = x;
    }

    std::cout << "Correct key is ";
    for (auto &k : correct_ks) std::cout << +k << " ";
    std::cout << std::endl << std::endl;

    // read the plaintext pairs
    std::vector<pair> pairs;
    while (std::getline(std::cin, line)) {
        std::istringstream iss(line);
        pair p;
        for (int i = 0; i < 48; ++i) {
            int x;
            iss >> x;
            if (i < 12) p.ps0[i] = x;
            else if (i < 24) p.ps1[i - 12] = x;
            else if (i < 36) p.cs0[i - 24] = x;
            else p.cs1[i - 36] = x;
        }
        pairs.push_back(p);
    }

    std::cout << "Stage 1: IDC on key nibbles 2, 3, 5, 8, 9, 10" << std::endl;
    std::cout << "===" << std::endl;

    std::function<nibs(nibs, nibs)> f = [](nibs ks, nibs cs) {
        return inv_roundf(ks, inv_roundf(ks, cs, 4), 3);
    };

    // generate a list of all the keys
    std::vector<nibs> kss = gen_keys();
    std::cout << "Generated " << +kss.size() << " keys." << std::endl;

    // go through all the pairs
    for (auto &p : pairs) {
        std::cout << "PS0: ";
        for (int i = 0; i < 12; ++i) std::cout << +p.ps0[i] << " ";
        std::cout << std::endl;
        std::cout << "PS1: ";
        for (int i = 0; i < 12; ++i) std::cout << +p.ps1[i] << " ";
        std::cout << std::endl;
        std::cout << "CS0: ";
        for (int i = 0; i < 12; ++i) std::cout << +p.cs0[i] << " ";
        std::cout << std::endl;
        std::cout << "CS1: ";
        for (int i = 0; i < 12; ++i) std::cout << +p.cs1[i] << " ";
        std::cout << std::endl;

        for (unsigned int i = 0; i < kss.size(); ++i) {
            auto ks = kss[i];
            auto ds0 = f(ks, p.cs0);
            auto ds1 = f(ks, p.cs1);
            if (differences(ds0, ds1) == diffs {0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1}) {
                if (
                    ks[2] == correct_ks[2] &&
                    ks[3] == correct_ks[3] &&
                    ks[5] == correct_ks[5] &&
                    ks[7] == correct_ks[7] &&
                    ks[8] == correct_ks[8] &&
                    ks[9] == correct_ks[9] &&
                    ks[10] == correct_ks[10]
                ) {
                    std::cout << "ERROR: Correct key was eliminated." << std::endl;
                    return 1;
                }

                std::swap(kss[i], kss[kss.size() - 1]);
                kss.pop_back();
            }
        }
        std::cout << "Number of keys remaining: " << kss.size() << std::endl;
    }

    std::cout << "Stage 2: Brute force on all possible keys left" << std::endl;
    std::cout << "===" << std::endl;

    // brute force on all possible keys left
    auto p = pairs[0];
    for (auto &ks : kss) {
        for (long x = 0; x < 1048576; ++x) {
            ks[0] = x >> 16 & 0xF;
            ks[1] = x >> 12 & 0xF;
            ks[4] = x >> 8 & 0xF;
            ks[6] = x >> 4 & 0xF;
            ks[11] = x & 0xF;
            if (p.ps0 == decrypt_block(ks, p.cs0) && p.ps1 == decrypt_block(ks, p.cs1)) {
                std::cout << "Found the correct key!" << std::endl;
                for (auto &k : ks) std::cout << +k << " ";
                std::cout << std::endl;
                return 0;
            }
        }
    }

    std::cout << "ERROR: Could not find the correct key!" << std::endl;
    return 1;
}

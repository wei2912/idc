#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "some_cipher.h"

/* Generate the list of keys based on range by iterating through key nibbles 2,
 * 3, 5, 7, 8, 9, 10 and setting all other nibbles to 0. */
std::vector<nibs> gen_keys(const long start, const long end) {
    nibs ks{0};
    std::vector<nibs> kss;
    for (long x = start; x < end; ++x) {
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

/* Iterate through all PT-CT pairs. For each pair, filter out keys using IDC. */
void filter_keys(std::vector<nibs> kss, const std::function<nibs(nibs, nibs)> f, const std::vector<pair> pairs) {
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

        for (unsigned int i = 0; i < kss.size();) {
            auto ks = kss[i];
            auto ds0 = f(ks, p.cs0);
            auto ds1 = f(ks, p.cs1);

            if (differences(ds0, ds1) == diffs {0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1}) {
                std::swap(kss[i], kss[kss.size() - 1]);
                kss.pop_back();
            } else {
                ++i;
            }
        }

        std::cout << "Number of keys remaining: " << kss.size() << std::endl;
    }
}

/* Given the remaining combinations of key nibbles 2, 3, 5, 7, 8, 9, 10 left
 * after performing IDC, brute force the remaining keys. */
nibs brute_force(const std::function<nibs(nibs, nibs)> f, const std::vector<nibs> kss, const nibs ps, const nibs cs) {
    for (auto &ks : kss) {
        auto ls = ks;
        for (long x = 0; x < 1048576; ++x) {
            ls[0] = x >> 16 & 0xF;
            ls[1] = x >> 12 & 0xF;
            ls[4] = x >> 8 & 0xF;
            ls[6] = x >> 4 & 0xF;
            ls[11] = x & 0xF;
            if (ps == f(ls, cs)) return ls;
        }
    }

    throw std::runtime_error("could not find correct key");
}

int main(const int argc, const char *argv[]) {
    if (argc != 3) {
        std::cerr << "Wrong number of arguments. Please pass in the start and end number of the key nibbles." << std::endl;
        return 1;
    }

    // range of key nibbles
    // inclusive of start, exclusive of end
    long start = std::atol(argv[1]);
    long end = std::atol(argv[2]);

    std::string line; // used to store current line being read

    // read the correct key
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

    // read the plaintext pairs from stdin
    std::vector<pair> pairs;
    while (std::getline(std::cin, line)) {
        std::istringstream iss(line);
        pair p;
        for (int i = 0; i < 48; ++i) {
            // 1st 12 numbers: ps0
            // 2nd 12 numbers: ps1
            // 3rd 12 numbers: cs0
            // 4th 12 numbers: cs1
            int x;
            iss >> x;
            if (i < 12) p.ps0[i] = x;
            else if (i < 24) p.ps1[i - 12] = x;
            else if (i < 36) p.cs0[i - 24] = x;
            else p.cs1[i - 36] = x;
        }
        pairs.push_back(p);
    }

    // generate the list of keys based on range by
    // iterating through key nibbles 2, 3, 5, 7, 8, 9, 10 and
    // setting all other nibbles to 0
    std::vector<nibs> kss = gen_keys(start, end);
    std::cout << "Generated " << +kss.size() << " keys." << std::endl;

    std::cout << "Stage 1: IDC on key nibbles 2, 3, 5, 7, 8, 9, 10" << std::endl;
    std::cout << "===" << std::endl;

    // function for decrypting last 2 rounds
    std::function<nibs(nibs, nibs)> f = [](nibs ks, nibs cs) {
        return inv_roundf(ks, inv_roundf(ks, cs, 4), 3);
    };

    filter_keys(kss, f, pairs); // filters the keys in place

    std::cout << "Stage 2: Brute force on all possible keys left" << std::endl;
    std::cout << "===" << std::endl;

    // function for decrypting ciphertext
    std::function<nibs(nibs, nibs)> g = [](nibs ks, nibs cs) {
        return decrypt_block(ks, cs);
    };

    // perform brute force using first PT-CT of first pair
    pair p = pairs[0];

    try {
        nibs ks = brute_force(g, kss, p.ps0, p.cs0);

        if (ks == correct_ks) {
            std::cout << "Found correct key!" << std::endl;

            std::ofstream outfile("success");
            outfile << "Found correct key:";
            for (int i = 0; i < 12; ++i) outfile << " " << ks[i];
            outfile << std::endl;

            return 0;
        } else {
            throw std::logic_error("key found through brute force is not key used to encrypt plaintext pairs");
        }
    } catch (const std::exception &e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
}

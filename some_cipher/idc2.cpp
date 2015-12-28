#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "some_cipher.h"

/* Iterate through all PT-CT pairs and try to eliminate the key. */
bool is_key_wrong(const std::vector<pair> pairs, const std::vector<diffs> dss, const nibs ks) {
    for (auto &p : pairs) {
        auto ds0 = inv_roundf(ks, p.cs0, ROUNDS - 1);
        auto ds1 = inv_roundf(ks, p.cs1, ROUNDS - 1);

        bool is_wrong = true;
        for (unsigned int i = 0; i < dss.size(); ++i) {
            auto ds = dss[i];
            ds0 = inv_roundf(ks, ds0, ROUNDS - i - 2);
            ds1 = inv_roundf(ks, ds1, ROUNDS - i - 2);
            if (differences(ds0, ds1) != ds) {
                is_wrong = false;
                break;
            }
        }

        if (is_wrong) return true;
    }

    return false;
}

int main(const int argc, const char *argv[]) {
    if (argc != 3) {
        std::cerr << "Wrong number of arguments. Please pass in the start and end number of the key nibbles." << std::endl;
        return 2;
    }

    // range of key nibbles
    // inclusive of start, exclusive of end
    long start = std::atol(argv[1]);
    long end = std::atol(argv[2]);

    std::string line;

    // skip the correct key
    std::getline(std::cin, line);

    // read the plaintext pairs from stdin
    std::vector<pair> pairs0;
    std::vector<pair> pairs1;
    while (std::getline(std::cin, line)) {
        std::istringstream iss(line);
        pair p;
        int id;
        for (int i = 0; i < 49; ++i) {
            // 0th number: id
            // 1-12th number: ps0
            // 13-24th number: ps1
            // 25-36th number: cs0
            // 37-48th number: cs1
            int x;
            iss >> x;
            if (i == 0) id = x;
            else if (i <= 12) p.ps0[i - 1] = x;
            else if (i <= 24) p.ps1[i - 13] = x;
            else if (i <= 36) p.cs0[i - 25] = x;
            else p.cs1[i - 37] = x;
        }

        if (id == 0) pairs0.push_back(p);
        else if (id == 1) pairs1.push_back(p);
    }

    // propagation of differentials from backwards
    std::vector<diffs> dss0;
    dss0.push_back({0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1});
    dss0.push_back({0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1});
    std::vector<diffs> dss1;
    dss1.push_back({1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0});
    dss1.push_back({1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0});

    std::cout << "Stage 1: IDC attack with first distinguisher" << std::endl;

    std::unordered_map<long, std::vector<nibs>> map_ks;

    // filtering by first distinguisher
    int keys_remaining = 0;
    for (long i = start; i < end; ++i) {
        nibs ks{0};

        // iterate through key nibbles 2, 3, 5, 7, 8, 9, 10
        // go through overlapping nibbles first
        ks[3] = i >> 24 & 0xF;
        ks[10] = i >> 20 & 0xF;
        // then the non-overlapping nibbles
        ks[2] = i >> 16 & 0xF;
        ks[5] = i >> 12 & 0xF;
        ks[7] = i >> 8 & 0xF;
        ks[8] = i >> 4 & 0xF;
        ks[9] = i & 0xF;

        if (is_key_wrong(pairs0, dss0, ks)) continue;

        ++keys_remaining;

        long overlap_k = ks[10] | ks[3] << 4;
        auto it = map_ks.find(overlap_k);

        std::vector<nibs> kss{};
        if (it != map_ks.end()) { // could find overlapped key
            kss = it->second;
            map_ks.erase(it);
        }
        kss.push_back(ks);
        map_ks.insert({overlap_k, kss});
    }

    std::cout << "Keys remaining: " << keys_remaining << std::endl;

    std::cout << "Stage 2: IDC attack with second distinguisher and brute force" << std::endl;

    for (auto &pair : map_ks) {
        long overlap_k = pair.first;
        std::vector<nibs> kss = pair.second;
        std::cout << overlap_k << ": " << +kss.size() << std::endl;
    }

    // filtering by second distinguisher
    // and conducting brute force
    for (auto &pair : map_ks) {
        long overlap_k = pair.first;
        std::vector<nibs> kss = pair.second;

        nibs ks{0};
        // overlapping nibbles
        ks[3] = overlap_k >> 4 & 0xF;
        ks[10] = overlap_k & 0xF;

        for (long i = 0; i < 1048576; ++i) {
            ks[0] = i >> 16 & 0xF;
            ks[1] = i >> 12 & 0xF;
            ks[4] = i >> 8 & 0xF;
            ks[6] = i >> 4 & 0xF;
            ks[11] = i & 0xF;

            if (is_key_wrong(pairs1, dss1, ks)) continue;

            for (auto &ls : kss) {
                ks[2] = ls[2];
                ks[5] = ls[5];
                ks[7] = ls[7];
                ks[8] = ls[8];
                ks[9] = ls[9];

                auto ps0 = pairs1[0].ps0;
                auto cs0 = pairs1[0].cs0;
                if (ps0 == decrypt_block(ks, cs0)) {
                    std::ofstream outfile("success");
                    outfile << "Found correct key:";
                    for (auto &k : ks) outfile << " " << +k;
                    outfile << std::endl;

                    return 0;
                }
            }
        }
    }

    std::cerr << "error: can't find correct key" << std::endl;
    return 1;
}

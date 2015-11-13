#include <array>
#include <algorithm>
#include <iostream>
#include <random>
#include <vector>

#include "some_cipher.h"

using diffs = std::array<bool, 12>;

diffs differences(const nibs ns0, const nibs ns1) {
    diffs ds;
    for (unsigned int i = 0; i < ns0.size(); ++i) ds[i] = ns0[i] == ns1[i];
    return ds;
}

std::vector<nibs> gen_plaintexts() {
    std::vector<nibs> pss;
    nibs ps;
    for (int i = 0; i < 12; ++i) ps[i] = 0;
    for (ps[6] = 0; ps[6] < 16; ++ps[6]) {
    for (ps[8] = 0; ps[8] < 16; ++ps[8]) {
    for (ps[9] = 0; ps[9] < 16; ++ps[9]) {
    for (ps[11] = 0; ps[11] < 16; ++ps[11]) {
        pss.push_back(ps);
    }}}}
    return pss;
}

std::vector<nibs> gen_keys() {
    std::vector<nibs> kss;
    nibs ks;
    for (int i = 0; i < 12; ++i) ks[i] = 0;
    for (ks[5] = 0; ks[5] < 16; ++ks[5]) {
    for (ks[6] = 0; ks[6] < 16; ++ks[6]) {
    for (ks[7] = 0; ks[7] < 16; ++ks[7]) {
    for (ks[8] = 0; ks[8] < 16; ++ks[8]) {
    for (ks[9] = 0; ks[9] < 16; ++ks[9]) {
    for (ks[10] = 0; ks[10] < 16; ++ks[10]) {
    for (ks[11] = 0; ks[11] < 16; ++ks[11]) {
        kss.push_back(ks);
    }}}}}}}
    return kss;
}

bool is_plaintext_match(nibs ps0, nibs ps1) {
    auto xs = differences(ps0, ps1);
    diffs ys = {0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1};
    return xs == ys;
}

bool is_ciphertext_match(nibs cs0, nibs cs1) {
    auto xs = differences(cs0, cs1);
    diffs ys = {0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0};
    return xs == ys;
}

bool is_impossible(nibs ds0, nibs ds1) {
    auto xs = differences(ds0, ds1);
    diffs ys = {0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1};
    return xs == ys;
}

int main() {
    std::random_device rd;
    std::default_random_engine g(rd());
    std::uniform_int_distribution<> d(0, 15);

    nibs ks;
    for (int i = 0; i < 12; ++i) ks[i] = d(g);

    std::cout << "Key: ";
    for (auto &k : ks) std::cout << +k << " ";
    std::cout << std::endl;

    auto pss = gen_plaintexts();
    std::cout << "Generated " << pss.size() << " plaintexts." << std::endl;
    auto kss = gen_keys();
    std::cout << "Generated " << kss.size() << " keys." << std::endl;

    for (auto &ps0 : pss) {
        for (auto &ps1 : pss) {
            if (!is_plaintext_match(ps0, ps1)) continue;

            auto cs0 = encrypt_block(ks, ps0);
            auto cs1 = encrypt_block(ks, ps1);
            if (!is_ciphertext_match(cs0, cs1)) continue;

            std::cout << "Found a plaintext pair." << std::endl;
            std::cout << "PS0: ";
            for (auto &p : ps0) std::cout << +p << " ";
            std::cout << std::endl;
            std::cout << "PS1: ";
            for (auto &p : ps1) std::cout << +p << " ";
            std::cout << std::endl;
            std::cout << "CS0: ";
            for (auto &c : cs0) std::cout << +c << " ";
            std::cout << std::endl;
            std::cout << "CS1: ";
            for (auto &c : cs1) std::cout << +c << " ";
            std::cout << std::endl;

            for (auto it = kss.begin(); it != kss.end(); ++it) {
                auto ks = *it;
                auto ds0 = inv_roundf(ks, inv_roundf(ks, cs0, 4), 3);
                auto ds1 = inv_roundf(ks, inv_roundf(ks, cs1, 4), 3);
                if (is_impossible(ds0, ds1)) {
                    std::iter_swap(it, kss.end());
                    kss.pop_back();
                }
            }

            std::cout << "Number of keys remaining: " << kss.size() << std::endl;
        }
    }

    return 0;
}


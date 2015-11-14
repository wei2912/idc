#include <functional>
#include <iostream>
#include <random>

#include "some_cipher.h"

std::vector<nibs> gen_plaintexts() {
    std::vector<nibs> pss;
    for (int p6 = 0; p6 < 16; ++p6) {
    for (int p8 = 0; p8 < 16; ++p8) {
    for (int p9 = 0; p9 < 16; ++p9) {
    for (int p11 = 0; p11 < 16; ++p11) {
        nibs ps{0};
        ps[6] = p6;
        ps[8] = p8;
        ps[9] = p9;
        ps[11] = p11;
        pss.push_back(ps);
    }}}}
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

    /* print out pairs per line:
     * cs0 cs1
     */

    std::function<nibs(nibs)> f = [ks](nibs ps) {
        return encrypt_block(ks, ps);
    };

    std::function<bool(nibs, nibs)> is_pt_match = [](nibs ps0, nibs ps1){
        return differences(ps0, ps1) == diffs {0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1};
    };

    std::function<bool(nibs, nibs)> is_ct_match = [](nibs cs0, nibs cs1){
        return differences(cs0, cs1) == diffs {0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0};
    };

    std::vector<nibs> pss = gen_plaintexts();
    for (auto &ps0 : pss) {
        for (auto &ps1 : pss) {
            if (!is_pt_match(ps0, ps1)) continue;

            auto cs0 = f(ps0);
            auto cs1 = f(ps1);
            if (!is_ct_match(cs0, cs1)) continue;

            for (nib &c : cs0) std::cout << +c << " ";
            for (nib &c : cs1) std::cout << +c << " ";
            std::cout << std::endl;
        }
    }
}


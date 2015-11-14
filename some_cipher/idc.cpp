#include <functional>
#include <iostream>
#include <vector>

#include "some_cipher.h"

std::vector<nibs> gen_keys() {
    std::vector<nibs> kss;
    for (int k5 = 0; k5 < 16; ++k5) {
    for (int k6 = 0; k6 < 16; ++k6) {
    for (int k7 = 0; k7 < 16; ++k7) {
    for (int k8 = 0; k8 < 16; ++k8) {
    for (int k9 = 0; k9 < 16; ++k9) {
    for (int k10 = 0; k10 < 16; ++k10) {
    for (int k11 = 0; k11 < 16; ++k11) {
        nibs ks{0};
        ks[5] = k5;
        ks[6] = k6;
        ks[7] = k7;
        ks[8] = k8;
        ks[9] = k9;
        ks[10] = k10;
        ks[11] = k11;
        kss.push_back(ks);
    }}}}}}}
    return kss;
}

int main() {
    // read the key
    nibs correct_ks;
    for (int i = 0; i < 12; ++i) std::cin >> correct_ks[i];

    // generate a list of all the keys
    std::vector<nibs> kss = gen_keys();
    std::cout << "Generated " << +kss.size() << " keys." << std::endl;

    // go through all the pairs

    std::function<nibs(nibs, nibs)> f = [](nibs ks, nibs cs) {
        return inv_roundf(ks, inv_roundf(ks, cs, 4), 3);
    };

    std::function<bool(nibs, nibs)> is_impossible = [](nibs ds0, nibs ds1) {
        return differences(ds0, ds1) == diffs {0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1};
    };

    while (std::cin) {
        nibs cs0, cs1;
        for (int i = 0; i < 12; ++i) std::cin >> cs0[i];
        for (int i = 0; i < 12; ++i) std::cin >> cs1[i];

        for (unsigned int i = 0; i < kss.size(); ++i) {
            auto ks = kss[i];
            auto ds0 = f(ks, cs0);
            auto ds1 = f(ks, cs1);
            if (is_impossible(ds0, ds1)) {
                if (
                    ks[5] == correct_ks[5] &&
                    ks[6] == correct_ks[6] &&
                    ks[7] == correct_ks[7] &&
                    ks[8] == correct_ks[8] &&
                    ks[9] == correct_ks[9] &&
                    ks[10] == correct_ks[10] &&
                    ks[11] == correct_ks[11]
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

    return 0;
}

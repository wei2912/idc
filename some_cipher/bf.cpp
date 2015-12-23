#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "some_cipher.h"

int main(const int argc, const char *argv[]) {
    if (argc != 3) {
        std::cerr << "Wrong number of arguments. Please pass in the start and end number of the key nibbles." << std::endl;
        return 2;
    }

    // range of key nibbles
    // inclusive of start, exclusive of end
    unsigned long long start = std::atol(argv[1]);
    unsigned long long end = std::atol(argv[2]);

    std::string line;
    std::getline(std::cin, line);

    // read in a plaintext pair
    nibs ps0, ps1, cs0, cs1;
    for (int i = 0; i < 49; ++i) {
        std::istringstream iss(line);
        // 0-11th number: ps0
        // 12-23th number: ps1
        // 24-35th number: cs0
        // 36-47th number: cs1
        int x;
        iss >> x;
        if (i < 12) ps0[i] = x;
        else if (i < 24) ps1[i - 12] = x;
        else if (i < 36) cs0[i - 24] = x;
        else cs1[i - 36] = x;
    }

    for (unsigned long long i = start; i < end; ++i) {
        nibs ks{0};

        ks[0] = i >> 44 & 0xF;
        ks[1] = i >> 40 & 0xF;
        ks[2] = i >> 36 & 0xF;
        ks[3] = i >> 32 & 0xF;
        ks[4] = i >> 28 & 0xF;
        ks[5] = i >> 24 & 0xF;
        ks[6] = i >> 20 & 0xF;
        ks[7] = i >> 16 & 0xF;
        ks[8] = i >> 12 & 0xF;
        ks[9] = i >> 8 & 0xF;
        ks[10] = i >> 4 & 0xF;
        ks[11] = i & 0xF;

        if (ps0 == decrypt_block(ks, cs0)) {
            std::ofstream outfile("success");
            outfile << "Found correct key:";
            for (auto &k : ks) outfile << " " << +k;
            outfile << std::endl;

            return 0;
        }
    }

    std::cerr << "error: can't find correct key" << std::endl;
    return 1;
}

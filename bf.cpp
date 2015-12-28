#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

#include "some_cipher.h"

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

    // read in plaintext and ciphertext
    std::getline(std::cin, line);
    std::istringstream iss(line);
    nibs ps, cs;
    for (int i = 0; i < 24; ++i) {
        // 0-11th number: ps
        // 12-23th number: cs
        int x;
        iss >> x;
        if (i < 12) ps[i] = x;
        else cs[i - 12] = x;
    }

    for (long i = start; i < end; ++i) {
        nibs ks{0};

        ks[0] = i >> 24 & 0xF;
        ks[1] = i >> 20 & 0xF;
        ks[2] = i >> 16 & 0xF;
        ks[3] = i >> 12 & 0xF;
        ks[4] = i >> 8 & 0xF;
        ks[5] = i >> 4 & 0xF;
        ks[6] = i & 0xF;

        for (long j = 0; j < 1048576; ++j) {
            ks[7] = j >> 16 & 0xF;
            ks[8] = j >> 12 & 0xF;
            ks[9] = j >> 8 & 0xF;
            ks[10] = j >> 4 & 0xF;
            ks[11] = j & 0xF;

            if (ps == decrypt_block(ks, cs)) {
                std::ofstream outfile("success");
                outfile << "Found correct key:";
                for (auto &k : ks) outfile << " " << +k;
                outfile << std::endl;

                return 0;
            }
        }
    }

    std::cerr << "error: can't find correct key" << std::endl;
    return 1;
}

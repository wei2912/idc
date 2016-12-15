#include <iostream>
#include <map>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include "../some_cipher.h"
}

typedef struct {
    uint16_t pt[3];
    uint16_t ct[3];
} pt_ct_t;

/* wrapper to print */
static void print_pair(const pt_ct_t x, const pt_ct_t y) {
    std::printf(
        "%04x%04x%04x %04x%04x%04x %04x%04x%04x %04x%04x%04x\n",
        x.pt[0], x.pt[1], x.pt[2],
        x.ct[0], x.ct[1], x.ct[2],
        y.pt[0], y.pt[1], y.pt[2],
        y.ct[0], y.ct[1], y.ct[2]
    );
}

static bool pt_has_44(const pt_ct_t x, const pt_ct_t y) {
    // no need to check for passive nibbles
    return (x.pt[1] & 0x00F0) != (y.pt[1] & 0x00F0);

    return (x.pt[2] & 0xF000) != (y.pt[2] & 0xF000);
    return (x.pt[2] & 0x0F00) != (y.pt[2] & 0x0F00);
}

static bool ct_has_450(const pt_ct_t x, const pt_ct_t y) {
    // no need to check for passive nibbles
    return (
        (x.ct[0] & 0x000F) != (y.ct[0] & 0x000F) &&

        (x.ct[1] & 0xF000) != (y.ct[1] & 0xF000) &&
        (x.ct[1] & 0x0F00) != (y.ct[1] & 0x0F00) &&

        (x.ct[2] & 0x00F0) != (y.ct[2] & 0x00F0)
    );
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " [start] [end]" << std::endl;
        std::cerr << "start and end are 64-bit values indicating the range of PT structures to encrypt" << std::endl;
        return 1;
    }

    uint64_t start = std::stoul(argv[1]);
    uint64_t end = std::stoul(argv[2]);

    // 1. Take in a key as a hexadecimal string.
    uint64_t key_hex;
    std::cin >> std::hex >> key_hex;

    uint16_t key[3];
    key[0] = key_hex >> 32;
    key[1] = key_hex >> 16 & 0xFFFF;
    key[2] = key_hex & 0xFFFF;

    // 2. Go through the range of PT structures.
    for (uint64_t i = start; i <= end; ++i) {
        // 3. Encrypt each plaintext in the structure.
        // Place each PT-CT pair into a hash table indexed by passive nibbles of ciphertext.
        std::map<uint64_t, std::vector<pt_ct_t>> map;
        for (uint16_t j = 0; j < 4096; ++j) {
            pt_ct_t pt_ct = {};
            pt_ct.pt[0] = i >> 20; 
            pt_ct.pt[1] = (i >> 12 & 0xFF00) | (j >> 4 & 0x00F0) | (i >> 8 & 0x000F);
            pt_ct.pt[2] = (j << 8 & 0xFF00) | (i & 0x00FF);

            encrypt(pt_ct.pt, pt_ct.ct, key);
            uint64_t fixed_nibs = (((uint64_t) pt_ct.ct[0] & 0xFFF0) << 32) |
                (((uint64_t) pt_ct.ct[1] & 0x00FF) << 16) |
                ((uint64_t) pt_ct.ct[2] & 0xFF0F);
            map[fixed_nibs].push_back(pt_ct);
        }

        // 4. Go through each row of the hash table, and pair up all plaintext-ciphertexts in that row with each other.
        // Check if the plaintext-ciphertext pairs satisfy the differences.
        for (auto const &p : map) {
            auto const vec = p.second;
            for (unsigned int i = 0; i < vec.size(); ++i) {
                for (unsigned int j = i + 1; j < vec.size(); ++j) {
                    if (pt_has_44(vec[i], vec[j]) && ct_has_450(vec[i], vec[j])) {
                        print_pair(vec[i], vec[j]);
                    }
                }
            }
        }
    }
}


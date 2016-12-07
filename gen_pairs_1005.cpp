#include <iostream>
#include <map>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include "some_cipher.h"
}

typedef struct {
    uint16_t pt[3];
    uint16_t ct[3];
} pt_ct_t;

/* wrapper to print */
static void print_pair(int id, const pt_ct_t x, const pt_ct_t y) {
    std::printf(
        "%d %04x%04x%04x %04x%04x%04x %04x%04x%04x %04x%04x%04x\n",
        id,
        x.pt[0], x.pt[1], x.pt[2],
        x.ct[0], x.ct[1], x.ct[2],
        y.pt[0], y.pt[1], y.pt[2],
        y.ct[0], y.ct[1], y.ct[2]
    );
}

static bool pt_has_1005(const pt_ct_t x, const pt_ct_t y) {
    return (
        (x.pt[0] & 0x00F0) != (y.pt[0] & 0x00F0) &&
        (x.pt[0] & 0x000F) != (y.pt[0] & 0x000F) &&

        (x.pt[1] & 0xF000) != (y.pt[1] & 0xF000) &&
        (x.pt[1] & 0x0F00) != (y.pt[1] & 0x0F00) &&
        (x.pt[1] & 0x00F0) != (y.pt[1] & 0x00F0) &&

        (x.pt[2] & 0xF000) != (y.pt[2] & 0xF000) &&
        (x.pt[2] & 0x0F00) != (y.pt[2] & 0x0F00) &&
        (x.pt[2] & 0x000F) != (y.pt[2] & 0x000F)
    );
}

static bool ct_has_450(const pt_ct_t x, const pt_ct_t y) {
    return (
        (x.ct[0] & 0x000F) != (y.ct[0] & 0x000F) &&

        (x.ct[1] & 0xF000) != (y.ct[1] & 0xF000) &&
        (x.ct[1] & 0x0F00) != (y.ct[1] & 0x0F00) &&

        (x.ct[2] & 0x00F0) != (y.ct[2] & 0x00F0)
    );
}

static bool ct_has_540(const pt_ct_t x, const pt_ct_t y) {
    return (
        (x.ct[0] & 0x00F0) != (y.ct[0] & 0x00F0) &&

        (x.ct[1] & 0x000F) != (y.ct[1] & 0x000F) &&

        (x.ct[2] & 0xF000) != (y.ct[2] & 0xF000) &&
        (x.ct[2] & 0x0F00) != (y.ct[2] & 0x0F00)
    );
}

static unsigned long c1 = 123456789, c2 = 362436069, c3 = 521288629;
static unsigned long xorshf96() {
    unsigned long t;
    c1 ^= c1 << 16;
    c1 ^= c1 >> 5;
    c1 ^= c1 << 1;

    t = c1;
    c1 = c2;
    c2 = c3;
    c3 = t ^ c1 ^ c2;

    return c3;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " [domain] [num]" << std::endl;
        std::cerr << "domain is a 16-bit value indicating the value of the passive nibbles" << std::endl;
        std::cerr << "num is a 32-bit value indicating the number of PT-CTs to encrypt" << std::endl;
        return 2;
    }

    uint16_t domain = std::stoi(argv[1]);
    uint32_t num = std::stoul(argv[2]);

    // 1. Take in a key as a hexadecimal string.
    uint64_t key_hex;
    std::cin >> std::hex >> key_hex;

    uint16_t key[3];
    key[0] = key_hex >> 32;
    key[1] = key_hex >> 16 & 0xFFFF;
    key[2] = key_hex & 0xFFFF;

    std::printf("%04x%04x%04x\n", key[0], key[1], key[2]);

    // 2. Generate random plaintexts in the domain and encrypt.
    // Place into a hash table, ordered by passive nibbles of ciphertext.
    std::map<uint64_t, std::vector<pt_ct_t>> map;
    for (uint32_t i = 0; i < num; ++i) {
        uint32_t x = xorshf96();
        pt_ct_t pt_ct = {};
        pt_ct.pt[0] = (domain & 0xFF00) | (x >> 24);
        pt_ct.pt[1] = (domain >> 4 & 0xF) | (x >> 8 & 0xFFF0);
        pt_ct.pt[2] = (domain << 4 & 0xF0) | (x << 4 & 0xFF00) | (x & 0xF);

        encrypt(pt_ct.pt, pt_ct.ct, key);
        uint64_t key = (((uint64_t) pt_ct.ct[0] & 0xFFF0) << 32) |
            (((uint64_t) pt_ct.ct[1] & 0x00FF) << 16) |
            ((uint64_t) pt_ct.ct[2] & 0xFF0F);
        map[key].push_back(pt_ct);
    }

    // 3. Go through each row of the hash table, and pair up all plaintext-ciphertexts in that row with each other.
    // Check if the plaintext-ciphertext pairs satisfy the differences.
    for (auto const &p : map) {
        auto const vec = p.second;
        for (unsigned int i = 0; i < vec.size(); ++i) {
            for (unsigned int j = i + 1; j < vec.size(); ++j) {
                if (pt_has_1005(vec[i], vec[j])) {
                    if (ct_has_450(vec[i], vec[j])) print_pair(450, vec[i], vec[j]);
                    else if (ct_has_540(vec[i], vec[j])) print_pair(540, vec[i], vec[j]);
                }
            }
        }
    }
}


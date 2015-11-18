#include <algorithm>
#include <iostream>

#include "some_cipher.h"

const int ROUNDS = 5;

const std::array<unsigned char, 16> SBOX = {
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
};

const std::array<unsigned char, 16> INV_SBOX = {
    0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF,
    0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5
};

const std::array<unsigned char, 16> M1 = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};

const std::array<unsigned char, 16> M4 = {
    0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF,
    0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9
};

const std::array<unsigned char, 16> M7 = {
    0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6,
    0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB
};

const std::array<unsigned char, 16> M8 = {
    0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD,
    0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1
};

const std::array<unsigned char, 16> M9 = {
    0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA,
    0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE
};

const std::array<unsigned char, 16> M12 = {
    0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2,
    0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8
};

diffs differences(const nibs ns0, const nibs ns1) {
    diffs ds;
    for (int i = 0; i < 12; ++i) ds[i] = ns0[i] != ns1[i];
    return ds;
}

nibs nibble_sub(const nibs ns) {
    auto os = ns;
    for (int i = 0; i < 12; ++i) os[i] = SBOX[ns[i]];
    return os;
}

nibs inv_nibble_sub(const nibs ns) {
    auto os = ns;
    for (int i = 0; i < 12; ++i) os[i] = INV_SBOX[ns[i]];
    return os;
}

nibs shift_row(const nibs ns) {
    auto os = ns;
    std::swap(os[2], os[6]);
    std::swap(os[2], os[10]);
    std::swap(os[3], os[11]);
    std::swap(os[3], os[7]);
    return os;
}

nibs inv_shift_row(const nibs ns) {
    auto os = ns;
    std::swap(os[2], os[6]);
    std::swap(os[6], os[10]);
    std::swap(os[3], os[7]);
    std::swap(os[3], os[11]);
    return os;
}

nibs mix_column(const nibs ns) {
    nibs os;
    os[0] = M1[ns[0]] ^ M1[ns[1]] ^ M4[ns[2]] ^ M9[ns[3]];
    os[1] = M1[ns[0]] ^ M4[ns[1]] ^ M9[ns[2]] ^ M1[ns[3]];
    os[2] = M4[ns[0]] ^ M9[ns[1]] ^ M1[ns[2]] ^ M1[ns[3]];
    os[3] = M9[ns[0]] ^ M1[ns[1]] ^ M1[ns[2]] ^ M4[ns[3]];

    os[4] = M1[ns[4]] ^ M1[ns[5]] ^ M4[ns[6]] ^ M9[ns[7]];
    os[5] = M1[ns[4]] ^ M4[ns[5]] ^ M9[ns[6]] ^ M1[ns[7]];
    os[6] = M4[ns[4]] ^ M9[ns[5]] ^ M1[ns[6]] ^ M1[ns[7]];
    os[7] = M9[ns[4]] ^ M1[ns[5]] ^ M1[ns[6]] ^ M4[ns[7]];

    os[8] = M1[ns[8]] ^ M1[ns[9]] ^ M4[ns[10]] ^ M9[ns[11]];
    os[9] = M1[ns[8]] ^ M4[ns[9]] ^ M9[ns[10]] ^ M1[ns[11]];
    os[10] = M4[ns[8]] ^ M9[ns[9]] ^ M1[ns[10]] ^ M1[ns[11]];
    os[11] = M9[ns[8]] ^ M1[ns[9]] ^ M1[ns[10]] ^ M4[ns[11]];
    return os;
}

nibs inv_mix_column(const nibs ns) {
    nibs os;
    os[0] = M8[ns[0]] ^ M12[ns[1]] ^ M7[ns[2]] ^ M7[ns[3]];
    os[1] = M12[ns[0]] ^ M7[ns[1]] ^ M7[ns[2]] ^ M8[ns[3]];
    os[2] = M7[ns[0]] ^ M7[ns[1]] ^ M8[ns[2]] ^ M12[ns[3]];
    os[3] = M7[ns[0]] ^ M8[ns[1]] ^ M12[ns[2]] ^ M7[ns[3]];

    os[4] = M8[ns[4]] ^ M12[ns[5]] ^ M7[ns[6]] ^ M7[ns[7]];
    os[5] = M12[ns[4]] ^ M7[ns[5]] ^ M7[ns[6]] ^ M8[ns[7]];
    os[6] = M7[ns[4]] ^ M7[ns[5]] ^ M8[ns[6]] ^ M12[ns[7]];
    os[7] = M7[ns[4]] ^ M8[ns[5]] ^ M12[ns[6]] ^ M7[ns[7]];

    os[8] = M8[ns[8]] ^ M12[ns[9]] ^ M7[ns[10]] ^ M7[ns[11]];
    os[9] = M12[ns[8]] ^ M7[ns[9]] ^ M7[ns[10]] ^ M8[ns[11]];
    os[10] = M7[ns[8]] ^ M7[ns[9]] ^ M8[ns[10]] ^ M12[ns[11]];
    os[11] = M7[ns[8]] ^ M8[ns[9]] ^ M12[ns[10]] ^ M7[ns[11]];
    return os;
}

nibs key_addition(const nibs ks, const nibs ns) {
    nibs os;
    for (int i = 0; i < 12; ++i) os[i] = ks[i] ^ ns[i];
    return os;
}

nibs roundf(const nibs ks, const nibs ns, const int i) {
    nibs os = shift_row(nibble_sub(ns));
    if (i != ROUNDS - 1) os = mix_column(os);
    return key_addition(ks, os);
}

nibs inv_roundf(const nibs ks, const nibs ns, const int i) {
    nibs os = key_addition(ks, ns);
    if (i != ROUNDS - 1) os = inv_mix_column(os);
    return inv_nibble_sub(inv_shift_row(os));
}

nibs encrypt_block(const nibs ks, const nibs ps) {
    nibs ns = key_addition(ks, ps);
    for (int i = 0; i < ROUNDS; ++i) ns = roundf(ks, ns, i);
    return ns;
}

nibs decrypt_block(const nibs ks, const nibs cs) {
    nibs ns = cs;
    for (int i = ROUNDS - 1; i >= 0; --i) ns = inv_roundf(ks, ns, i);
    return key_addition(ks, ns);
}

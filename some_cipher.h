#ifndef SOME_CIPHER_H
#define SOME_CIPHER_H

#include <array>

#define ROUNDS 6

using diff = bool;
using diffs = std::array<diff, 12>;

using nib = unsigned char;
using nibs = std::array<nib, 12>;

typedef struct {
    nibs ps0;
    nibs ps1;
    nibs cs0;
    nibs cs1;
} pair;

diffs differences(nibs ns0, nibs ns1);

nibs roundf(nibs ks, nibs ns, int i);
nibs inv_roundf(nibs ks, nibs ns, int i);

nibs encrypt_block(nibs ks, nibs ps);
nibs decrypt_block(nibs ks, nibs cs);

#endif

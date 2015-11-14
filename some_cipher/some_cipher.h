#ifndef SOME_CIPHER_H
#define SOME_CIPHER_H

#include <array>

using diff = bool;
using diffs = std::array<bool, 12>;

using nib = unsigned char;
using nibs = std::array<unsigned char, 12>;

diffs differences(nibs ns0, nibs ns1);

nibs roundf(nibs ks, nibs ns, int i);
nibs inv_roundf(nibs ks, nibs ns, int i);

nibs encrypt_block(nibs ks, nibs ps);
nibs decrypt_block(nibs ks, nibs cs);

#endif

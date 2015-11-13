#include <array>

using nibs = std::array<unsigned char, 12>;

nibs roundf(nibs ks, nibs ns, int i);
nibs inv_roundf(nibs ks, nibs ns, int i);

nibs encrypt_block(nibs ks, nibs ps);
nibs decrypt_block(nibs ks, nibs cs);


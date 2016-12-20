#ifndef IDC_H
#define IDC_H

#include <bitset>
#include <map>

typedef std::map<uint32_t, std::bitset<256>> pks_t;

void derive_from_k5(const uint16_t *k5, uint16_t *output);

#endif


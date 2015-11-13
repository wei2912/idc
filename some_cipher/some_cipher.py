"""
Implementation of SomeCipher.
"""

import random

ROUNDS = 5

SBOX = [
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
]

INV_SBOX = [
    0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF,
    0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5
]

MULTI_1 = [
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
]

MULTI_4 = [
    0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF,
    0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9
]

MULTI_7 = [
    0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6,
    0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB
]

MULTI_8 = [
    0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD,
    0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1
]

MULTI_9 = [
    0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA,
    0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE
]

MULTI_12 = [
    0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2,
    0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8
]

# utility functions

def chunks(xs, n):
    """
    xs -> List of elements.
    n -> Length of chunk.

    Divide a list of elements into chunks of length `n`.
    """
    for i in range(0, len(xs), n):
        yield xs[i:i+n]

# procedures

def nibble_sub(ns):
    """
    ns -> List of nibbles

    Passes each nibble through a S-Box. The mapping is specified in `SBOX`.
    """
    return [SBOX[n] for n in ns]

def inv_nibble_sub(ns):
    """
    ns -> List of nibbles

    Inverse function of `nibble_sub()`.
    """
    return [INV_SBOX[n] for n in ns]

def shift_row(ns):
    """
    ns -> List of nibbles

    Shift each row of the matrix of nibbles to the right by different amounts.

    The first and second row is unchanged, while the third and fourth row are
    rotated by 1 and 2 elements to the right respectively.
    """
    assert len(ns) == 12
    n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11 = ns
    return [n0, n1, n10, n7, n4, n5, n2, n11, n8, n9, n6, n3]

def inv_shift_row(ns):
    """
    ns -> List of nibbles

    Inverse function of `shift_row()`.
    """
    assert len(ns) == 12
    n0, n1, n10, n7, n4, n5, n2, n11, n8, n9, n6, n3 = ns
    return [n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11]

def mix_column(ns):
    """
    ns -> List of nibbles

    Multiplies the matrix of nibbles by a constant matrix,

        1  1  4  9

        1  4  9  1

        4  9  1  1

        9  1  1  4
    """
    def multiply_matrix(ms):
        assert len(ms) == 4
        m0, m1, m2, m3 = ms
        return [
            MULTI_1[m0] ^ MULTI_1[m1] ^ MULTI_4[m2] ^ MULTI_9[m3],
            MULTI_1[m0] ^ MULTI_4[m1] ^ MULTI_9[m2] ^ MULTI_1[m3],
            MULTI_4[m0] ^ MULTI_9[m1] ^ MULTI_1[m2] ^ MULTI_1[m3],
            MULTI_9[m0] ^ MULTI_1[m1] ^ MULTI_1[m2] ^ MULTI_4[m3],
        ]

    assert len(ns) == 12
    return [
        n
        for ms in chunks(ns, 4)
        for n in multiply_matrix(ms)
    ]

def inv_mix_column(ns):
    """
    ns -> List of nibbles

    Inverse of `mix_column()`.

    Multiplies the matrix of nibbles by a constant matrix,

        8  12 7  7

        12 7  7  8

        7  7  8  12

        7  8  12 7
    """
    def multiply_matrix(ns):
        assert len(ns) == 4
        n0, n1, n2, n3 = ns
        return [
            MULTI_8[n0] ^ MULTI_12[n1] ^ MULTI_7[n2] ^ MULTI_7[n3],
            MULTI_12[n0] ^ MULTI_7[n1] ^ MULTI_7[n2] ^ MULTI_8[n3],
            MULTI_7[n0] ^ MULTI_7[n1] ^ MULTI_8[n2] ^ MULTI_12[n3],
            MULTI_7[n0] ^ MULTI_8[n1] ^ MULTI_12[n2] ^ MULTI_7[n3],
        ]

    assert len(ns) == 12
    return [
        n
        for ms in chunks(ns, 4)
        for n in multiply_matrix(ms)
    ]

def key_addition(ks, ns):
    """
    ks -> List of round key nibbles
    ns -> List of nibbles

    XORS each nibble with its corresponding round key nibble.
    """
    assert len(ks) == len(ns)
    return [w ^ n for (w, n) in zip(ks, ns)]

def roundf(ks, ns, i):
    """
    ks -> List of key nibbles
    ns -> List of nibbles
    i -> Round number

    Round function of SomeCipher.

    This function operates by performing the following operations in order:
    1. KeyAddition (with ith round key)
    2. NibbleSub
    3. ShiftRow
    4. MixColumn (if not the last round)

    Note that this function does not handle the addition of the final round key.
    """
    assert len(ns) == 12
    ns = shift_row(nibble_sub(ns))
    if i != ROUNDS - 1:
        ns = mix_column(ns)
    return key_addition(ks, ns)

def inv_roundf(ks, ns, i):
    """
    ks -> List of key nibbles
    ns -> List of nibbles
    i -> Round number

    Inverse round function of SomeCipher. Refer to `roundf()` for more details.
    """
    assert len(ns) == 12
    ns = key_addition(ks, ns)
    if i != ROUNDS - 1:
        ns = inv_mix_column(ns)
    return inv_nibble_sub(inv_shift_row(ns))

def encrypt_block(k, p):
    """
    k -> Key
    p -> Plaintext

    Encrypts the plaintext block with SomeCipher, given the key.
    """
    assert len(k) == len(p) == 12
    ns = key_addition(k, p)
    for i in range(0, ROUNDS):
        ns = roundf(k, ns, i)
    return ns

def decrypt_block(k, c):
    """
    k -> Key
    c -> Ciphertext

    Decrypts the ciphertext block encrypted with SomeCipher, given the key.
    """
    assert len(k) == len(c) == 12
    ns = c
    for i in range(ROUNDS - 1, -1, -1):
        ns = inv_roundf(k, ns, i)
    return key_addition(k, ns)

# main function

def main():
    k = [random.randint(0, 15) for _ in range(12)]
    p = [random.randint(0, 15) for _ in range(12)]
    print("Key: {}".format(k))
    print("Plaintext: {}".format(p))

    c = encrypt_block(k, p)
    print("Ciphertext: {}".format(c))
    d = decrypt_block(k, c)
    print("Decrypted ciphertext: {}".format(d))

    if p == d:
        print("Decrypted ciphertext is the plaintext.")
    else:
        print("ERROR: Decrypted ciphertext does not match the plaintext.")

if __name__ == "__main__":
    main()


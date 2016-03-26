"""
Implementation of Mini AES.
"""

ROUNDS = 5

SBOX = [
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
]

INV_SBOX = [
    0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF,
    0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5
]

MULTI_2 = [
    0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE,
    0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD
]

MULTI_3 = [
    0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9,
    0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2
]

RCONS = [0x1, 0x2, 0x4, 0x8, 0x3]

# utility functions

def chunks(xs, n):
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

    Retrieves the preimage of the mapping of each nibble. The inverse mapping is
    specified in `INV_SBOX`.
    """
    return [INV_SBOX[n] for n in ns]

def shift_row(ns):
    """
    ns -> List of nibbles

    Shift each row of the matrix of nibbles to the left by different amounts.

    The first row is unchanged while the second row is shifted by 1 element to
    the right.
    """
    assert len(ns) == 4
    n0, n1, n2, n3 = ns
    return [n0, n3, n2, n1]

def mix_column(ns):
    """
    ns -> List of nibbles

    Multiplies the matrix of nibbles by a constant matrix,

        3  2

        2  3
    """
    def multiply_matrix(ms):
        assert len(ms) == 2
        m0, m1 = ms
        return [
            MULTI_3[m0] ^ MULTI_2[m1],
            MULTI_2[m0] ^ MULTI_3[m1]
        ]

    assert len(ns) == 4
    return [
        n
        for ms in chunks(ns, 2)
        for n in multiply_matrix(ms)
    ]

def key_addition(ws, ns):
    """
    ws -> List of round key nibbles
    ns -> List of nibbles

    XORs each nibble with its corresponding round key nibble.
    """
    assert len(ws) == len(ns) == 4
    return [w ^ n for (w, n) in zip(ws, ns)]

def key_schedule(k):
    """
    k -> Key

    Generates round keys from a 16-bit key.

    The first round key is derived directly from the supplied key.
    """
    assert len(k) == 4
    wss = [[]] * (ROUNDS + 1)
    wss[0] = k
    for i in range(0, ROUNDS):
        ws = [0] * 4
        ws[0] = wss[i][0] ^ SBOX[wss[i][3]] ^ RCONS[i]
        ws[1] = wss[i][1] ^ ws[0]
        ws[2] = wss[i][2] ^ ws[1]
        ws[3] = wss[i][3] ^ ws[2]
        wss[i + 1] = ws
    return wss

# encryption & decryption

def roundf(ws, ns, i):
    """
    ws -> List of key nibbles
    ns -> List of nibbles
    i -> Round number

    Round function of Mini-AES.

    This function operates by performing the following operations in order:
    1. KeyAddition (with ith round key)
    2. NibbleSub
    3. ShiftRow
    4. MixColumn (if not the last round)

    Note that this function does not handle the addition of the final round key.
    """
    assert len(ns) == 4
    ns = shift_row(
        nibble_sub(
            key_addition(ws, ns)
        )
    )
    if i != ROUNDS - 1:
        ns = mix_column(ns)
    return ns

def inv_roundf(ws, ns, i):
    """
    ws -> List of key nibbles
    ns -> List of nibbles
    i -> Round number

    Inverse round function of Mini-AES. Refer to `roundf()` for more details.
    """
    assert len(ns) == 4
    if i != ROUNDS - 1:
        ns = mix_column(ns)
    ns = key_addition(ws,
        inv_nibble_sub(
            shift_row(ns)
        )
    )
    return ns

def encrypt_block(k, p):
    """
    k -> Key
    p -> Plaintext

    Encrypts the plaintext block with Mini-AES, given the key.
    """
    assert len(k) == len(p) == 4
    wss = key_schedule(k)
    assert len(wss) == ROUNDS + 1

    ns = p
    for i in range(0, ROUNDS):
        ns = roundf(wss[i], ns, i)
    ns = key_addition(wss[ROUNDS], ns)
    return ns

def decrypt_block(k, c):
    """
    k -> Key
    c -> Ciphertext

    Decrypts the ciphertext block encrypted with Mini-AES, given the key.
    """
    assert len(k) == len(c) == 4
    wss = key_schedule(k)
    assert len(wss) == ROUNDS + 1

    ns = key_addition(wss[ROUNDS], c)
    for i in range(ROUNDS - 1, -1, -1):
        ns = inv_roundf(wss[i], ns, i)
    return ns

# main function

def main():
    import random
    k = [random.randint(0, 15) for _ in range(4)]
    p = [random.randint(0, 15) for _ in range(4)]
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

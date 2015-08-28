"""
Implementation of SomeCipher.
"""

ROUNDS = 8

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

# procedures

def nibble_sub(ns):
    """
    ns -> List of nibbles

    Passes each nibble through a S-Box. Refer to `SBOX` for the mapping of the
    nibbles.
    """
    return [SBOX[n] for n in ns]

def inv_nibble_sub(ns):
    """
    ns -> List of nibbles

    Retrieves the preimage of the mapping of each nibble. Refer to `INV_SBOX`
    for the inverse mapping of the nibbles
    """
    return [INV_SBOX[n] for n in ns]

def shift_row(ns):
    """
    ns -> List of nibbles

    Shift each row of the matrix of nibbles to the left by different amounts.

    The first and second row is unchanged, while the third and fourth row are
    rotated by 1 and 2 elements to the right respectively.
    """
    assert len(ns) == 12
    n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11 = ns
    return [n0, n1, n10, n7, n4, n5, n2, n11, n8, n9, n6, n3]

def mix_column(ns):
    """
    ns -> List of nibbles

    Multiplies the matrix of nibbles by a constant matrix.
    """


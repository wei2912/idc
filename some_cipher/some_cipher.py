"""
Implementation of SomeCipher. The spec is listed in the report.
"""

import pytest
from pytest import list_of

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

    Passes each nibble through a S-Box. The mapping is as follows (in binary):

    0000 -> 1110
    0001 -> 0100
    0010 -> 1101
    0011 -> 0001
    0100 -> 0010
    0101 -> 1111
    0110 -> 1011
    0111 -> 1000
    1000 -> 0011
    1001 -> 1010
    1010 -> 0110
    1011 -> 1100
    1100 -> 0101
    1101 -> 1001
    1110 -> 0000
    1111 -> 0111
    """
    return [SBOX[n] for n in ns]

def inv_nibble_sub(ns):
    """
    ns -> List of nibbles

    Retrieves the preimage of the mapping of each nibble. Refer to
    `nibble_sub()` for more details.
    """
    return [INV_SBOX[n] for n in ns]

@pytest.mark.randomize(
    ns=list_of(int),
    min_num=0,
    max_num=15
)
def test_nibble_sub(ns):
    """
    Ensure that any list of nibbles, when passed through `nibble_sub` and
    `inv_nibble_sub`, returns the original list.
    """
    assert ns == inv_nibble_sub(nibble_sub(ns))

def shift_row(ns):
    """
    ns -> List of nibbles

    Shift each row of the matrix of nibbles to the left by different amounts.

    For example, given the list of nibbles, `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11, 12]`, they will be arranged in a matrix layout,

        0  4  8

        1  5  9

        2  6  10

        3  7  11

    from top to down, left to right.

    The first and second row is unchanged while the third and fourth row are
    rotated by 1 and 2 elements to the right respectively. This gives the
    resulting matrix:

        0  4  8

        1  5  9

        10 2  6

        7  11 3

    or, in the form of a list, `[0, 1, 10, 7, 4, 5, 2, 11, 8, 9, 6, 3]`.
    """
    assert len(ns) == 12
    n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11 = ns
    return [n0, n1, n10, n7, n4, n5, n2, n11, n8, n9, n6, n3]


"""
Test suite for the `mini_aes` module.
"""

import pytest
from pytest import list_of

import mini_aes

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
    assert ns == mini_aes.inv_nibble_sub(mini_aes.nibble_sub(ns))

@pytest.mark.randomize(
    n0=int,
    n1=int,
    n2=int,
    n3=int,
    min_num=0,
    max_num=15
)
def test_shift_row(n0, n1, n2, n3):
    """
    Ensure that `shift_row` interchanges the second and fourth nibble.
    """
    assert mini_aes.shift_row([n0, n1, n2, n3]) == [n0, n3, n2, n1]

@pytest.mark.randomize(
    ns=[int, int, int, int],
    min_num=0,
    max_num=15
)
def test_mix_column(ns):
    """
    Ensure that `mix_column` is its own inverse.
    """
    assert ns == mini_aes.mix_column(mini_aes.mix_column(ns))

@pytest.mark.randomize(
    k=[int, int, int, int],
    p=[int, int, int, int],
    min_num=0,
    max_num=15
)
def test_encrypt_decrypt(k, p):
    """
    Make sure that decrypting an encrypted message returns the same plaintext.
    """
    assert p == mini_aes.decrypt_block(k, mini_aes.encrypt_block(k, p))


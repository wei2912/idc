"""
Test suite for the `some_cipher` module.
"""

import pytest
from pytest import list_of

import some_cipher

@pytest.mark.randomize(
    ns=list_of(int),
    min_num=0,
    max_num=15
)
def test_nibble_sub(ns):
    # Ensure that `inv_nibble_sub` is inverse of `nibble_sub`.
    assert ns == some_cipher.inv_nibble_sub(some_cipher.nibble_sub(ns))

@pytest.mark.randomize(
    ns=list_of(int, items=12),
    min_num=0,
    max_num=15
)
def test_shift_row(ns):
    # Ensure that `inv_shift_row` is inverse of `shift_row`.
    assert ns == some_cipher.inv_shift_row(some_cipher.shift_row(ns))

@pytest.mark.randomize(
    ns=list_of(int, items=12),
    min_num=0,
    max_num=15
)
def test_mix_column(ns):
    # Ensure that `inv_mix_column` is inverse of `mix_column`.
    assert ns == some_cipher.inv_mix_column(some_cipher.mix_column(ns))

@pytest.mark.randomize(
    k=list_of(int, items=12),
    p=list_of(int, items=12),
    min_num=0,
    max_num=15
)
def test_encrypt_decrypt(k, p):
    # Make sure that decrypting an encrypted message returns the same plaintext.
    assert p == some_cipher.decrypt_block(k, some_cipher.encrypt_block(k, p))


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
    """
    Ensure that any list of nibbles, when passed through `nibble_sub` and
    `inv_nibble_sub`, returns the original list.
    """
    assert ns == some_cipher.inv_nibble_sub(some_cipher.nibble_sub(ns))


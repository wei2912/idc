"""
Test suite for the `generate_ids` module.
"""

import pytest
from pytest import list_of

import generate_ids

@pytest.mark.randomize(
    x=int,
    min_num=0,
    max_num=4095
)
def test_convert(x):
    # Ensure that list of states has 12 elements.
    ns = generate_ids.convert_int(x)
    assert len(ns) == 12
    # Ensure that `convert_int` is inverse of `convert_states`.
    assert x == generate_ids.convert_states(ns)


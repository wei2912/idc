"""
Test suite for the `gen_graph` module.
"""

import pytest
from pytest import list_of

import gen_graph

@pytest.mark.randomize(
    x=int,
    min_num=0,
    max_num=4095
)
def test_convert(x):
    # Ensure that list of states has 12 elements.
    ns = gen_graph.convert_int(x)
    assert len(ns) == 12
    # Ensure that `convert_int` is inverse of `convert_states`.
    assert x == gen_graph.convert_states(ns)


"""
Given a list of impossible differentials, create a 2-round backward extension
and try to find a distinguisher that works well for launching attacks.
"""

from ast import literal_eval
import math
import sys

import networkx as nx

import gen_graph

def propagate(g, v0, rounds):
    """
    g -> Graph of states of nibbles
    v0 -> Current state
    rounds -> Number of rounds to propagate by
    cutoff -> Cutoff weight for a branch

    Propagate from the current state by a few rounds. Returns a list of tuples
    containing:
    1. the path
    2. negated logarithmic probability of taking that route
    """

    ps = [([v0], 0)]
    for i in range(rounds):
        n_ps = []
        for p0, w0 in ps:
            v0 = p0[-1]
            for v1 in g[v0]:
                w1 = g[v0][v1]['weight']
                n_ps.append((p0 + [v1], w0 + w1))
        ps = n_ps
    return ps

def main():
    if not (len(sys.argv) == 3 and sys.argv[1] in ["forward", "backward"]):
        print("usage: ./find_ext.py [forward/backward] [differentials file]", file=sys.stderr)
        sys.exit(1)

    direction = sys.argv[1]
    if direction == "forward":
        g = nx.read_gpickle("rev_forward.gpickle")
    else:
        g = nx.read_gpickle("rev_backward.gpickle")

    with open(sys.argv[2]) as f:
        for start, _ in map(literal_eval, f):
            rounds = 1
            for p, w in propagate(g, start, rounds):
                print((start, p, w))

if __name__ == "__main__":
    main()


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

    Propagate from the current state by a few rounds. Returns a list of list of tuples, each list indicating a path.
    """

    ps = [[]]
    for i in range(rounds):
        n_ps = []
        for p0 in ps:
            if not i == 0:
                v0, _ = p0[-1]

            for v1 in g[v0]:
                w1 = g[v0][v1]['weight']
                n_ps.append(p0 + [(v1, w1)])
        ps = n_ps
    return ps

def main():
    if not (len(sys.argv) == 3 and sys.argv[1] in ["forward", "backward"]):
        print("usage: {} [forward/backward] [differentials file]".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    direction = sys.argv[1]
    if direction == "forward":
        g = nx.read_gpickle("rev_forward.gpickle")
        rounds = 0
    elif direction == "backward":
        g = nx.read_gpickle("rev_backward.gpickle")
        rounds = 2

    with open(sys.argv[2]) as f:
        starts = set()
        for start, _ in map(literal_eval, f):
            starts.add(start)

        for start in starts:
            for p in propagate(g, start, rounds):
                print((start, p))

if __name__ == "__main__":
    main()


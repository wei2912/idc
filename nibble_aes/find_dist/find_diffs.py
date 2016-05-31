"""
Derive a list of forward and backward differentials.
"""

import sys

import networkx as nx

def find_diff(g, start):
    """
    g -> Graph of states of nibbles
    start -> Starting configuration

    Find all possible differentials given a start configuration. The function
    returns a tuple containing:
    1. the number of rounds
    2. a list of all possible end states (second-last round)
    3. a list of all possible end states (last round)
    """
    vs = set([start])
    states = [vs]
    rounds = 0

    is_end = False
    while len(vs) > 0 and not is_end:
        n_vs = set()
        for v0 in vs:
            for v1 in g[v0]:
                if v1 == 65535:
                    is_end = True
                n_vs.add(v1)

        vs = n_vs
        states.append(vs)
        rounds += 1

    return (rounds, states)

def main(direction):
    # we do not consider 0 and 65535
    for i in range(1, 65535):
        rounds, states = find_diff(GRAPH, i)
        if rounds == 2:
            # retain up till last state of forward differential
            if direction == "forward":
                print((i, states[-1]))
            # but only retain till 2nd last state of backward differential
            elif direction == "backward":
                print((i, states[-2]))

if len(sys.argv) != 2:
    print("usage: ./find_diffs.py [forward/backward]", file=sys.stderr)
    sys.exit(1)

direction = sys.argv[1]
if direction == "forward":
    GRAPH = nx.read_gpickle("forward.gpickle")
elif direction == "backward":
    GRAPH = nx.read_gpickle("backward.gpickle")
else:
    print("Error: Invalid direction specified (forward/backward).")
    sys.exit(1)

main(direction)

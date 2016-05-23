"""
Derive a list of forward and backward differentials.
"""

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

def main():
    forward_g = nx.read_gpickle("forward.gpickle")
    forward_diffs = [0] * 65536
    for start in range(65536):
        rounds, states = find_diff(forward_g, start)
        print("F{} ({}) {}".format(start, rounds, states))

    backward_g = nx.read_gpickle("backward.gpickle")
    backward_diffs = [0] * 65536
    for start in range(65536):
        rounds, states = find_diff(backward_g, start)
        print("B{} ({}) {}".format(start, rounds, states))

if __name__ == "__main__":
    main()

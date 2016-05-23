"""
Derive a list of forward and backward differentials.
"""

from multiprocessing import Pool
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

def main():
    if len(sys.argv) != 2:
        print("Error: Direction not stated (forward/backward).")
        sys.exit(1)

    direction = sys.argv[1]
    if direction == "forward":
        g = nx.read_gpickle("forward.gpickle")
    elif direction == "backward":
        g = nx.read_gpickle("backward.gpickle")

    def f(i):
        rounds, states = find_diff(g, i)
        if rounds >= 2:
            print((i, rounds, states))

    pool = multiprocessing.Pool()
    pool.map(f, range(65536))
    pool.close()

if __name__ == "__main__":
    main()

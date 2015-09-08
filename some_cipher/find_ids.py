"""
Derive a list of impossible differentials.
"""

import argparse
import math

import networkx as nx

import gen_graph

def find_diff(g, start):
    """
    g -> Graph of states of nibbles
    start -> Starting configuration
    truncate -> Boolean indicating whether to truncate the final round or not.

    Find all possible differentials given a start configuration. The function
    returns a tuple containing:
    1. the number of rounds
    2. a list of all possible end states (truncating the final round)
    3. a list of all possible end states (including the final round)
    """
    cycles = set(nx.find_cycle(g))

    ps = [[start]]
    rounds = 0
    isEnd = False
    while len(ps) > 0 and not isEnd:
        n_ps = []
        for p in ps:
            v0 = p[-1]
            for v1 in g[v0]:
                if (v0, v1) in cycles or v1 == 4095:
                    isEnd = True
                n_ps.append(p + [v1])
        ps = n_ps
        rounds += 1

    second_last_states = set()
    last_states = set()
    for p in ps:
        second_last_states.add(p[-2])
        last_states.add(p[-1])
    return (rounds, second_last_states, last_states)

def main():
    forward_g = nx.read_gpickle("forward.gpickle")
    backward_g = nx.read_gpickle("backward.gpickle")

    forward_diffs = []
    backward_diffs = []
    for start in range(4096):
        forward_diffs.append(find_diff(forward_g, start))
        backward_diffs.append(find_diff(backward_g, start))

    # the forward differential progresses all the way
    # while the backward differential has a truncated final round
    for i in range(4096):
        forward_rounds, _, xs = forward_diffs[i]
        for j in range(4096):
            backward_rounds, ys, _ = backward_diffs[j]
            if not (forward_rounds == backward_rounds == 2):
                continue

            if xs.intersection(ys) == set():
                print("No. of rounds: 3")
                print("Start: {}".format(gen_graph.convert_int(i)))
                print("End: {}".format(gen_graph.convert_int(j)))
                print("---")

if __name__ == "__main__":
    main()


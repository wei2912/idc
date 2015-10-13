"""
Derive a list of impossible differentials.
"""

import pickle

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
    cycles = set(nx.find_cycle(g))

    vs = set([start])
    states = [vs]
    rounds = 0

    isEnd = False
    while len(vs) > 0 and not isEnd:
        n_vs = set()
        for v0 in vs:
            for v1 in g[v0]:
                if (v0, v1) in cycles or v1 == 4095:
                    isEnd = True
                n_vs.add(v1)

        vs = n_vs
        states.append(vs)
        rounds += 1

    return (rounds, states)

def main():
    forward_g = nx.read_gpickle("forward.gpickle")
    backward_g = nx.read_gpickle("backward.gpickle")

    forward_diffs = []
    backward_diffs = []
    for start in range(4096):
        forward_diffs.append(find_diff(forward_g, start))
        backward_diffs.append(find_diff(backward_g, start))

    ids = []
    for i in range(4096):
        forward_rounds, xss = forward_diffs[i]
        for j in range(4096):
            backward_rounds, yss = backward_diffs[j]

            # truncate first round of backward differential
            # by comparing last round of forward differential and second last
            # round of backward differential
            if xss[-1].intersection(yss[-2]) == set():
                backward_rounds -= 1
                if forward_rounds + backward_rounds < 3:
                    continue
                ids.append((i, forward_rounds, backward_rounds, j))
    print("Found {} impossible differentials.".format(len(ids)))
    with open("ids.pickle", "wb") as f:
        pickle.dump(ids, f)

if __name__ == "__main__":
    main()


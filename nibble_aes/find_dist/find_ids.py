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

    is_end = False
    while len(vs) > 0 and not is_end:
        n_vs = set()
        for v0 in vs:
            for v1 in g[v0]:
                if (v0, v1) in cycles or v1 == 4095:
                    is_end = True
                n_vs.add(v1)

        vs = n_vs
        states.append(vs)
        rounds += 1

    return (rounds, states)

def main():
    forward_g = nx.read_gpickle("forward.gpickle")
    backward_g = nx.read_gpickle("backward.gpickle")

    ids = []
    max_rounds = 0
    for i in range(65536):
        forward_rounds, xss = find_diff(forward_g, i)
        for j in range(65536):
            backward_rounds, yss = find_diff(backward_g, j)

            # truncate first round of backward differential
            # by comparing last round of forward differential and second last
            # round of backward differential
            if xss[-1].intersection(yss[-2]) == set():
                backward_rounds -= 1
                rounds = forward_rounds + backward_rounds

                if rounds < max_rounds:
                    continue
                elif rounds > max_rounds:
                    ids = []
                    max_rounds = rounds
                    print("Found impossible differential of {} rounds.".format(
                        max_rounds
                    )) # should hit at least 5, which was the longest previously
                       # found

                ids.append((i, forward_rounds, backward_rounds, j))
                print(len(ids))

    with open("ids.pickle", "wb") as f:
        pickle.dump(ids, f)

if __name__ == "__main__":
    main()

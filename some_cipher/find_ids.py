"""
Derive a list of impossible differentials.
"""

import pickle

import networkx as nx

import gen_graph

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

    ids = []
    for i in range(4096):
        for j in range(4096):
            forward_rounds, xs0, xs1 = forward_diffs[i]
            backward_rounds, ys0, ys1 = backward_diffs[j]

            # truncating last round of forward differential
            if xs0.intersection(ys1) == set():
                forward_rounds -= 1
            # truncating first round of backward differential
            elif xs1.intersection(ys0) == set():
                backward_rounds -= 1
            else: # not an impossible differential
                continue

            if forward_rounds + backward_rounds < 3:
                continue
            ids.append((i, forward_rounds, backward_rounds, j, 1))
    print("Found {} impossible differentials.".format(len(ids)))
    with open("ids.pickle", "wb") as f:
        pickle.dump(ids, f)

if __name__ == "__main__":
    main()


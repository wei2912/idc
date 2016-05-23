"""
Derive a list of impossible differentials.
"""

from multiprocessing import Process, Queue
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
    forward_diffs = [0] * 65536
    for start in range(65536):
        forward_diffs[start] = find_diff(forward_g, start)

    backward_g = nx.read_gpickle("backward.gpickle")
    backward_diffs = [0] * 65536
    for start in range(65536):
        backward_diffs[start] = find_diff(backward_g, start)

    def f(i, qu):
        forward_rounds, xss = forward_diffs[i]
        for j in range(65536):
            backward_rounds, yss = backward_diffs[j]

            # truncate first round of backward differential
            # by comparing last round of forward differential and second last
            # round of backward differential
            if xss[-1].intersection(yss[-2]) == set():
                backward_rounds -= 1
                rounds = forward_rounds + backward_rounds

                if rounds >= 4:
                    qu.put((i, forward_rounds, backward_rounds, j))

    qu = Queue()
    ps = [Process(target=f, args=(i, qu)) for i in range(65536)]

    for p in ps:
        p.start()
    for p in ps:
        p.join()
    ids = [qu.get() for p in ps]

    with open("ids.pickle", "wb") as f:
        pickle.dump(ids, f)

if __name__ == "__main__":
    main()

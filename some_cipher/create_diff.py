"""
Given a list of impossible differentials, propagate in both directions by a few
rounds and try to find a differential that works well for launching attacks.
"""

import math
import pickle

import networkx as nx

import gen_graph

def count(x):
    """
    Count the number of active nibbles in a state.
    """
    return sum(gen_graph.convert_int(x))

def propagate(g, start, rounds):
    """
    g -> Graph of states of nibbles
    start -> Starting configuration

    Propagate from the start by a few rounds. Returns a list of tuples
    containing:
    1. the number of rounds
    2. end
    3. negated logarithmic probability of taking that route
    """
    ps = [([start], 0)]
    for _ in range(rounds):
        n_ps = []
        for p, w0 in ps:
            v0 = p[-1]
            for v1 in g[v0]:
                w1 = g[v0][v1]['weight']
                n_ps.append((p + [v1], w0 + w1))
        ps = n_ps
    return ps

def main():
    rev_forward_g = nx.read_gpickle("rev_forward.gpickle")
    rev_backward_g = nx.read_gpickle("rev_backward.gpickle")
    with open("ids.pickle", "rb") as f:
        ids = pickle.load(f)

    for start, forward_rounds, backward_rounds, end in ids:
        def f(p, w, B=32):
            s = count(start)
            t = count(p[-1])
            if 8*s + 4*t - 49 >= w / math.log(2):
                if 4*t <= B:
                    return True
                else:
                    return (8*s - 49) * math.log(2) - w >= math.log(4*t - B) + math.log(math.log(2))

        # backward extension
        ps = propagate(rev_forward_g, end, 1)

        for p, w in filter(lambda t: f(*t, B=32), ps):
            print("{} X {} <- {} with probability {}".format(
                start,
                end,
                " <- ".join(str(v) for v in p[1:]),
                math.exp(-w)
            ))

if __name__ == "__main__":
    main()


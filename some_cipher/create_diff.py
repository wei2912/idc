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

def propagate(g, start, rounds, cutoff=None):
    """
    g -> Graph of states of nibbles
    start -> Starting configuration

    Propagate from the start by a few rounds. Returns a list of tuples
    containing:
    1. the number of rounds
    2. end
    3. negated logarithmic probability of taking that route
    """
    if rounds == 0:
        yield ([start], 0)
        return

    v0 = start
    for v1 in g[v0]:
        w0 = g[v0][v1]['weight']
        for p, w1 in propagate(g, v1, rounds - 1, cutoff=cutoff):
            if cutoff is not None and w0 + w1 >= cutoff:
                continue
            yield ([v0] + p, w0 + w1)

def main():
    rev_forward_g = nx.read_gpickle("rev_forward.gpickle")
    rev_backward_g = nx.read_gpickle("rev_backward.gpickle")
    with open("ids.pickle", "rb") as f:
        ids = pickle.load(f)

    for start, forward_rounds, backward_rounds, end in ids:
        def f(p, w, B=32):
            s = count(start)
            t = count(p[-1])
            if 4*t <= B:
                return w <= (8*s + 4*t - 49) * math.log(2)
            else:
                return w <= (8*s - 49) * math.log(2) + min(4*t*math.log(2), -math.log(4*t - B) - math.log(math.log(2)))

        # backward extension
        s = count(start)
        for p, w in filter(
            lambda t: f(*t, B=32),
            propagate(
                rev_backward_g,
                end,
                1,
                cutoff=(8*s - 1) * math.log(2) # based on formula
            )
        ):
            print("{} X {} <- {} with probability {}".format(
                start,
                end,
                " <- ".join(str(v) for v in p[1:]),
                math.exp(-w)
            ))

if __name__ == "__main__":
    main()


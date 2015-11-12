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
        # filter by number of start nibbles
        s = count(start)
        if s > 4:
            continue

        def f(p, w):
            s = count(start)
            t = count(p[-1])

            # filter by number of end nibbles
            if t < 7:
                return False

            # filter by number of wrong key guesses
            B = 28
            if 4*t <= B:
                return w <= (8*s + 4*t - 49) * math.log(2)
            else:
                return w <= (8*s - 49) * math.log(2) + min(4*t*math.log(2), -math.log(4*t - B) - math.log(math.log(2)))

        # backward extension
        backward_extension_rounds = 1
        rounds = forward_rounds + backward_rounds + backward_extension_rounds
        for p, w in filter(
            lambda t: f(*t),
            propagate(
                rev_backward_g,
                end,
                backward_extension_rounds,
                cutoff=(8*s - 1) * math.log(2) # based on formula
            )
        ):
            print("{} ... X ... {} <- {} with probability {}, {} rounds".format(
                start,
                end,
                " <- ".join(str(v) for v in p[1:]),
                math.exp(-w),
                rounds
            ))

if __name__ == "__main__":
    main()


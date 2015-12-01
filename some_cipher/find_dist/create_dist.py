"""
Given a list of impossible differentials, create a 2-round backward extension
and try to find a distinguisher that works well for launching attacks.
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

def propagate(g, v0, rounds, cutoff):
    """
    g -> Graph of states of nibbles
    v0 -> Current state
    rounds -> Number of rounds to propagate by
    cutoff -> Cutoff weight.

    Propagate from the current state by a few rounds. Returns a list of tuples
    containing:
    1. the path
    2. negated logarithmic probability of taking that route
    """
    if rounds == 0:
        t = count(v0)
        if t >= 7:
            yield ([v0], 0)
        return

    for v1 in g[v0]:
        w0 = g[v0][v1]['weight']
        if w0 >= cutoff:
            continue
        for p, w1 in propagate(g, v1, rounds - 1, cutoff=cutoff):
            if w0 + w1 >= cutoff:
                continue
            yield ([v0] + p, w0 + w1)

def add_last_round(ts):
    for p, w in ts:
        p += [gen_graph.convert_states(
            gen_graph.last_roundf(
                gen_graph.convert_int(p[-1])
            )
        )]
        yield (p, w)

def main():
    rev_forward_g = nx.read_gpickle("rev_forward.gpickle")
    rev_backward_g = nx.read_gpickle("rev_backward.gpickle")
    with open("ids.pickle", "rb") as f:
        ids = pickle.load(f)

    dists = []
    for start, forward_rounds, backward_rounds, end in ids:
        # filter by number of start nibbles
        s = count(start)
        if s > 5:
            continue

        # backward extension
        backward_extension_rounds = 3
        rounds = forward_rounds + backward_rounds + backward_extension_rounds
        for p, w in add_last_round(
            propagate(
                rev_backward_g,
                end,
                backward_extension_rounds - 1,
                (8*s - 21) * math.log(2) # based on formula, assuming t >= 7
            )
        ):
            dists.append((start, p, w, rounds))

    best_w = min(w for _, _, w, _ in dists)
    dists = list(filter(lambda t: t[2] == best_w, dists))

    for start, p, w, rounds in dists:
        print("{} ... X ... {} with probability {}, {} rounds".format(
            start,
            " <- ".join(str(v) for v in p),
            math.exp(-w),
            rounds
        ))

    with open("dists.pickle", "wb") as f:
        pickle.dump(dists, f)

if __name__ == "__main__":
    main()


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
    cutoff -> Cutoff weight for a branch

    Propagate from the current state by a few rounds. Returns a list of tuples
    containing:
    1. the path
    2. negated logarithmic probability of taking that route
    """

    ps = [([v0], 0)]
    for i in range(rounds):
        n_ps = []
        for p0, w0 in ps:
            if w0 > cutoff:
                continue

            v0 = p0[-1]
            for v1 in g[v0]:
                w1 = g[v0][v1]['weight']
                if w0 + w1 > cutoff:
                    continue

                # if last round, we can update the cutoff and check for required t
                if i == rounds - 1:
                    t = count(v1)
                    if not 7 <= t <= 9:
                        continue

                    if w0 + w1 < cutoff:
                        cutoff = w0 + w1
                        n_ps = []

                n_ps.append((p0 + [v1], w0 + w1))
        ps = n_ps
    return (cutoff, ps)

def add_last_round(p):
    return p + [gen_graph.convert_states(
        gen_graph.last_roundf(
            gen_graph.convert_int(p[-1])
        )
    )]

def main():
    rev_forward_g = nx.read_gpickle("rev_forward.gpickle")
    rev_backward_g = nx.read_gpickle("rev_backward.gpickle")
    with open("ids.pickle", "rb") as f:
        ids = pickle.load(f)

    cutoff = 12
    dists = []
    for start, forward_rounds, backward_rounds, end in ids:
        s = count(start)
        if not 4 <= s <= 6:
            continue

        # backward extension
        backward_extension_rounds = 3
        rounds = forward_rounds + backward_rounds + backward_extension_rounds

        n_cutoff, ps = propagate(
            rev_backward_g,
            end,
            backward_extension_rounds - 1,
            cutoff
        )

        if n_cutoff < cutoff:
            cutoff = n_cutoff
            dists = []

        for p, w in ps:
            p = add_last_round(p)
            dists.append((start, p, w, rounds))

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


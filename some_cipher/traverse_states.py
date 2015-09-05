"""
Generate a directed graph of changes in states of nibbles in SomeCipher.
"""

import math

import networkx as nx

# utility functions

def chunks(xs, n):
    """
    xs -> List of elements.
    n -> Length of chunk.

    Divide a list of elements into chunks of length `n`.
    """
    for i in range(0, len(xs), n):
        yield xs[i:i+n]

def convert_states(ns):
    """
    ns -> States of nibbles

    Convert the states of nibbles to an integer.
    """
    x = 0
    for n in ns:
        x = (x << 1) | n
    return x

def convert_int(x):
    """
    x -> Integer representing state.

    Convert the integer into states of nibbles.
    """
    assert 0 <= x <= 4096
    ns = []
    while x != 0:
        if x % 2 == 0:
            ns.append(0)
        else:
            ns.append(1)
        x //= 2
    return [0] * (12 - len(ns)) + list(reversed(ns))

# procedures

def shift_row(ns):
    """
    ns -> States of nibbles

    Predict the states of nibbles after passing through ShiftRow in SomeCipher.
    """
    assert len(ns) == 12
    n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11 = ns
    return [n0, n1, n10, n7, n4, n5, n2, n11, n8, n9, n6, n3]

def mix_column(ns):
    """
    ns -> States of nibbles

    Predict the states of nibbles after passing through MixColumn in SomeCipher.

    Note that since multiple states may occur with different probabilities, a
    list of possible states along with their approximate probabilities is
    returned.

    To prevent float underflow, the probabilities are expressed in a
    logarithmic form.
    The weights are recorded as positive instead of negative. This means that
    the higher the weight, the lower the probability.
    """
    def multiply_matrix(ms):
        assert len(ms) == 4

        count = 0
        for m in ms:
            if m == 1:
                count += 1

        if count == 0:
            return [([0, 0, 0, 0], 0)]
        elif count == 1:
            return [([1, 1, 1, 1], 0)]
        elif count == 2:
            return [
                ([0, 1, 1, 1], 4 * math.log(2)),
                ([1, 0, 1, 1], 4 * math.log(2)),
                ([1, 1, 0, 1], 4 * math.log(2)),
                ([1, 1, 1, 0], 4 * math.log(2)),

                ([1, 1, 1, 1], math.log(4) - math.log(3))
            ]
        elif count == 3:
            return [
                ([0, 0, 1, 1], 8 * math.log(2)),
                ([0, 1, 0, 1], 8 * math.log(2)),
                ([0, 1, 1, 0], 8 * math.log(2)),
                ([1, 0, 0, 1], 8 * math.log(2)),
                ([1, 0, 1, 0], 8 * math.log(2)),
                ([1, 1, 0, 0], 8 * math.log(2)),

                ([0, 1, 1, 1], 4 * math.log(2)),
                ([1, 0, 1, 1], 4 * math.log(2)),
                ([1, 1, 0, 1], 4 * math.log(2)),
                ([1, 1, 1, 0], 4 * math.log(2)),

                ([1, 1, 1, 1], math.log(128) - math.log(93))
            ]
        elif count == 4:
            return [
                ([0, 0, 0, 1], 12 * math.log(2)),
                ([0, 0, 1, 0], 12 * math.log(2)),
                ([0, 1, 0, 0], 12 * math.log(2)),
                ([1, 0, 0, 0], 12 * math.log(2)),

                ([0, 0, 1, 1], 8 * math.log(2)),
                ([0, 1, 0, 1], 8 * math.log(2)),
                ([0, 1, 1, 0], 8 * math.log(2)),
                ([1, 0, 0, 1], 8 * math.log(2)),
                ([1, 0, 1, 0], 8 * math.log(2)),
                ([1, 1, 0, 0], 8 * math.log(2)),

                ([0, 1, 1, 1], 4 * math.log(2)),
                ([1, 0, 1, 1], 4 * math.log(2)),
                ([1, 1, 0, 1], 4 * math.log(2)),
                ([1, 1, 1, 0], 4 * math.log(2)),

                ([1, 1, 1, 1], math.log(1024) - math.log(743))
            ]

    def join(states):
        s0, s1, s2 = states
        return [
            (x + y + z, px + py + pz)
            for x, px in s0
            for y, py in s1
            for z, pz in s2
        ]

    assert len(ns) == 12
    return join([
        multiply_matrix(ms)
        for ms in chunks(ns, 4)
    ])

def roundf(ns):
    """
    ns -> States of nibbles

    Predict the states of nibbles after passing through a round of SomeCipher.

    Each state will have a weight attached to it. The higher the weight, the
    lower the probability.
    """
    ns = shift_row(ns)
    return mix_column(ns)

def generate_graph():
    g = nx.DiGraph()
    g.add_nodes_from(range(4096))
    for x in range(4096):
        for ns, p in roundf(list(convert_int(x))):
            y = convert_states(ns)
            g.add_edge(x, y, weight=p)
    return g

def find_ids(g):
    """
    g -> Graph of states of nibbles

    Find all paths that are impossible differentials.
    """
    ps = [[x] for x in range(4096)]
    while len(ps) > 0:
        n_ps = []
        for p in ps:
            v0 = p[-1]
            for v1 in g[v0]:
                if v0 == v1: # skip cycles
                    continue

                if g[v0][v1]['weight'] == 0:
                    p.append(v1)
                    if v1 == 4095:
                        yield p
                    else:
                        n_ps.append(p)
        ps = n_ps

def main():
    try:
        g = nx.read_gpickle("ids.gpickle")
    except FileNotFoundError:
        g = generate_graph()
        nx.write_gpickle(g, "ids.gpickle")

    for p in find_ids(g):
        for x in p:
            print(convert_int(x))
        print("---")

if __name__ == "__main__":
    main()


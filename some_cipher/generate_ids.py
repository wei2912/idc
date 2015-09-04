"""
Generate a directed graph of Impossible Differentials on SomeCipher.
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
    if x < 0 or x >= 4096:
        raise IndexError("integer out of range")
    if x == 0:
        return [0]
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
    returned. To prevent float underflow, the probabilities are expressed in a
    logarithmic form (with a base of 2 for convenience).
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
                ([0, 1, 1, 1], -4),
                ([1, 0, 1, 1], -4),
                ([1, 1, 0, 1], -4),
                ([1, 1, 1, 0], -4),

                ([1, 1, 1, 1], math.log(3) - 2)
            ]
        elif count == 3:
            return [
                ([0, 0, 1, 1], -8),
                ([0, 1, 0, 1], -8),
                ([0, 1, 1, 0], -8),
                ([1, 0, 0, 1], -8),
                ([1, 0, 1, 0], -8),
                ([1, 1, 0, 0], -8),

                ([0, 1, 1, 1], -4),
                ([1, 0, 1, 1], -4),
                ([1, 1, 0, 1], -4),
                ([1, 1, 1, 0], -4),

                ([1, 1, 1, 1], math.log(21) - 5)
            ]
        elif count == 4:
            return [
                ([0, 0, 0, 1], -12),
                ([0, 0, 1, 0], -12),
                ([0, 1, 0, 0], -12),
                ([1, 0, 0, 0], -12),

                ([0, 0, 1, 1], -8),
                ([0, 1, 0, 1], -8),
                ([0, 1, 1, 0], -8),
                ([1, 0, 0, 1], -8),
                ([1, 0, 1, 0], -8),
                ([1, 1, 0, 0], -8),

                ([0, 1, 1, 1], -4),
                ([1, 0, 1, 1], -4),
                ([1, 1, 0, 1], -4),
                ([1, 1, 1, 0], -4),

                ([1, 1, 1, 1], math.log(743) - 10)
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

    Each state will have a probability attached to it.
    """
    ns = shift_row(ns)
    return mix_column(ns)

def main():
    g = nx.DiGraph()
    # node 0 and 4095 are reserved.
    # 0 acts as the start point, 4095 acts as the end point.
    g.add_nodes_from(range(4096))
    g.add_edges_from([(0, n) for n in range(1, 4095)])
    g.add_edges_from([(n, 4095) for n in range(1, 4095)])

    for x in range(1, 4095):
        for ns, p in roundf(list(convert_int(x))):
            y = convert_states(ns)
            g.add_edge(x, y, weight=p)

    nx.write_gpickle(g, "ids.gpickle")

if __name__ == "__main__":
    main()


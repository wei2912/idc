"""
Generate a directed graph of changes in states of nibbles in SomeCipher.

To prevent float underflow, the probabilities are expressed in a logarithmic
form, using this formula:

    -log(p)

This ensures that the weights are positive and additive. Hence,the higher the
weight, the lower the probability.
"""

import array
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
    assert 0 <= x <= 65535
    ns = []
    while x != 0:
        if x % 2 == 0:
            ns.append(0)
        else:
            ns.append(1)
        x //= 2
    return [0] * (16 - len(ns)) + list(reversed(ns))

# procedures

def shift_row(ns):
    """
    ns -> States of nibbles

    Predict the states of nibbles after passing through ShiftRow in SomeCipher.
    """
    assert len(ns) == 16
    n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11, n12, n13, n14, n15 = ns
    return [n0, n5, n10, n15, n4, n9, n14, n3, n8, n13, n2, n7, n12, n1, n6, n11]

def inv_shift_row(ns):
    """
    ns -> States of nibbles

    Predict the states of nibbles after passing through InvShiftRow in
    SomeCipher.
    """
    assert len(ns) == 16
    n0, n5, n10, n15, n4, n9, n14, n3, n8, n13, n2, n7, n12, n1, n6, n11 = ns
    return [n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11, n12, n13, n14, n15]

def mix_column(ns):
    """
    ns -> States of nibbles

    Predict the states of nibbles after passing through MixColumn in SomeCipher.

    Note that since multiple states may occur with different probabilities, a
    list of possible states along with their weights is returned.
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
                ([0, 1, 1, 1], 16 * math.log(2) - 3 * math.log(15)),
                ([1, 0, 1, 1], 16 * math.log(2) - 3 * math.log(15)),
                ([1, 1, 0, 1], 16 * math.log(2) - 3 * math.log(15)),
                ([1, 1, 1, 0], 16 * math.log(2) - 3 * math.log(15)),

                ([1, 1, 1, 1], 14 * math.log(2) - math.log(13009))
            ]
        elif count == 3:
            return [
                ([0, 0, 1, 1], 16 * math.log(2) - 2 * math.log(15)),
                ([0, 1, 0, 1], 16 * math.log(2) - 2 * math.log(15)),
                ([0, 1, 1, 0], 16 * math.log(2) - 2 * math.log(15)),
                ([1, 0, 0, 1], 16 * math.log(2) - 2 * math.log(15)),
                ([1, 0, 1, 0], 16 * math.log(2) - 2 * math.log(15)),
                ([1, 1, 0, 0], 16 * math.log(2) - 2 * math.log(15)),

                ([0, 1, 1, 1], 16 * math.log(2) - 3 * math.log(15)),
                ([1, 0, 1, 1], 16 * math.log(2) - 3 * math.log(15)),
                ([1, 1, 0, 1], 16 * math.log(2) - 3 * math.log(15)),
                ([1, 1, 1, 0], 16 * math.log(2) - 3 * math.log(15)),

                ([1, 1, 1, 1], 15 * math.log(2) - math.log(25343))
            ]
        elif count == 4:
            return [
                ([0, 0, 0, 1], 16 * math.log(2) - math.log(15)),
                ([0, 0, 1, 0], 16 * math.log(2) - math.log(15)),
                ([0, 1, 0, 0], 16 * math.log(2) - math.log(15)),
                ([1, 0, 0, 0], 16 * math.log(2) - math.log(15)),

                ([0, 0, 1, 1], 16 * math.log(2) - 2 * math.log(15)),
                ([0, 1, 0, 1], 16 * math.log(2) - 2 * math.log(15)),
                ([0, 1, 1, 0], 16 * math.log(2) - 2 * math.log(15)),
                ([1, 0, 0, 1], 16 * math.log(2) - 2 * math.log(15)),
                ([1, 0, 1, 0], 16 * math.log(2) - 2 * math.log(15)),
                ([1, 1, 0, 0], 16 * math.log(2) - 2 * math.log(15)),

                ([0, 1, 1, 1], 16 * math.log(2) - 3 * math.log(15)),
                ([1, 0, 1, 1], 16 * math.log(2) - 3 * math.log(15)),
                ([1, 1, 0, 1], 16 * math.log(2) - 3 * math.log(15)),
                ([1, 1, 1, 0], 16 * math.log(2) - 3 * math.log(15)),

                ([1, 1, 1, 1], 15 * math.log(2) - math.log(25313))
            ]

    def join(states):
        s0, s1, s2, s3 = states
        return [
            (a + b + c + d, pa + pb + pc + pd)
            for a, pa in s0
            for b, pb in s1
            for c, pc in s2
            for d, pd in s3
        ]

    assert len(ns) == 16
    return join([
        multiply_matrix(ms)
        for ms in chunks(ns, 4)
    ])

def roundf(ns):
    """
    ns -> States of nibbles

    Predict the states of nibbles after passing through a round of SomeCipher.

    Note that since multiple states may occur with different probabilities, a
    list of possible states along with their weights is returned.
    """
    return mix_column(shift_row(ns))

def inv_roundf(ns):
    """
    ns -> States of nibbles

    Predict the states of nibbles after passing through an inverse round of
    SomeCipher. Refer to `roundf()` for more details.
    """
    return [(inv_shift_row(ms), weight) for ms, weight in mix_column(ns)]

def last_roundf(ns):
    """
    ns -> States of nibbles

    Predict the states of nibbles after passing through the last round of
    SomeCipher.
    """
    return shift_row(ns)

def inv_last_roundf(ns):
    """
    ns -> States of nibbles

    Predict the states of nibbles after passing through the inverse last round
    of SomeCipher. Refer to `last_roundf()` for more details.
    """
    return inv_shift_row(ns)

def main():
    forward_g = nx.DiGraph()
    forward_g.add_nodes_from(range(65536))
    for x in range(65536):
        for ns, w in roundf(convert_int(x)):
            y = convert_states(ns)
            forward_g.add_edge(x, y, weight=w)
    nx.write_gpickle(forward_g, "forward.gpickle")

    print("Generated forward.gpickle.")

    rev_forward_g = nx.DiGraph()
    rev_forward_g.add_nodes_from(range(65536))
    for x in range(65536):
        for ns, w in roundf(convert_int(x)):
            y = convert_states(ns)
            rev_forward_g.add_edge(y, x, weight=w)
    nx.write_gpickle(rev_forward_g, "rev_forward.gpickle")

    print("Generated rev_forward.gpickle.")

    backward_g = nx.DiGraph()
    backward_g.add_nodes_from(range(65536))
    for x in range(65536):
        for ns, w in inv_roundf(convert_int(x)):
            y = convert_states(ns)
            backward_g.add_edge(x, y, weight=w)
    nx.write_gpickle(backward_g, "backward.gpickle")

    print("Generated backward.gpickle.")

    rev_backward_g = nx.DiGraph()
    rev_backward_g.add_nodes_from(range(65536))
    for x in range(65536):
        for ns, w in inv_roundf(convert_int(x)):
            y = convert_states(ns)
            rev_backward_g.add_edge(y, x, weight=w)
    nx.write_gpickle(rev_backward_g, "rev_backward.gpickle")

    print("Generated rev_backward.gpickle.")

if __name__ == "__main__":
    main()

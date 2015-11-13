"""
Implementation of Impossible Differential Cryptanalysis on SomeCipher.
"""

import random

import some_cipher


def differences(ns0, ns1):
    assert len(ns0) == len(ns1)
    return [0 if ns0[i] == ns1[i] else 1 for i in range(len(ns0))]

def gen_pairs(f):
    """
    Given a list of plaintexts, return a generator of plaintext pairs which,
    when encrypted, give the required difference.
    """

    def gen_plaintexts():
        """
        Return a generator of plaintexts.
        """
        n0, n1, n2, n3, n4, n5, n7, n10 = tuple(random.randint(0, 15) for _ in range(8))
        ns = (
            (n6, n8, n9, n11)
            for n6 in range(0, 16)
            for n8 in range(0, 16)
            for n9 in range(0, 16)
            for n11 in range(0, 16)
        )
        for n6, n8, n9, n11 in ns:
            yield [n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11]

    ps = list(gen_plaintexts())
    for p0 in ps:
        c0 = f(p0)
        for p1 in ps:
            c1 = f(p1)
            if (differences(p0, p1) == [0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1] and
                differences(c0, c1) == [0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]):
                yield (p0, p1, c0, c1)

# main function

def main():
    k = [random.randint(0, 15) for _ in range(12)]
    print("Key: {}".format(k))

    wss = (
        (w5, w6, w7, w8, w9, w10, w11)
        for w5 in range(0, 16)
        for w6 in range(0, 16)
        for w7 in range(0, 16)
        for w8 in range(0, 16)
        for w9 in range(0, 16)
        for w10 in range(0, 16)
        for w11 in range(0, 16)
    )
    n_wss = []
    for p0, p1, c0, c1 in gen_pairs(lambda p: some_cipher.encrypt_block(k, p)):
        print((p0, p1, c0, c1))
        for ws in wss:
            w0, w1, w2, w3, w4 = tuple(random.randint(0, 15) for _ in range(5))
            w5, w6, w7, w8, w9, w10, w11 = ws
            k = [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11]

            d0 = some_cipher.inv_roundf(k, some_cipher.inv_roundf(k, c0, 4), 3)
            d1 = some_cipher.inv_roundf(k, some_cipher.inv_roundf(k, c1, 4), 3)

            if differences(d0, d1) == [0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1]:
                print("Key eliminated: {}".format(ws))
            else:
                n_wss.append(ws)
        wss = n_wss
        print("Number of remaining keys: {}".format(len(wss)))

    if (k[2], k[4], k[5], k[7], k[8], k[9], k[10]) in wss:
        print("Actual key is in the list of guesses.")
    else:
        print("ERROR: Actual key is not in the list of guesses.")

main()


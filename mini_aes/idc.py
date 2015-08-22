"""
Implementation of Impossible Differential Cryptanalysis on Mini AES.
"""

import random

import mini_aes

def gen_plaintexts():
    """
    Generate a list of plaintexts, which have a fixed random second and third
    nibble.
    """
    n1 = random.randint(0, 15)
    n2 = random.randint(0, 15)
    return [
        [n0, n1, n2, n3]
        for n0 in range(0, 8)
        for n3 in range(0, 8)
    ]

def differences(ns0, ns1):
    """
    ns0, ns1 -> list of nibbles to be compared

    Given two lists of nibbles and a list of booleans, return a list of booleans
    indicating if the nibbles in the position is different.
    """
    assert len(ns0) == len(ns1)
    return [
        True if ns0[i] == ns1[i] else False
        for i in range(len(ns0))
    ]

def gen_pairs(ps):
    """
    ps -> list of plaintexts

    Given a list of plaintexts, generate pairs of plaintexts which:
    1. are different in the first and fourth nibble
    2. are equal in the second and third nibble
    """
    return [
        (p0, p1)
        for p0 in ps
        for p1 in ps
        if differences(p0, p1) == [False, True, True, False]
    ]

def filter_plaintexts(f, ps):
    """
    f -> function to encrypt the plaintext
    ps -> list of pairs of plaintexts

    Filter out pairs of plaintexts which corresponding ciphertexts:
    1. are different in the first and fourth nibble
    2. are equal in the second and third nibble
    """
    ls = []
    for p0, p1 in ps:
        ds = differences(f(p0), f(p1))
        if (
            ds == [False, True, True, False] or
            ds == [True, False, False, True]
        ):
            ls.append((p0, p1))
    return ls

def guess_key(f, ps):
    """
    f -> function to pass the plaintext through the first round
    ps -> list of pairs of plaintexts

    Create a list of guesses for the first and fourth nibble of the key.
    """
    def is_guess_correct(w0, w3):
        for p0, p1 in ps:
            ws = [w0, 0, 0, w3]
            x0 = f(ws, p0)
            x1 = f(ws, p1)
            ds = differences(x0, x1)
            if (
                ds == [False, True, True, True] or
                ds == [True, False, True, True]
            ):
                return False
        return True

    return [
        (w0, w3)
        for w0 in range(16)
        for w3 in range(16)
        if is_guess_correct(w0, w3)
    ]

# main function

def main():
    k = [random.randint(0, 15) for _ in range(4)]
    print("Key: {}".format(k))

    ps = filter_plaintexts(
        lambda p: mini_aes.encrypt_block(k, p),
        gen_pairs(gen_plaintexts())
    )
    print("Number of plaintext pairs: {}".format(len(ps)))

    ws = guess_key(lambda ws, p: mini_aes.roundf(ws, p, 0), ps)
    print("Guesses for 1st and 4th nibble: {}".format(ws))
    print("Number of guesses remaining: {}".format(len(ws)))

main()


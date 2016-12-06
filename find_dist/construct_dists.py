from ast import literal_eval
import math
import sys

from list_dist_config import find_derived_nibbles

def last_round(end):
    bs = [end >> (11 - i) & 0x1 for i in range(12)]
    b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11 = bs
    bs = b0, b1, b10, b7, b4, b5, b2, b11, b8, b9, b6, b3
    return int("".join(str(b) for b in bs), 2)

def main():
    if not len(sys.argv) == 5:
        print("usage: {} \"(lambda_0, lambda_4_prime, lambda_6, w_4, w_5)\" [impossible differentials file] [forward extensions file] [backward extensions file]".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    tgt_lambda_0, tgt_lambda_4_prime, tgt_lambda_5, tgt_w_4, tgt_w_5 = literal_eval(sys.argv[1])

    backward_exts = {}
    with open(sys.argv[4]) as f:
        for state_3, pss in map(literal_eval, f):
            backward_exts[state_3] = []
            for ps in pss:
                state_4, w_4 = ps[0]
                state_5, w_5 = ps[1]
                if not (w_4 < tgt_w_4 and w_5 < tgt_w_5):
                    continue

                lambda_4 = bin(state_4).count("1")
                lambda_5 = bin(state_5).count("1")
                lambda_4_prime = lambda_4 - len(list(find_derived_nibbles(state_4, state_5)))

                if not (lambda_4_prime == tgt_lambda_4_prime and lambda_5 == tgt_lambda_5):
                    continue

                backward_exts[state_3].append(ps)

    dists = {}
    with open(sys.argv[2]) as f:
        for state_0, state_3 in map(literal_eval, f):
            if not state_3 in backward_exts:
                continue

            lambda_0 = bin(state_0).count("1")
            if not lambda_0 == tgt_lambda_0:
                continue

            for ps in backward_exts[state_3]:
                state_6 = last_round(ps[-1][0]) 
                key = (state_0, state_6)
                val = (state_0, ps, state_6)
                dists.setdefault(key, []).append(val)

    for key in sorted(dists):
        print("{}: {}".format(key, len(dists[key])))
        for dist in dists[key]:
            print(dist)
        print()

if __name__ == "__main__":
    main()


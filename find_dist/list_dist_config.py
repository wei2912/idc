from ast import literal_eval
import math
import sys

def main():
    if not len(sys.argv) == 4:
        print("usage: {} [impossible differentials file] [forward extensions file] [backward extensions file]".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    backward_exts = {}
    with open(sys.argv[3]) as f:
        for state_3, pss in map(literal_eval, f):
            backward_exts[state_3] = {}
            for ps in pss:
                state_4, w_4 = ps[0]
                state_5, w_5 = ps[1]
                
                lambda_4 = bin(state_4).count("1")
                lambda_5 = bin(state_5).count("1")
                backward_exts[state_3][state_5] = (lambda_4, lambda_5, w_4, w_5)

    dists = {}
    with open(sys.argv[1]) as f:
        for state_0, state_3 in map(literal_eval, f):
            if not state_3 in backward_exts:
                continue

            lambda_0 = bin(state_0).count("1")
            for state_5, t in backward_exts[state_3].items():
                lambda_4, lambda_5, w_4, w_5 = t

                x = (w_4 + w_5, w_4)
                key = (lambda_0, lambda_4, lambda_5)
                if (key not in dists) or (x < dists[key][0]):
                    dists[key] = (x, w_4, w_5)

    for key, val in dists.items():
        lambda_0, lambda_4, lambda_5 = key
        _, w_4, w_5 = val
        print((lambda_0, lambda_4, lambda_5, w_4, w_5))

if __name__ == "__main__":
    main()


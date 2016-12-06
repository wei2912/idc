from ast import literal_eval
import math
import sys

from gen_graph import convert_int

def find_derived_nibbles(state_4, state_5):
    ns4 = convert_int(state_4)
    ns5 = convert_int(state_5)

    # if there is a pair of active nibbles in ns5, (i, i + 4),
    # then we can derive the key nibble (i + 4) in ns4.
    for i in range(8):
        if ns5[i] == 1 and ns5[i + 4] == 1 and ns4[i + 4] == 1:
            yield i + 4

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
                lambda_4_prime = lambda_4 - len(list(find_derived_nibbles(state_4, state_5)))

                # x is a heruistic used to represent time complexity of key guessing rounds
                # approximating N to be extremely large
                x = 2**(4*lambda_5) * (1 + 2**(4*lambda_4_prime) * math.exp(-w_5)) / math.exp(-w_4 - w_5)
                t = (x, lambda_4_prime, lambda_5, w_4, w_5)
                if (state_5 not in backward_exts[state_3]) or (x < backward_exts[state_3][state_5][0]):
                    backward_exts[state_3][state_5] = t

    xs = {} # indicates cost
    ys = {} # contains distinguisher info
    with open(sys.argv[1]) as f:
        for state_0, state_3 in map(literal_eval, f):
            if not state_3 in backward_exts:
                continue

            lambda_0 = bin(state_0).count("1")
            for state_5, t in backward_exts[state_3].items():
                x, lambda_4_prime, lambda_5, w_4, w_5 = t

                key = (lambda_0, lambda_4_prime, lambda_5)
                if (key not in xs) or (x < xs[key]):
                    xs[key] = x
                    ys[key] = (w_4, w_5)

    for lambda_0, lambda_4_prime, lambda_5 in xs:
        w_4, w_5 = ys[key]
        print((lambda_0, lambda_4_prime, lambda_5, w_4, w_5))

if __name__ == "__main__":
    main()


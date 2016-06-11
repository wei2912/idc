from ast import literal_eval
import math
import sys

def main():
    if not len(sys.argv) == 4:
        print("usage: ./create_dist.py [differentials file] [forward extensions file] [backward extensions file]", file=sys.stderr)
        sys.exit(1)

    forward_exts = {}
    with open(sys.argv[2]) as f:
        for start, p, w in map(literal_eval, f):
            forward_exts.setdefault(start, []).append((p[1], w))

    backward_exts = {}
    with open(sys.argv[3]) as f:
        for end, p, w in map(literal_eval, f):
            backward_exts.setdefault(end, []).append((p[1], w))

    ls = {}
    with open(sys.argv[1]) as f:
        for start, end in map(literal_eval, f):
            if not (start in forward_exts and end in backward_exts):
                continue

            for n_start, wf in forward_exts[start]:
                for n_end, wb in backward_exts[end]:
                    s = bin(n_start).count("1")
                    t = bin(n_end).count("1")
                    if (s, t) not in ls:
                        ls[(s, t)] = wf + wb
                    elif wf + wb < ls[(s, t)]:
                        ls[(s, t)] = wf + wb
                    #print ((n_start, start, end, n_end, wf + wb))

    for (s, t) in ls:
        print((s, t, ls[(s, t)]))

if __name__ == "__main__":
    main()


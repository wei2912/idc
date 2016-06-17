from ast import literal_eval
import math
import sys

def main():
    if not len(sys.argv) == 5:
        print("usage: ./create_dist.py \"(s, t)\" [differentials file] [forward extensions file] [backward extensions file]", file=sys.stderr)
        sys.exit(1)

    target_s, target_t = literal_eval(sys.argv[1])

    forward_exts = {}
    with open(sys.argv[3]) as f:
        for start, p, w in map(literal_eval, f):
            forward_exts.setdefault(start, []).append((p[1], w))

    backward_exts = {}
    with open(sys.argv[4]) as f:
        for end, p, w in map(literal_eval, f):
            backward_exts.setdefault(end, []).append((p[1], w))

    dists = []
    min_w = float('inf')
    with open(sys.argv[2]) as f:
        for start, end in map(literal_eval, f):
            if not (start in forward_exts and end in backward_exts):
                continue

            for n_start, wf in forward_exts[start]:
                s = bin(n_start).count("1")
                if s != target_s:
                    continue

                for n_end, wb in backward_exts[end]:
                    t = bin(n_end).count("1")
                    if t != target_t:
                        continue

                    if wf + wb < min_w:
                        dists = []
                        min_w = wf + wb
                    elif wf + wb > min_w:
                        continue

                    dists.append((n_start, start, end, n_end, wf + wb))

    for dist in dists:
        print(dist)

if __name__ == "__main__":
    main()


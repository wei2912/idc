from ast import literal_eval
import math
import sys

def last_round(end):
    bs = [end >> (11 - i) & 0x1 for i in range(12)]
    b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11 = bs
    bs = b0, b1, b10, b7, b4, b5, b2, b11, b8, b9, b6, b3
    return int("".join(str(b) for b in bs), 2)

def main():
    if not len(sys.argv) == 5:
        print("usage: {} \"(s, t, w)\" [impossible differentials file] [forward extensions file] [backward extensions file]".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    target_s, target_t, target_w = literal_eval(sys.argv[1])

    forward_exts = {}
    with open(sys.argv[3]) as f:
        for start, p, w in map(literal_eval, f):
            s = bin(p[-1]).count("1")
            if s == target_s:
                forward_exts.setdefault(start, []).append((p, w))

    backward_exts = {}
    with open(sys.argv[4]) as f:
        for end, p, w in map(literal_eval, f):
            t = bin(p[-1]).count("1")
            if t == target_t:
                backward_exts.setdefault(end, []).append((p, w))

    dists = {}
    with open(sys.argv[2]) as f:
        for start, end in map(literal_eval, f):
            if not (start in forward_exts and end in backward_exts):
                continue

            for pf, wf in forward_exts[start]:
                for pb, wb in backward_exts[end]:
                    if wf + wb > target_w:
                        continue

                    key = (pf[-1], last_round(pb[-1]))
                    val = (list(reversed(pf)), pb, last_round(pb[-1]))
                    dists.setdefault(key, []).append(val)

    for key in sorted(dists):
        print("{}: {}".format(key, len(dists[key])))
        for dist in dists[key]:
            print(dist)
        print()

if __name__ == "__main__":
    main()


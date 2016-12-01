from ast import literal_eval
import math
import sys

def main():
    if not len(sys.argv) == 4:
        print("usage: {} [impossible differentials file] [forward extensions file] [backward extensions file]".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    
    # as we're looking for just distinguisher configurations,
    # we do not need to be concerned with multiple paths that lead to the same n_start/n_end
    # just the one with the lowest weight
    
    forward_exts = {}
    with open(sys.argv[2]) as f:
        for start, p, w in map(literal_eval, f):
            forward_exts.setdefault(start, {})
            if (p[-1] not in forward_exts[start]) or (w < forward_exts[start][p[-1]]):
                forward_exts[start][p[-1]] = w

    backward_exts = {}
    with open(sys.argv[3]) as f:
        for end, p, w in map(literal_eval, f):
            backward_exts.setdefault(end, {})
            if (p[-1] not in backward_exts[end]) or (w < backward_exts[end][p[-1]]):
                backward_exts[end][p[-1]] = w

    ws = {}
    with open(sys.argv[1]) as f:
        for start, end in map(literal_eval, f):
            if not (start in forward_exts and end in backward_exts):
                continue

            for n_start, wf in forward_exts[start].items():
                s = bin(n_start).count("1")
                for n_end, wb in backward_exts[end].items():
                    t = bin(n_end).count("1")

                    if ((s, t) not in ws) or (wf + wb < ws[(s, t)]):
                        ws[(s, t)] = wf + wb

    for (s, t) in ws:
        print((s, t, ws[(s, t)]))

if __name__ == "__main__":
    main()


"""
Derive a list of impossible differentials.
"""

import ast
import sys

def parse(line):
    return ast.literal_eval(line)

def main():
    if len(sys.argv) != 3:
        print("usage: ./find_ids.py [forward differentials file] [backward differentials file]", file=sys.stderr)
        sys.exit(1)

    forward_diffs = []
    with open(sys.argv[1]) as f:
        for i, forward_rounds, xss in map(parse, f):
            forward_diffs.append((i, forward_rounds, [set(xs) for xs in xss]))

    backward_diffs = []
    with open(sys.argv[2]) as g:
        for i, backward_rounds, yss in map(parse, g):
            backward_diffs.append((i, backward_rounds, [set(ys) for ys in yss]))

    # truncate first round of backward differential
    # by comparing last round of forward differential and second last
    # round of backward differential
    ids = []
    for i, forward_rounds, xss in forward_diffs:
        for j, backward_rounds, yss in backward_diffs:
            if xss[-1].isdisjoint(yss[-2]):
                backward_rounds -= 1
                print((i, forward_rounds, backward_rounds, j))

if __name__ == "__main__":
    main()

"""
Derive a list of impossible differentials.
"""

import ast
import sys

def parse(line):
    i, rounds, xss = ast.literal_eval(line)
    yss = [set(xs) for xs in xss]
    return (i, rounds, yss)

def main():
    if len(sys.argv) != 3:
        print("usage: ./find_ids.py [forward differentials file] [backward differentials file]", file=sys.stderr)
        sys.exit(1)

    ids = []
    with open(sys.argv[1]) as f:
        forward_diffs = [parse(l) for l in f]
    with open(sys.argv[2]) as g:
        backward_diffs = [parse(l) for l in g]

    for i, forward_rounds, xss in forward_diffs: 
        for j, backward_rounds, yss in backward_diffs:
            # truncate first round of backward differential
            # by comparing last round of forward differential and second last
            # round of backward differential
            if xss[-1].intersection(yss[-2]) == set():
                backward_rounds -= 1
                rounds = forward_rounds + backward_rounds
            # or vice versa
            elif xss[-2].intersection(yss[-1]) == set():
                forward_rounds -= 1
                rounds = forward_rounds + backward_rounds
            # if there is no contradiction, skip
            else:
                continue

            if rounds >= 3:
                print((i, forward_rounds, backward_rounds, j))

if __name__ == "__main__":
    main()

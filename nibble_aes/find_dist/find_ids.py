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
        for i, forward_rounds, xss in map(parse, f): 
            if forward_rounds < 2:
                continue

            with open(sys.argv[2]) as g:
                for j, backward_rounds, yss in map(parse, g):
                    if backward_rounds < 2:
                        continue

                    # truncate first round of backward differential
                    # by comparing last round of forward differential and second last
                    # round of backward differential
                    if xss[-1].isdisjoint(yss[-2]):
                        backward_rounds -= 1
                        print((i, forward_rounds, backward_rounds, j))

if __name__ == "__main__":
    main()

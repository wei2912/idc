"""
Derive a list of impossible differentials.
"""

from ast import literal_eval
import sys

def parse(line):
    return literal_eval(line)

def in_set(s, xs):
    return any(i in s for i in xs)

def main():
    if len(sys.argv) != 3:
        print("usage: ./find_ids.py [forward differentials file] [backward differentials file]", file=sys.stderr)
        sys.exit(1)

    ids = []
    with open(sys.argv[1], "rt") as f:
        for i, forward_rounds, xs in map(parse, f):
            with open(sys.argv[2], "rt") as g:
                for j, backward_rounds, ys in map(parse, g):
                    if xs.isdisjoint(ys):
                        backward_rounds -= 1
                        print((i, forward_rounds, backward_rounds, j))

if __name__ == "__main__":
    main()

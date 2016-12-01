"""
Derive a list of impossible differentials.
"""

from ast import literal_eval
import sys

def main():
    if len(sys.argv) != 3:
        print("usage: {} [forward differentials file] [backward differentials file]".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    ids = []
    with open(sys.argv[1], "rt") as f:
        for i, xs in map(literal_eval, f):
            with open(sys.argv[2], "rt") as g:
                for j, ys in map(literal_eval, g):
                    if xs.isdisjoint(ys):
                        print((i, j))

if __name__ == "__main__":
    main()

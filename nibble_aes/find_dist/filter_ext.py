from ast import literal_eval
import sys

def main():
    if not len(sys.argv) == 2:
        print("usage: ./filter_ext.py [extensions file]", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        for start, path, w in map(literal_eval, f):
            if w < 14:
                print((start, path, w))

if __name__ == "__main__":
    main()


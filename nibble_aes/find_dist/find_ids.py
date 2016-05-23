"""
Derive a list of impossible differentials.
"""

def main():
    with open("forward_diffs.pickle", "rb") as f:
        forward_diffs = pickle.load(f)
    with open("backward_diffs.pickle", "rb") as f:
        backward_diffs = pickle.load(f)

    ids = []
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

            if rounds >= 4:
                t = (i, forward_rounds, backward_rounds, j)
                print(t)
                ids.append(t)

    with open("ids.pickle", "wb") as f:
        pickle.dump(ids, f)

if __name__ == "__main__":
    main()

"""
Derive a list of impossible differentials.
"""

def main():
    with open("forward_diffs.pickle") as f:
        forward_diffs = pickle.load(f)
    with open("backward_diffs.pickle") as f:
        backward_diffs = pickle.load(f)

    for i in range(65536):
        forward_rounds, xss = forward_diffs[i]
        for j in range(65536):
            backward_rounds, yss = backward_diffs[j]

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
                print((i, forward_rounds, backward_rounds, j))

if __name__ == "__main__":
    main()

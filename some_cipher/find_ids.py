"""
Derive a list of impossible differentials.
"""

import argparse
import math

import networkx as nx

import gen_graph

def find_diff(g, start):
    """
    g -> Graph of states of nibbles
    start -> Starting configuration

    Return a dictionary of all possible end states with a list of probabilities.
    Multiple end states (with the same number of active nibbles in each column)
    are combined together and their probabilities added together.
    """
    def count_active(v):
        """
        Count the number of active nibbles in each column and return a tuple.
        """
        ns = gen_graph.convert_int(v)
        nss = list(gen_graph.chunks(ns, 4))
        return (sum(nss[0]), sum(nss[1]), sum(nss[2]))

    cycles = set(nx.find_cycle(g))

    ps = [([start], 0)]
    rounds = 0
    isEnd = False
    while len(ps) > 0 and not isEnd:
        n_ps = []
        for p, weight in ps:
            v0 = p[-1]
            for v1 in g[v0]:
                if (v0, v1) in cycles or v1 == 4095:
                    isEnd = True

                v1_weight = g[v0][v1]["weight"]
                n_ps.append((p + [v1], weight + v1_weight))
        rounds += 1
        ps = n_ps

    end_states = {}
    for p, w0 in ps:
        end_state = count_active(p[-1])
        if end_state in end_states:
            w1 = end_states[end_state]
            end_states[end_state] = -math.log(math.exp(-w0) + math.exp(-w1))
        else:
            end_states[end_state] = w0
    return (rounds, end_states)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d',
        '--direction',
        choices=['forward', 'backward'],
        required=True,
        help='direction of differentials'
    )
    args = parser.parse_args()

    if args.direction == "forward":
        g = nx.read_gpickle("forward.gpickle")
    else:
        g = nx.read_gpickle("backward.gpickle")

    for start in range(4096):
        print("Start: {}".format(gen_graph.convert_int(start)))
        rounds, end_states = find_diff(g, start)
        print("No. of rounds: {}".format(rounds))
        ls = list(end_states.items())
        ls.sort(key=lambda t: t[1])
        for end_state, weight in ls:
            print("{} ({})".format(
                end_state,
                math.exp(-weight)
            ))
        print("---")

if __name__ == "__main__":
    main()


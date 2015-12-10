"""
Given a list of distinguishers that work well, find combinations of multiple distinguishers that will cut down time complexity.
"""

import math
import pickle

import networkx as nx

import gen_graph

def overlap(ds0, ds1):
    """
    Return a list of numbers that indicate the number of distinguishers that have an active nibble in that position.
    """
    return [ds0[i] + ds1[i] for i in range(12)]

def main():
    with open("dists.pickle", "rb") as f:
        dists = pickle.load(f)

    best_prob = (0, 0)

    dist_pairs = []
    for i, dist0 in enumerate(dists):
        for j in range(i + 1, len(dists)):
            dist1 = dists[j]
            ds0 = gen_graph.convert_int(dist0[1][-1])
            ds1 = gen_graph.convert_int(dist1[1][-1])

            # make sure the group of distinguishers covers all 12 squares
            cover_score = sum(1 for i in overlap(ds0, ds1) if i >= 1)
            if not cover_score == 12:
                continue

            # calculate number of key nibbles which all of the distinguishers share
            overlap_score = sum(1 for i in overlap(ds0, ds1) if i == 2)
            if not overlap_score == 2:
                continue

            prob = (dist0[2], dist1[2])
            if prob < best_prob:
                continue
            elif prob > best_prob:
                dist_pairs = []
                best_prob = prob
            dist_pairs.append((dist0, dist1))

    for dist0, dist1 in dist_pairs:
        print(
            "{} ... X ... {} with probability {}, {} rounds".format(
                dist0[0],
                " <- ".join(str(v) for v in dist0[1]),
                math.exp(-dist0[2]),
                dist0[3]
            )
        )
        print(
            "{} ... X ... {} with probability {}, {} rounds".format(
                dist1[0],
                " <- ".join(str(v) for v in dist1[1]),
                math.exp(-dist1[2]),
                dist1[3]
            )
        )
        print("---")

main()


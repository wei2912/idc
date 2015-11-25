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

    dist_pairs = []
    for i in range(len(dists)):
        dist0 = dists[i]
        for j in range(i + 1, len(dists)):
            dist1 = dists[j]
            ds0 = gen_graph.convert_int(dist0[1][-1])
            ds1 = gen_graph.convert_int(dist1[1][-1])

            # make sure the group of distinguishers covers all 12 squares
            overlap_score = sum(1 for i in overlap(ds0, ds1) if i >= 1)
            if not overlap_score == 12:
                continue

            # calculate number of key nibbles which all of the distinguishers share
            core_score = sum(1 for i in overlap(ds0, ds1) if i == 2)
            dist_pairs.append((dist0, dist1, core_score))

    dist_pairs.sort(key=lambda t: t[2], reverse=True)
    for dist0, dist1, score in dist_pairs:
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
        print("Score: {}".format(score))

main()


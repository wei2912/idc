#!/bin/bash
# Takes in the filename of the list of pairs and the two output files for (44, 450) and (44, 540) respectively.
grep "^450 " $1 | sed -s 's/^450 //' | head -n 45000 > $2
grep "^540 " $1 | sed -s 's/^540 //' | head -n 45000 > $3

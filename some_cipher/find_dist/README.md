To generate a list of distinguishers used in our project:

```bash
# 1. Generate forward.gpickle, rev_forward.gpickle, backward.gpickle and rev_backward.gpickle. These are graphs which are precomputations of possible transitions when applying a single round function.
$ python3 gen_graph.py

# 2. Generate 2-round forward and 1-round backward differentials. These are combined together to form 3 round impossible differential properties.
$ python3 find_diffs.py forward > forward_diffs.txt
$ python3 find_diffs.py backward > backward_diffs.txt
$ python3 find_ids.py forward_diffs.txt backward_diffs.txt > ids.txt

# 3. Generate key guessing rounds. There are no forward extensions, while there are 2-round backward extensions. These are appended onto the impossible differential properties later on.
$ python3 find_exts.py forward forward_diffs.txt > forward_exts.txt
$ python3 find_exts.py backward backward_diffs.txt > backward_exts.txt

# 4. Construct a list of all distinguisher configurations. Distinguisher configurations look like this: (s, t, w)
# where s is the number of start nibbles, t is the number of end nibbles and w is the weight.
# Time complexity speedup needs to be factored in to select the best distinguisher configurations.
$ python3 list_dist_config.py ids.txt forward_exts.txt backward_exts.txt > dist_configs.txt

# 5. Construct a list of 6-round distinguishers with the last round.
# You need to specify the distinguisher config chosen so that the program does not need to search the whole space.
$ python3 construct_dists.py "($s, $t, $w)" ids.txt forward_exts.txt backward_exts.txt > dists.txt

# 6. View the list of distinguishers.
# The file is formatted to group together distinguishers with the same start and end state.
# Distinguishers with the same list of start and end configuration can use the same list of plaintext-ciphertext pairs for the attack.
$ less dists.txt

```


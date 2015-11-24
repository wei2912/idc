aes-idc [![Build Status](https://travis-ci.org/wei2912/aes-idc.svg?branch=master)](https://travis-ci.org/wei2912/aes-idc)
===

This project studies impossible differential cryptanalysis on substitution-permutation networks.

The code is written in Python 3 and C++.

### Installation

Run the following commands from the root directory of this project to install the dependencies:

```bash
$ pip install -r requirements.txt
$ py.test
```

### Finding distinguishers

Run the following commands from the root directory:

```bash
cd some_cipher/find_diff
python3 gen_graph.py
python3 find_ids.py
python3 create_dist.py > dists.txt
```

### Launching IDC attack (using hardcoded distinguishers)

Run the following commands from the root directory:

```bash
cd some_cipher
make
./gen_pairs > pairs.txt
cat pairs.txt | ./idc 0 1024
```

You can change the range of key nibbles that will be iterated through.


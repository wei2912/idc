idc
===

This project studies impossible differential cryptanalysis on substitution-permutation networks.

The code is written in Python 3 and C++.

## Installation

Run the following commands from the root directory of this project to install the dependencies:

```bash
$ pip install -r requirements.txt
$ py.test
```

## SomeCipher

Description of SomeCipher and attacks carried out will be uploaded in a report soon.

The source code of SomeCipher is available at `some_cipher.cpp`. The header file is available at `some_cipher.h`.

To build the project, simply run `make`.

### Finding distinguisher pairs

Run the following commands from the root directory:

```bash
cd find_dist
python3 gen_graph.py # generates graphs of how differentials propagate in a single round
python3 find_ids.py # find 3-round impossible differential properties
python3 create_dist.py > dists.txt # find 6-round distinguishers
python3 find_dist_pairs.py # find pairs of 6-round distinguishers
```

`gen_graph.py` will generate the files `backward.gpickle`, `forward.gpickle`, `rev_backward.gpickle` and `rev_forward.gpickle`. These are graphs of how differentials propagate in a single round. Each edge has a weight, which is the negated logarithmic probability.

The procedure of finding the distinguishers is briefly described in the report.

### Launching brute force (for benchmarking purposes)

```bash
./gen_bf # generates bf.txt which contains a key, plaintext and ciphertext
cat bf.txt | ./bf 0 1024 # 0 and 1024 are the start and end partitions respectively
```

### Launching IDC attack (using hardcoded distinguishers)

Run the following commands from the root directory:

```bash
./gen_pairs 256 # generates pairs_256.txt where 256 is the no. of filtered PT-CT pairs
cat pairs_256.txt | ./idc 0 1024 # 0 and 1024 are the start and end partitions respectively
```

### Launching double distinguisher attack

The same applies to launching a double distinguisher attack. To do so, just replace `gen_pairs` with `gen_pairs2` and `idc` with `idc2`.

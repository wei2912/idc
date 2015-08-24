aes-idc [![Build Status](https://travis-ci.org/wei2912/aes-idc.svg?branch=master)](https://travis-ci.org/wei2912/aes-idc)
===

This project studies impossible differential cryptanalysis on
substitution-permutation networks, specifically on AES.

The code is written in Python 3.

### Outline of plan

1. Small scale attack - IDC on 5 round Mini-AES. *Bonus: 6 round Mini-AES*
2. IDC on 5 rounds of 48-bit SPN cipher. *Bonus: attack more rounds*
3. Either of the following:
    a. 64-bit SPN cipher, 5 or 6 round attack.
    b. 128-bit AES - compute distinguishers, key guess round extensions

### Installation

The module can be used directly without installing any dependencies.

If you wish to run the test suite, run the following commands:

```bash
$ pip install -r requirements.txt
$ py.test
```


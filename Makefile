CC=gcc
CFLAGS=-Wall -O3
CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all: test_some_cipher brute_force gen_pairs_1005_450 gen_pairs_1005_540 idc_single
clean:
	rm some_cipher.o test_some_cipher
	rm brute_force
	rm gen_pairs_1005_450 gen_pairs_1005_540
	rm idc_single

some_cipher.o: some_cipher.h
test_some_cipher: some_cipher.o

brute_force: some_cipher.o
gen_pairs_1005_450: some_cipher.o
gen_pairs_1005_540: some_cipher.o
idc_single: some_cipher.o

CC=gcc
CFLAGS=-Wall -O3
CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all: test_nibble_aes test_brute_force gen_pairs
clean:
	rm nibble_aes.o test_nibble_aes
	rm brute_force.o test_brute_force
	rm gen_pairs_388 gen_pairs_6210

nibble_aes.o: nibble_aes.h
test_nibble_aes: nibble_aes.o

brute_force.o: nibble_aes.o
test_brute_force: brute_force.o nibble_aes.o

gen_pairs: gen_pairs_388 gen_pairs_6210
gen_pairs_388: nibble_aes.o
gen_pairs_6210: nibble_aes.o


CC=gcc
CFLAGS=-Wall -O3
CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all: test_nibble_aes test_brute_force gen_pairs
clean:
	rm nibble_aes.o test_nibble_aes
	rm brute_force.o test_brute_force
	rm gen_pairs

nibble_aes.o: nibble_aes.c nibble_aes.h
test_nibble_aes: nibble_aes.o

brute_force.o: nibble_aes.o brute_force.c
test_brute_force: brute_force.o nibble_aes.o

gen_pairs: nibble_aes.o idc.h gen_pairs.c

CC=gcc
CFLAGS=-Wall -O3
CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all: some_cipher.o test_some_cipher
	+$(MAKE) -C brute_force
	+$(MAKE) -C gen_pairs
	+$(MAKE) -C idc
clean:
	+$(MAKE) -C brute_force clean
	+$(MAKE) -C gen_pairs clean
	+$(MAKE) -C idc clean
	rm some_cipher.o test_some_cipher

some_cipher.o: some_cipher.c
test_some_cipher: some_cipher.o

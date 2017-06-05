CC=gcc
CFLAGS=-std=c11 -Wall -O3
CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all: some_cipher.o test_some_cipher
	+$(MAKE) -C gen_pairs
	+$(MAKE) -C attacks
clean:
	+$(MAKE) -C gen_pairs clean
	+$(MAKE) -C attacks clean
	rm some_cipher.o test_some_cipher

some_cipher.o: some_cipher.c
test_some_cipher: some_cipher.o

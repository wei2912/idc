CC=gcc
CFLAGS=-Wall -O3
CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all: test_some_cipher brute_force
clean:
	rm some_cipher.o test_some_cipher
	rm brute_force

some_cipher.o: some_cipher.h
test_some_cipher: some_cipher.o

brute_force: some_cipher.o

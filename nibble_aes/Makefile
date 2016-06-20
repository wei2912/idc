CC=gcc
CFLAGS=-Wall -O3
CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all: test_nibble_aes test_brute_force
clean:
	rm nibble_aes.o test_nibble_aes
	rm brute_force.o test_brute_force

nibble_aes.o: nibble_aes.h
test_nibble_aes: nibble_aes.o

brute_force.o: nibble_aes.o
test_brute_force: brute_force.o nibble_aes.o


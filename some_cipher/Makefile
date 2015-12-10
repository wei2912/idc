CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all: test_some_cipher gen_pairs gen_pairs2 idc idc2
clean:
	rm some_cipher.o test_some_cipher gen_pairs gen_pairs2 idc idc2

test_some_cipher: some_cipher.o
gen_pairs: some_cipher.o
gen_pairs2: some_cipher.o
idc: some_cipher.o
idc2: some_cipher.o


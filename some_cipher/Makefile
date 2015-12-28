CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all: test_some_cipher bf idc idc2 gen_bf gen_pairs gen_pairs2
clean:
	rm some_cipher.o test_some_cipher gen_bf gen_pairs gen_pairs2 idc idc2 bf

test_some_cipher: some_cipher.o
bf: some_cipher.o
idc: some_cipher.o
idc2: some_cipher.o

gen_bf: some_cipher.o
gen_pairs: some_cipher.o
gen_pairs2: some_cipher.o

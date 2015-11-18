CXX=g++
CXXFLAGS=-std=c++11 -Wall -O3 -g

all: test_some_cipher gen_pairs idc
clean:
	rm some_cipher.o  test_some_cipher gen_pairs idc

test_some_cipher: some_cipher.o
gen_pairs: some_cipher.o
idc: some_cipher.o


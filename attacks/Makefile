CC=gcc
CFLAGS=-Wall -O3
CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all: brute_force idc_44_450 idc_44_540 idc_single idc_double

brute_force: ../some_cipher.o
idc_44_450: idc.o ../some_cipher.o
idc_44_540: idc.o ../some_cipher.o
idc_single: idc.o ../some_cipher.o
idc_double: idc.o ../some_cipher.o

clean:
	rm brute_force idc.o idc_44_450 idc_44_540 idc_single idc_double

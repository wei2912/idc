CC=gcc
CFLAGS=-Wall -O3
CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all: idc_193_450 idc_single

idc_193_450: idc.o ../some_cipher.o
idc_single: idc.o ../some_cipher.o

clean:
	rm idc.o idc_193_450 idc_single

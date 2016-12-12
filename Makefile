CC=gcc
CFLAGS=-Wall -O3
CXX=g++
CXXFLAGS=-std=c++14 -Wall -O3

all:
	+$(MAKE) -C src
clean:
	+$(MAKE) -C src clean

all: hwsim_test

ifndef CC
CC=gcc
endif

ifndef CFLAGS
CFLAGS = -O2 -Wall -g
endif

hwsim_test: hwsim_test.o

clean:
	rm -rf *.o
	rm -rf hwsim_test

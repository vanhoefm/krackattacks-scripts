TESTS=test-base64

all: $(TESTS)

ifndef CC
CC=gcc
endif

ifndef LDO
LDO=$(CC)
endif

ifndef CFLAGS
CFLAGS = -MMD -O2 -Wall -g
endif

CFLAGS += -I../src


BASE64_OBJS=test-base64.o ../src/utils/base64.o ../src/utils/os_unix.o

test-base64: $(BASE64_OBJS)
	$(LDO) $(LDFLAGS) -o $@ $(BASE64_OBJS)

clean:
	$(MAKE) -C ../src clean
	rm -f $(TESTS) *~ *.o

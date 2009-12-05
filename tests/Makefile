TESTS=test-base64 test-milenage

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
CFLAGS += -I../src/utils

OS_OBJS=../src/utils/os_unix.o


BASE64_OBJS=test-base64.o \
	../src/utils/base64.o \
	$(OS_OBJS)

test-base64: $(BASE64_OBJS)
	$(LDO) $(LDFLAGS) -o $@ $(BASE64_OBJS)


MILENAGE_OBJS=test-milenage.o \
	../src/utils/wpa_debug.o \
	../src/crypto/aes-internal.o \
	../src/crypto/aes-internal-enc.o \
	../src/crypto/aes-encblock.o \
	../src/crypto/milenage.o \
	$(OS_OBJS)

test-milenage: $(MILENAGE_OBJS)
	$(LDO) $(LDFLAGS) -o $@ $(MILENAGE_OBJS)


run-tests: $(TESTS)
	./test-milenage

clean:
	$(MAKE) -C ../src clean
	rm -f $(TESTS) *~ *.o *.d

-include $(OBJS:%.o=%.d)

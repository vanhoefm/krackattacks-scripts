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

LIBS = ../src/utils/libutils.a \
	../src/crypto/libcrypto.a

../src/utils/libutils.a:
	$(MAKE) -C ../src/utils

../src/crypto/libcrypto.a:
	$(MAKE) -C ../src/crypto

BASE64_OBJS=test-base64.o \
	$(LIBS)

test-base64: $(BASE64_OBJS)
	$(LDO) $(LDFLAGS) -o $@ $(BASE64_OBJS)


MILENAGE_OBJS=test-milenage.o \
	$(LIBS)

test-milenage: $(MILENAGE_OBJS)
	$(LDO) $(LDFLAGS) -o $@ $(MILENAGE_OBJS)


run-tests: $(TESTS)
	./test-milenage

clean:
	$(MAKE) -C ../src clean
	rm -f $(TESTS) *~ *.o *.d

-include $(OBJS:%.o=%.d)

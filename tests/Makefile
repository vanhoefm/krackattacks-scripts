TESTS=test-base64 test-md4 test-milenage

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


test-base64: test-base64.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^

test-md4: test-md4.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^

test-milenage: test-milenage.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^


run-tests: $(TESTS)
	./test-md4
	./test-milenage

clean:
	$(MAKE) -C ../src clean
	rm -f $(TESTS) *~ *.o *.d

-include $(OBJS:%.o=%.d)

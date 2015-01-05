TESTS=test-base64 test-md4 test-milenage \
	test-rsa-sig-ver \
	test-sha1 \
	test-sha256 test-aes test-asn1 test-x509 test-x509v3 test-list test-rc4

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

SLIBS = ../src/utils/libutils.a

DLIBS = ../src/crypto/libcrypto.a \
	../src/tls/libtls.a

LIBS = $(SLIBS) $(DLIBS)
LLIBS = -Wl,--start-group $(DLIBS) -Wl,--end-group $(SLIBS)

# glibc < 2.17 needs -lrt for clock_gettime()
LLIBS += -lrt

../src/utils/libutils.a:
	$(MAKE) -C ../src/utils

../src/crypto/libcrypto.a:
	$(MAKE) -C ../src/crypto

../src/tls/libtls.a:
	$(MAKE) -C ../src/tls


test-aes: test-aes.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^ $(LLIBS)

test-asn1: test-asn1.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^ $(LLIBS)

test-base64: test-base64.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^ $(LLIBS)

test-https: test-https.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $< $(LLIBS)

test-list: test-list.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^ $(LLIBS)

test-md4: test-md4.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^ $(LLIBS)

test-milenage: test-milenage.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^ $(LLIBS)

test-rc4: test-rc4.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^ $(LLIBS)

test-rsa-sig-ver: test-rsa-sig-ver.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $< $(LLIBS)

test-sha1: test-sha1.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^ $(LLIBS)

test-sha256: test-sha256.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^ $(LLIBS)

test-x509: test-x509.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $< $(LLIBS)

test-x509v3: test-x509v3.o $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $< $(LLIBS)


run-tests: $(TESTS)
	./test-aes
	./test-list
	./test-md4
	./test-milenage
	./test-rsa-sig-ver
	./test-sha1
	./test-sha256
	@echo
	@echo All tests completed successfully.

clean:
	$(MAKE) -C ../src clean
	rm -f $(TESTS) *~ *.o *.d
	rm -f test-https
	rm -f test_x509v3_nist.out.*
	rm -f test_x509v3_nist2.out.*

-include $(OBJS:%.o=%.d)

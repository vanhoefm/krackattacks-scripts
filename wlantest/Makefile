ALL=wlantest

all: $(ALL)

ifndef CC
CC=gcc
endif

ifndef RANLIB
RANLIB=ranlib
endif

ifndef CFLAGS
CFLAGS = -MMD -O2 -Wall -g
endif


CFLAGS += -I.
CFLAGS += -I../src
CFLAGS += -I../src/utils


ifndef LDO
LDO=$(CC)
endif

Q=@
E=echo
ifeq ($(V), 1)
Q=
E=true
endif

%.o: %.c
	$(Q)$(CC) -c -o $@ $(CFLAGS) $<
	@$(E) "  CC " $<


OBJS_lib += ../src/utils/libutils.a
OBJS_lib += ../src/crypto/libcrypto.a

OBJS += ../src/common/ieee802_11_common.o
OBJS += ../src/common/wpa_common.o

OBJS += wlantest.o
OBJS += readpcap.o
OBJS += monitor.o
OBJS += process.o
OBJS += rx_mgmt.o
OBJS += rx_data.o
OBJS += bss.o
OBJS += sta.o
OBJS += crc32.o

LIBS += -lpcap


../src/utils/libutils.a:
	$(MAKE) -C ../src/utils

../src/crypto/libcrypto.a:
	$(MAKE) -C ../src/crypto


ifneq ($(CONFIG_SOLIB), yes)
LIBWLANTEST = libwlantest.a
libwlantest.a: $(OBJS_lib)
	$(AR) crT libwlantest.a $(OBJS_lib)
	$(RANLIB) libwlantest.a

else
CFLAGS  += -fPIC -DPIC
LDFLAGS += -shared

LIBWLANTEST  = libwlantest.so
libwlantest.so: $(OBJS_lib)
	$(LDO) $(LDFLAGS) $(OBJS_lib) -o $(LIBWLANTEST)

endif

wlantest: $(OBJS) $(LIBWLANTEST)
	$(LDO) $(LDFLAGS) -o wlantest $(OBJS) -L. -lwlantest $(LIBS)

clean:
	$(MAKE) -C ../src clean
	rm -f core *~ *.o *.d libwlantest.a libwlantest.so $(ALL)

-include $(OBJS:%.o=%.d)

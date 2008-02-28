ALL=radius_example

all: $(ALL)

ifndef CC
CC=gcc
endif

ifndef CFLAGS
CFLAGS = -MMD -O2 -Wall -g
endif

CFLAGS += -I.
CFLAGS += -I../src
CFLAGS += -I../src/crypto
CFLAGS += -I../src/utils

OBJS += ../src/utils/common.o
OBJS += ../src/utils/os_unix.o
OBJS += ../src/utils/wpa_debug.o
OBJS += ../src/utils/eloop.o
OBJS += ../src/utils/ip_addr.o
OBJS += ../src/crypto/md5.o
CFLAGS += -DINTERNAL_MD5

OBJS += ../src/radius/radius.o
OBJS += ../src/radius/radius_client.o

ifndef LDO
LDO=$(CC)
endif


OBJS_ex = radius_example.o

libradius.a: $(OBJS)
	ar rc libradius.a $(OBJS)
	ranlib libradius.a

radius_example: $(OBJS_ex) libradius.a
	$(LDO) $(LDFLAGS) -o radius_example $(OBJS_ex) -L. -lradius $(LIBS)

clean:
	$(MAKE) -C ../src clean
	rm -f core *~ *.o *.d libradius.a $(ALL)

-include $(OBJS:%.o=%.d)

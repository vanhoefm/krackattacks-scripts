all: libutils.a

clean:
	for d in $(SUBDIRS); do make -C $$d clean; done
	rm -f *~ *.o *.d libutils.a

install:
	@echo Nothing to be made.


ifndef CC
CC=gcc
endif

ifndef CFLAGS
CFLAGS = -MMD -O2 -Wall -g
endif


LIB_OBJS= \
	base64.o \
	common.o \
	ip_addr.o \
	radiotap.o \
	uuid.o \
	wpa_debug.o \
	wpabuf.o

# Pick correct OS wrapper implementation
LIB_OBJS += os_unix.o

# Pick correct event loop implementation
LIB_OBJS += eloop.o

#LIB_OBJS += pcsc_funcs.o

libutils.a: $(LIB_OBJS)
	$(AR) cr $@ $(LIB_OBJS)

-include $(OBJS:%.o=%.d)

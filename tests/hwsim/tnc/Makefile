CFLAGS += -I$(abspath ../../../src)
CFLAGS += -I$(abspath ../../../src/utils)

ALL=libhostap_imc.so libhostap_imv.so libhostap2_imc.so libhostap2_imv.so
all: $(ALL)

lib%.so: %.c
	$(CC) $(LDFLAGS) -o $@ $(CFLAGS) -shared -rdynamic -fPIC $<

clean:
	rm -f $(ALL)

# Determine path to the root directory of the Linux kernel source for the
# currently running kernel. Version can be hardcoded with environment variable:
# KVERS=2.6.25-foo make
# Kernel path can be overrided with KERNEL_PATH argument to make:
# make KERNEL_PATH=/usr/src/linux
KVERS ?= $(shell uname -r)
KERNEL_PATH ?= /lib/modules/$(KVERS)/build

hwsim:
	$(MAKE) -C $(KERNEL_PATH) SUBDIRS=$(PWD) modules

obj-m += mac80211_hwsim.o

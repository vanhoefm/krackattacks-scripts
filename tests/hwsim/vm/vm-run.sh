#!/bin/bash

cd "$(dirname $0)"

if [ -z "$TESTDIR" ] ; then
	TESTDIR=$(pwd)/../
fi

LOGS=/tmp/hwsim-test-logs/

# increase the memory size if you want to run with valgrind, 512 MB works
MEMORY=128

# Some ubuntu systems (notably 12.04) have issues with this - since the guest
# mounts as read-only it should be safe to not specify ,readonly. Override in
# vm-config if needed (see below)
ROTAG=,readonly

# set this to ttyS0 to see kvm messages (if something doesn't work)
KVMOUT=ttyS1

# you can set EPATH if you need anything extra in $PATH inside the VM
#EPATH=/some/dir

# extra KVM arguments, e.g., -s for gdbserver
#KVMARGS=-s

# number of channels each hwsim device supports
CHANNELS=1

test -f vm-config && . vm-config

if [ -z "$KERNEL" ] && [ -z "$KERNELDIR" ] ; then
	echo "You need to set a KERNEL or KERNELDIR (in the environment or vm-config)"
	exit 2
fi
if [ -z "$KERNEL" ] ; then
	KERNEL=$KERNELDIR/arch/x86_64/boot/bzImage
fi


CMD=$TESTDIR/vm/inside.sh
LOGDIR=$LOGS/$(date +%s)
mkdir -p $LOGDIR

exec kvm \
	-kernel $KERNEL -smp 4 \
	$KVMARGS -m $MEMORY -nographic \
	-fsdev local,security_model=none,id=fsdev-root,path=/$ROTAG \
	-device virtio-9p-pci,id=fs-root,fsdev=fsdev-root,mount_tag=/dev/root \
	-fsdev local,security_model=none,id=fsdev-logs,path="$LOGDIR",writeout=immediate \
	-device virtio-9p-pci,id=fs-logs,fsdev=fsdev-logs,mount_tag=logshare \
	-monitor null -serial stdio -serial file:$LOGDIR/console \
	-append "mac80211_hwsim.channels=$CHANNELS mac80211_hwsim.radios=5 init=$CMD testdir=$TESTDIR console=$KVMOUT root=/dev/root rootflags=trans=virtio,version=9p2000.u ro rootfstype=9p EPATH=$EPATH ARGS=$*"

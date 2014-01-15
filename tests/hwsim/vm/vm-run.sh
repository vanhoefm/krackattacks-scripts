#!/bin/bash

cd "$(dirname $0)"

if [ -z "$TESTDIR" ] ; then
	TESTDIR=$(pwd)/../
fi

LOGS=/tmp/hwsim-test-logs

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
test -f ~/.wpas-vm-config && . ~/.wpas-vm-config

if [ -z "$KERNEL" ] && [ -z "$KERNELDIR" ] ; then
	echo "You need to set a KERNEL or KERNELDIR (in the environment or vm-config)"
	exit 2
fi
if [ -z "$KERNEL" ] ; then
	KERNEL=$KERNELDIR/arch/x86_64/boot/bzImage
fi


CMD=$TESTDIR/vm/inside.sh
DATE=$(date +%s)
LOGDIR=$LOGS/$DATE
mkdir -p $LOGDIR

if [ "$1" = "--codecov" ]; then
    shift
    CODECOV=yes
    DIR=$PWD
    if [ -e /tmp/logs ]; then
	echo "/tmp/logs exists - cannot prepare build trees"
	exit 1
    fi
    mkdir /tmp/logs
    echo "Preparing separate build trees for hostapd/wpa_supplicant"
    cd ../../..
    git archive --format=tar --prefix=hostap/ HEAD > /tmp/logs/hostap.tar
    cd $DIR
    cat ../../../wpa_supplicant/.config > /tmp/logs/wpa_supplicant.config
    echo "CONFIG_CODE_COVERAGE=y" >> /tmp/logs/wpa_supplicant.config
    cat ../../../hostapd/.config > /tmp/logs/hostapd.config
    echo "CONFIG_CODE_COVERAGE=y" >> /tmp/logs/hostapd.config

    cd /tmp/logs
    tar xf hostap.tar
    mv hostap alt-wpa_supplicant
    mv wpa_supplicant.config alt-wpa_supplicant/wpa_supplicant/.config
    tar xf hostap.tar
    mv hostap alt-hostapd
    cp hostapd.config alt-hostapd/hostapd/.config
    tar xf hostap.tar
    mv hostap alt-hostapd-as
    mv hostapd.config alt-hostapd-as/hostapd/.config
    rm hostap.tar

    cd /tmp/logs/alt-wpa_supplicant/wpa_supplicant
    echo "Building wpa_supplicant"
    make -j8 > /dev/null

    cd /tmp/logs/alt-hostapd/hostapd
    echo "Building hostapd"
    make -j8 hostapd > /dev/null

    cd /tmp/logs/alt-hostapd-as/hostapd
    echo "Building hostapd/hlr_auc_gw (AS)"
    make -j8 hostapd hlr_auc_gw > /dev/null

    cd $DIR

    mv /tmp/logs/alt-wpa_supplicant $LOGDIR
    mv /tmp/logs/alt-hostapd $LOGDIR
    mv /tmp/logs/alt-hostapd-as $LOGDIR
else
    CODECOV=no
fi

if [ "$1" == "--timewarp" ] ; then
    TIMEWARP=1
    shift
else
    TIMEWARP=0
fi

echo "Starting test run in a virtual machine"

kvm \
	-kernel $KERNEL -smp 4 \
	$KVMARGS -m $MEMORY -nographic \
	-fsdev local,security_model=none,id=fsdev-root,path=/$ROTAG \
	-device virtio-9p-pci,id=fs-root,fsdev=fsdev-root,mount_tag=/dev/root \
	-fsdev local,security_model=none,id=fsdev-logs,path="$LOGDIR",writeout=immediate \
	-device virtio-9p-pci,id=fs-logs,fsdev=fsdev-logs,mount_tag=logshare \
	-monitor null -serial stdio -serial file:$LOGDIR/console \
	-append "mac80211_hwsim.channels=$CHANNELS mac80211_hwsim.radios=6 init=$CMD testdir=$TESTDIR timewarp=$TIMEWARP console=$KVMOUT root=/dev/root rootflags=trans=virtio,version=9p2000.u ro rootfstype=9p EPATH=$EPATH ARGS=$*"

if [ $CODECOV = "yes" ]; then
    mv $LOGDIR/alt-wpa_supplicant /tmp/logs
    mv $LOGDIR/alt-hostapd /tmp/logs
    mv $LOGDIR/alt-hostapd-as /tmp/logs

    echo "Generating code coverage report for wpa_supplicant"
    cd /tmp/logs/alt-wpa_supplicant/wpa_supplicant
    lcov -c -d .. > lcov.info 2> lcov.log
    genhtml -t "wpa_supplicant hwsim test run $DATE" lcov.info --output-directory $LOGDIR/lcov-wpa_supplicant >> lcov.log 2>&1
    mv lcov.info lcov.log $LOGDIR/lcov-wpa_supplicant

    echo "Generating code coverage report for hostapd"
    cd /tmp/logs/alt-hostapd/hostapd
    lcov -c -d .. > lcov.info 2> lcov.log
    genhtml -t "hostapd hwsim test run $DATE" lcov.info --output-directory $LOGDIR/lcov-hostapd >> lcov.log 2>&1
    mv lcov.info lcov.log $LOGDIR/lcov-hostapd

    echo "Generating code coverage report for hostapd/hlr_auc_gw (AS)"
    cd /tmp/logs/alt-hostapd-as/hostapd
    lcov -c -d .. > lcov.info 2> lcov.log
    genhtml -t "hostapd/hlr_auc_gw (AS) hwsim test run $DATE" lcov.info --output-directory $LOGDIR/lcov-hostapd-as >> lcov.log 2>&1
    mv lcov.info lcov.log $LOGDIR/lcov-hostapd-as

    echo "Generating combined code coverage report"
    mkdir $LOGDIR/lcov-combined
    for i in wpa_supplicant hostapd hostapd-as; do
	sed s%SF:/tmp/logs/alt-[^/]*/%SF:/tmp/logs/alt-wpa_supplicant/% < $LOGDIR/lcov-$i/lcov.info > $LOGDIR/lcov-combined/$i.info
    done
    cd $LOGDIR/lcov-combined
    lcov -a wpa_supplicant.info -a hostapd.info -a hostapd-as.info -o combined.info > lcov.log 2>&1
    genhtml -t "wpa_supplicant/hostapd combined for hwsim test run $DATE" combined.info --output-directory . >> lcov.log 2>&1

    cd $DIR
    rm -r /tmp/logs/alt-wpa_supplicant
    rm -r /tmp/logs/alt-hostapd
    rm -r /tmp/logs/alt-hostapd-as
    rmdir /tmp/logs
fi

echo
echo "Test run completed"
echo "Logfiles are at $LOGDIR"
if [ $CODECOV = "yes" ]; then
    echo "Code coverage reports:"
    echo "wpa_supplicant: file://$LOGDIR/lcov-wpa_supplicant/index.html"
    echo "hostapd: file://$LOGDIR/lcov-hostapd/index.html"
    echo "hostapd/hlr_auc_gw (AS): file://$LOGDIR/lcov-hostapd-as/index.html"
    echo "combined: file://$LOGDIR/lcov-combined/index.html"
fi

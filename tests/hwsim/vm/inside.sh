#!/bin/sh

# mount all kinds of things
mount tmpfs -t tmpfs /etc
# we need our own /dev/rfkill, and don't want device access
mount tmpfs -t tmpfs /dev
mount tmpfs -t tmpfs /tmp
# some sockets go into /var/run, and / is read-only
mount tmpfs -t tmpfs /var/run
mount proc -t proc /proc
mount sysfs -t sysfs /sys
# needed for tracing
mount debugfs -t debugfs /sys/kernel/debug

# reboot on any sort of crash
sysctl kernel.panic_on_oops=1
sysctl kernel.panic=1

# get extra command line variables from /proc/cmdline
TESTDIR=$(sed 's/.*testdir=\([^ ]*\) .*/\1/' /proc/cmdline)
EPATH=$(sed 's/.*EPATH=\([^ ]*\) .*/\1/' /proc/cmdline)
ARGS=$(sed 's/.*ARGS=//' /proc/cmdline)

# create /dev entries we need
mknod -m 660 /dev/ttyS0 c 4 64
mknod -m 660 /dev/random c 1 8
mknod -m 660 /dev/urandom c 1 9
mknod -m 666 /dev/null c 1 3
test -f /sys/class/misc/rfkill/dev && \
	mknod -m 660 /dev/rfkill c $(cat /sys/class/misc/rfkill/dev | tr ':' ' ')
ln -s /proc/self/fd/0 /dev/stdin
ln -s /proc/self/fd/1 /dev/stdout
ln -s /proc/self/fd/2 /dev/stderr

# create dummy sudo - everything runs as uid 0
mkdir /tmp/bin
cat > /tmp/bin/sudo << EOF
#!/bin/bash

exec "\$@"
EOF
chmod +x /tmp/bin/sudo
# and put it into $PATH, as well as our extra-$PATH
export PATH=/tmp/bin:$EPATH:$PATH

# some tests assume adm/admin group(s) exist(s)
echo 'adm:x:0:' > /etc/group
echo 'admin:x:0:' >> /etc/group
# root should exist
echo 'root:x:0:0:root:/tmp:/bin/bash' > /etc/passwd

# local network is needed for some tests
ip link set lo up

# create logs mountpoint and mount the logshare
mkdir /tmp/logs
mount -t 9p -o trans=virtio,rw logshare /tmp/logs

# check if we're rebooting due to a kernel panic ...
if grep -q 'Kernel panic' /tmp/logs/console ; then
	echo "KERNEL CRASHED!" >/dev/ttyS0
else
	# finally run the tests
	export USER=0
	export LOGDIR=/tmp/logs
	export DBFILE=$LOGDIR/results.db
	export PREFILL_DB=y

	cd $TESTDIR
	./run-all.sh $ARGS >/dev/ttyS0 2>&1
	#bash </dev/ttyS0 >/dev/ttyS0 2>&1
fi

# and shut down the machine again
halt -f -p

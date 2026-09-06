#!/bin/sh
# Repeated measurement: REPS runs of each configuration, so a conclusion rests
# on a median rather than on one noisy sample.
set -u
mkdir -p /var/run/ubus /tmp/out; chmod 1777 /var/run/ubus
ip link set lo up 2>/dev/null || true
S=/var/run/ubus/ubus.sock
REPS=${REPS:-5}

measure() { # $1 = serve mode, $2 = label
	mode=$1; label=$2
	r=0
	while [ $r -lt $REPS ]; do
		r=$((r + 1))
		/sbin/ubusd-under-test >/tmp/out/bus.log 2>&1 & bus=$!
		i=0; while [ $i -lt 10 ]; do [ -S $S ] && break; i=$((i+1)); sleep 1; done
		/tmp/bench $S "$mode" >/tmp/out/serve.log 2>&1 & srv=$!
		i=0; while [ $i -lt 15 ]; do ubus list | grep -q '^bench.target$' && break; i=$((i+1)); sleep 1; done
		printf '%s rep=%s ' "$label" "$r"
		/tmp/bench $S lookup_all 300
		kill $srv $bus 2>/dev/null
		sleep 1
		rm -f $S
	done
}

measure serve_many:10  "objs=10"
measure serve_many:160 "objs=160"
measure serve_wide:16  "methods=16"
measure serve_wide:64  "methods=64"
exit 0

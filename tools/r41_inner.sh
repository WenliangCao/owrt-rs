#!/bin/sh
set -u
mkdir -p /var/run/ubus /tmp/out; chmod 1777 /var/run/ubus
ip link set lo up 2>/dev/null || true
S=/var/run/ubus/ubus.sock
say() { printf '%s\n' "$*"; }

/sbin/ubusd-under-test >/tmp/out/bus.log 2>&1 & bus=$!
i=0; while [ $i -lt 10 ]; do [ -S $S ] && break; i=$((i+1)); sleep 1; done

say "--- 1. the message size cap, found by bisection rather than assumed"
# 1 MiB is the upstream CMake default. Probe just under, exactly at, and over.
for n in 1048572 1048576 1048577 1048580 2097152; do
	say "size=$n verdict=$(/tmp/busprobe big $S $n 2>&1 | tr -d '\n')"
	say "  bus_alive_after=$(kill -0 $bus 2>/dev/null && echo yes || echo no) serving=$(ubus list >/dev/null 2>&1 && echo yes || echo no)"
done

say "--- 2. a blob header shorter than a blob_attr"
say "size=3 verdict=$(/tmp/busprobe big $S 3 2>&1 | tr -d '\n')"
say "  serving=$(ubus list >/dev/null 2>&1 && echo yes || echo no)"

say "--- 3. more than the transmit cap queued for one client that never reads"
# ~200 objects of 64 methods is well over 1 MiB of lookup replies
/tmp/bench $S serve_wide_many:200:64 >/tmp/out/serve.log 2>&1 & srv=$!
i=0; while [ $i -lt 30 ]; do [ "$(ubus list | wc -l)" -ge 200 ]  && break; i=$((i+1)); sleep 1; done
say "objects=$(ubus list | wc -l)"
say "one_signature_bytes=$(ubus -v list bench.target | wc -c)"
rss() { awk '/VmRSS/{print $2}' /proc/$bus/status 2>/dev/null; }
r0=$(rss)
# a client that asks for every object and never reads a byte of the answer
/tmp/busprobe slow $S 6 >/tmp/out/slow.txt 2>&1 & sp=$!
sleep 3
say "during: serving=$(ubus list >/dev/null 2>&1 && echo yes || echo no) call_rc=$(ubus -S call bench.target method_number_0000 '{}' >/dev/null 2>&1; echo $?)"
say "during: rss_growth_kib_bounded=$([ $(( $(rss) - r0 )) -lt 8192 ] && echo yes || echo no)"
wait $sp 2>/dev/null
sleep 1
say "after: bus_alive=$(kill -0 $bus 2>/dev/null && echo yes || echo no)"
say "after: serving=$(ubus list >/dev/null 2>&1 && echo yes || echo no)"
say "after: rss_growth_kib_bounded=$([ $(( $(rss) - r0 )) -lt 8192 ] && echo yes || echo no)"

say "--- 4. ten such clients in a row leave nothing behind"
j=0; while [ $j -lt 10 ]; do /tmp/busprobe drop $S >/dev/null 2>&1; j=$((j+1)); done
sleep 1
say "still_serving=$(ubus list >/dev/null 2>&1 && echo yes || echo no)"
say "fd_bounded=$([ $(ls /proc/$bus/fd | wc -l) -lt 32 ] && echo yes || echo no)"
say "rss_growth_kib_bounded=$([ $(( $(rss) - r0 )) -lt 8192 ] && echo yes || echo no)"

kill $srv $bus 2>/dev/null
exit 0

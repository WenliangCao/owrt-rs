#!/bin/sh
# Runs inside the chroot. Same load, same client, one daemon per run.
set -u
mkdir -p /var/run/ubus /tmp/out; chmod 1777 /var/run/ubus
ip link set lo up 2>/dev/null || true
N=${N:-3000}

/sbin/ubusd-under-test >/tmp/out/bus.log 2>&1 & bus=$!
i=0; while [ $i -lt 10 ]; do [ -S /var/run/ubus/ubus.sock ] && break; i=$((i+1)); sleep 1; done

S=/var/run/ubus/ubus.sock
/tmp/bench $S serve >/tmp/out/serve.log 2>&1 & srv=$!
i=0; while [ $i -lt 10 ]; do ubus list | grep -q '^bench.target$' && break; i=$((i+1)); sleep 1; done
ubus list | grep -q '^bench.target$' || { echo "provider did not register"; exit 1; }

# real objects on the bus as well, so lookup_all has something to walk
/sbin/rpcd >/tmp/out/rpcd.log 2>&1 & rp=$!
i=0; while [ $i -lt 15 ]; do ubus list | grep -q '^uci$' && break; i=$((i+1)); sleep 1; done
echo "objects: $(ubus list | wc -l)"

cpu() { awk '{print $14+$15}' /proc/$bus/stat 2>/dev/null; }
rss() { awk '/VmRSS/{print $2}' /proc/$bus/status 2>/dev/null; }
fds() { ls /proc/$bus/fd 2>/dev/null | wc -l; }

c0=$(cpu); r0=$(rss); f0=$(fds)
# each phase gets a hard bound so a stall shows up as one missing line rather
# than as a run that never ends
guard() { "$@" & gp=$!; ( sleep 120; kill $gp 2>/dev/null ) & kp=$!; wait $gp 2>/dev/null; kill $kp 2>/dev/null; wait $kp 2>/dev/null; }
guard /tmp/bench $S lookup     $N
guard /tmp/bench $S lookup_all $((N / 10))
guard /tmp/bench $S invoke     $N
guard /tmp/bench $S notify     $N
c1=$(cpu); r1=$(rss); f1=$(fds)
echo "daemon_cpu_ticks: $((c1 - c0))"
echo "daemon_rss_kib_before: $r0 after: $r1 delta: $((r1 - r0))"
echo "daemon_fd_delta: $((f1 - f0))"

# eight concurrent clients doing the same invoke load
echo "--- 8 concurrent clients"
c2=$(cpu)
# wait only on the load clients: a bare `wait` would also wait for the daemon,
# the provider and rpcd, which never exit.
pids=
j=0
while [ $j -lt 8 ]; do
	/tmp/bench $S invoke $((N / 4)) > /tmp/out/con-$j.txt 2>&1 &
	pids="$pids $!"
	j=$((j + 1))
done
for p in $pids; do wait "$p" 2>/dev/null; done
c3=$(cpu)
cat /tmp/out/con-*.txt | awk '{print}' | sed 's/^invoke /concurrent_invoke /'
echo "concurrent_daemon_cpu_ticks: $((c3 - c2))"
echo "rss_after_concurrent_kib: $(rss) fd_delta_total: $(( $(fds) - f0 ))"

kill $rp $srv $bus 2>/dev/null
exit 0

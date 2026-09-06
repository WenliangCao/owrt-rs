#!/bin/sh
set -u
mkdir -p /var/run/ubus /tmp/out; chmod 1777 /var/run/ubus
ip link set lo up 2>/dev/null || true
S=/var/run/ubus/ubus.sock
/sbin/ubusd-under-test >/tmp/out/bus.log 2>&1 & bus=$!
i=0; while [ $i -lt 10 ]; do [ -S $S ] && break; i=$((i+1)); sleep 1; done
# a real provider, so malformed traffic has live state to disturb
/sbin/rpcd >/tmp/out/rpcd.log 2>&1 & rp=$!
i=0; while [ $i -lt 15 ]; do ubus list | grep -q '^uci$' && break; i=$((i+1)); sleep 1; done
before=$(ubus list | sort | tr '\n' ' ')
/tmp/fuzz $S 600
echo "survived: $(kill -0 $bus 2>/dev/null && echo yes || echo no)"
echo "final objects unchanged: $([ "$before" = "$(ubus list | sort | tr '\n' ' ')" ] && echo yes || echo no)"
echo "final serving: $(ubus -S call session list '{}' >/dev/null 2>&1; echo $?)"
echo "final fd bounded: $([ $(ls /proc/$bus/fd | wc -l) -lt 32 ] && echo yes || echo no)"
kill $rp $bus 2>/dev/null
exit 0

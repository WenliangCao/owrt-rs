#!/bin/sh
set -u
mkdir -p /var/run/ubus /tmp/out; chmod 1777 /var/run/ubus
ip link set lo up 2>/dev/null || true
S=/var/run/ubus/ubus.sock
/sbin/ubusd-under-test >/tmp/out/bus.log 2>&1 & bus=$!
i=0; while [ $i -lt 10 ]; do [ -S $S ] && break; i=$((i+1)); sleep 1; done
# a real provider, so malformed traffic has live state to disturb
/sbin/rpcd >/tmp/out/rpcd.log 2>&1 & rp=$!
# rpcd registers its plugin objects (luci, network.rrdns) a moment after uci;
# take the baseline only once two listings a second apart agree, or the final
# comparison races the provider rather than testing the bus.
i=0; prev=; while [ $i -lt 20 ]; do
	cur=$(ubus list | sort | tr '\n' ' ')
	case "$cur" in *"uci "*) [ "$cur" = "$prev" ] && break ;; esac
	prev=$cur; i=$((i+1)); sleep 1
done
before=$(ubus list | sort | tr '\n' ' ')
/tmp/fuzz $S 600
echo "survived: $(kill -0 $bus 2>/dev/null && echo yes || echo no)"
echo "final objects unchanged: $([ "$before" = "$(ubus list | sort | tr '\n' ' ')" ] && echo yes || echo no)"
echo "final serving: $(ubus -S call session list '{}' >/dev/null 2>&1; echo $?)"
echo "final fd bounded: $([ $(ls /proc/$bus/fd | wc -l) -lt 32 ] && echo yes || echo no)"
kill $rp $bus 2>/dev/null
exit 0

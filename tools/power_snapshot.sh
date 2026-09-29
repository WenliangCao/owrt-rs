#!/bin/sh
# Read-only; invoked under the standalone helper's time/output limits.
printf 'wall='; date -Iseconds
printf 'boot='; cat /proc/sys/kernel/random/boot_id
printf 'uptime='; cat /proc/uptime
echo '[link]'
for dev in wan eth0 br-lan phy0-ap0 phy1-ap0; do
    printf '%s ' "$dev"
    for field in ifindex operstate carrier flags; do
        printf '%s=' "$field"
        cat "/sys/class/net/$dev/$field" 2>/dev/null || printf 'missing\n'
    done
done
ip link show
echo '[addresses]'
ip -4 address show
ip -6 address show
echo '[routes and rules]'
ip -4 route show table all
ip -6 route show table all
ip -4 rule show
ip -6 rule show
cat /proc/net/route /proc/net/ipv6_route
echo '[processes]'
ps w
echo '[protocol runtime files]'
for file in /var/run/udhcpc-wan.pid /tmp/resolv.conf.d/resolv.conf.auto; do
    echo "$file"
    cat "$file" 2>/dev/null
done
echo '[network ubus]'
/bin/ubus -S -t 2 call network.interface dump
echo '[recent log]'
logread 2>&1 | tail -80
echo '[kernel tail]'
dmesg | tail -50
echo '[snapshot complete]'

#!/bin/sh
# Run on the router from /tmp/warp-stage (warp-failover, warp-failover.init,
# wg.conf, address4). Installs the service and arms a detached rollback that
# fires after 180 s unless /tmp/warp-confirm exists.
set -e
S=/tmp/warp-stage

cp /etc/config/firewall /tmp/warp-firewall.bak

cat >/tmp/warp-rollback.sh <<'EOF'
#!/bin/sh
/etc/init.d/warp-failover stop 2>/dev/null
/etc/init.d/warp-failover disable 2>/dev/null
/usr/sbin/warp-failover cleanup 2>/dev/null
cp /tmp/warp-firewall.bak /etc/config/firewall
fw4 reload
logger -t warp-failover "rolled back"
EOF
chmod 700 /tmp/warp-rollback.sh

mkdir -p /etc/warp
chmod 700 /etc/warp
cp "$S/wg.conf" "$S/address4" /etc/warp/
chmod 600 /etc/warp/wg.conf /etc/warp/address4
cp "$S/warp-failover" /usr/sbin/warp-failover
cp "$S/warp-failover.init" /etc/init.d/warp-failover
chmod 755 /usr/sbin/warp-failover /etc/init.d/warp-failover

uci add_list firewall.@zone[1].device='warp'
uci commit firewall
fw4 reload

/etc/init.d/warp-failover enable
/etc/init.d/warp-failover start

rm -f /tmp/warp-confirm
setsid sh -c 'sleep 180; [ -f /tmp/warp-confirm ] || /tmp/warp-rollback.sh' </dev/null >/dev/null 2>&1 &
echo "installed; rollback armed for 180 s"

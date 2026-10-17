set -eu
field() { "$@"; printf "\034"; }
boot=$(cat /proc/sys/kernel/random/boot_id)
field printf "%s\n" "$boot"
field date -u +%s
field cat /proc/uptime
field uname -r
printf 'component installed rom\n'
printf "fw4 %s %s\n" "$(sha256sum /sbin/fw4 | cut -d' ' -f1)" "$(sha256sum /rom/sbin/fw4 | cut -d' ' -f1)"
printf "httpd %s %s\n" "$(sha256sum /usr/sbin/uhttpd | cut -d' ' -f1)" "$(sha256sum /rom/usr/sbin/uhttpd | cut -d' ' -f1)"
printf "logd %s %s\n" "$(sha256sum /sbin/logd | cut -d' ' -f1)" "$(sha256sum /rom/sbin/logd | cut -d' ' -f1)"
printf "netifd %s %s\n" "$(sha256sum /sbin/netifd | cut -d' ' -f1)" "$(sha256sum /rom/sbin/netifd | cut -d' ' -f1)"
printf "procd %s %s\n" "$(sha256sum /sbin/procd | cut -d' ' -f1)" "$(sha256sum /rom/sbin/procd | cut -d' ' -f1)"
printf "reload-config %s %s\n" "$(sha256sum /sbin/reload_config | cut -d' ' -f1)" "$(sha256sum /rom/sbin/reload_config | cut -d' ' -f1)"
printf "rpcd %s %s\n" "$(sha256sum /sbin/rpcd | cut -d' ' -f1)" "$(sha256sum /rom/sbin/rpcd | cut -d' ' -f1)"
printf "ubusd %s %s\n" "$(sha256sum /sbin/ubusd | cut -d' ' -f1)" "$(sha256sum /rom/sbin/ubusd | cut -d' ' -f1)"
printf "uci %s %s\n" "$(sha256sum /sbin/uci | cut -d' ' -f1)" "$(sha256sum /rom/sbin/uci | cut -d' ' -f1)"
printf "dnsmasq %s %s\n" "$(sha256sum /usr/sbin/dnsmasq | cut -d' ' -f1)" "$(sha256sum /rom/usr/sbin/dnsmasq | cut -d' ' -f1)"
printf "\034"
dns_pid=
dns_start=
pids=1
matched=0
for p in $pids; do
 digest=$(sha256sum /proc/$p/exe | cut -d' ' -f1)
 if [ "$digest" = 59fbe5235d630e15296d5c66c09a2f5db4c466f69fb8cb8b7e94ee3eb918c72e ]; then
  matched=$((matched+1))
  printf "procd %s %s\n" "$p" "$digest"
  cat /proc/$p/stat
 else
  exit 3
 fi
done
[ "$matched" -eq 1 ]
pids=$(pidof ubusd)
matched=0
for p in $pids; do
 digest=$(sha256sum /proc/$p/exe | cut -d' ' -f1)
 if [ "$digest" = ab3bff56b6ba5d798701d0e73d20469a36cf1ea0773fdd64a0eb9411ec1fc42d ]; then
  matched=$((matched+1))
  printf "ubusd %s %s\n" "$p" "$digest"
  cat /proc/$p/stat
 else
  exit 3
 fi
done
[ "$matched" -eq 1 ]
pids=$(pidof netifd)
matched=0
for p in $pids; do
 digest=$(sha256sum /proc/$p/exe | cut -d' ' -f1)
 if [ "$digest" = 282a4c224d984228a0ab7c6d7169e4797f3e3e60cc03fa78b61fbe0fdd43bad2 ]; then
  matched=$((matched+1))
  printf "netifd %s %s\n" "$p" "$digest"
  cat /proc/$p/stat
 else
  exit 3
 fi
done
[ "$matched" -eq 1 ]
pids=$(pidof rpcd)
matched=0
for p in $pids; do
 digest=$(sha256sum /proc/$p/exe | cut -d' ' -f1)
 if [ "$digest" = fa4af38a2761636329a14436587eae871e8902eaf617ec787ab9d79434262226 ]; then
  matched=$((matched+1))
  printf "rpcd %s %s\n" "$p" "$digest"
  cat /proc/$p/stat
 else
  exit 3
 fi
done
[ "$matched" -eq 1 ]
pids=$(pidof logd)
matched=0
for p in $pids; do
 digest=$(sha256sum /proc/$p/exe | cut -d' ' -f1)
 if [ "$digest" = 324621fe9dc0ac85646098077eb263962182e20f5866b60b28a8fae414d39c05 ]; then
  matched=$((matched+1))
  printf "logd %s %s\n" "$p" "$digest"
  cat /proc/$p/stat
 else
  exit 3
 fi
done
[ "$matched" -eq 1 ]
pids=$(pidof uhttpd)
matched=0
for p in $pids; do
 digest=$(sha256sum /proc/$p/exe | cut -d' ' -f1)
 if [ "$digest" = c27a4acbb408a0473c09a3d917174ae800ffd8dbc3262d92017a82e0f4fe36bc ]; then
  matched=$((matched+1))
  printf "httpd %s %s\n" "$p" "$digest"
  cat /proc/$p/stat
 else
  exit 3
 fi
done
[ "$matched" -eq 1 ]
pids=$(pidof dnsmasq)
matched=0
for p in $pids; do
 digest=$(sha256sum /proc/$p/exe | cut -d' ' -f1)
 if [ "$digest" = f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08 ]; then
  matched=$((matched+1))
  printf "dnsmasq %s %s\n" "$p" "$digest"
  cat /proc/$p/stat
  dns_pid=$p
  dns_start=$(awk '{print $22}' /proc/$p/stat)
 else
  [ "$digest" = b141627f4c2064b69f214ecc1425904544b69b5b2210fb3195f10ad587c48644 ]
 fi
done
[ "$matched" -eq 1 ]
printf "\034"
field cat /proc/$dns_pid/status
field sh -c 'ls /proc/"$1"/fd | wc -l' sh "$dns_pid"
field cat /proc/$dns_pid/stat
nft list table inet fw4 >/dev/null
field printf 'firewall-present\n'
uci -q get 'system.@system[0].timezone' >/dev/null
field printf 'uci-read-ok\n'
field ubus -S -t 3 call system watchdog
field logread -l 200
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ]
[ "$(awk '{print $22}' /proc/$dns_pid/stat)" = "$dns_start" ]
[ "$(sha256sum /proc/$dns_pid/exe | cut -d' ' -f1)" = f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08 ]
field printf "same-identity\n"
field date -u +%s

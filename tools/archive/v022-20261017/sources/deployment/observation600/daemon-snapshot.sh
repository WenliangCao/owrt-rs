set -eu
pid=${DNSMASQ_PID:?set the observed dnsmasq PID}
printf 'BEGIN dnsmasq %s\n' "$pid"
cat /proc/$pid/stat
sha256sum /proc/$pid/exe
cat /proc/$pid/status
printf 'FDCOUNT '; ls /proc/$pid/fd | wc -l
printf 'FINALSTAT '; cat /proc/$pid/stat
printf 'END\n'
pid=${HTTPD_PID:?set the observed httpd PID}
printf 'BEGIN httpd %s\n' "$pid"
cat /proc/$pid/stat
sha256sum /proc/$pid/exe
cat /proc/$pid/status
printf 'FDCOUNT '; ls /proc/$pid/fd | wc -l
printf 'FINALSTAT '; cat /proc/$pid/stat
printf 'END\n'
pid=${LOGD_PID:?set the observed logd PID}
printf 'BEGIN logd %s\n' "$pid"
cat /proc/$pid/stat
sha256sum /proc/$pid/exe
cat /proc/$pid/status
printf 'FDCOUNT '; ls /proc/$pid/fd | wc -l
printf 'FINALSTAT '; cat /proc/$pid/stat
printf 'END\n'
pid=${NETIFD_PID:?set the observed netifd PID}
printf 'BEGIN netifd %s\n' "$pid"
cat /proc/$pid/stat
sha256sum /proc/$pid/exe
cat /proc/$pid/status
printf 'FDCOUNT '; ls /proc/$pid/fd | wc -l
printf 'FINALSTAT '; cat /proc/$pid/stat
printf 'END\n'
pid=${PROCD_PID:?set the observed procd PID}
printf 'BEGIN procd %s\n' "$pid"
cat /proc/$pid/stat
sha256sum /proc/$pid/exe
cat /proc/$pid/status
printf 'FDCOUNT '; ls /proc/$pid/fd | wc -l
printf 'FINALSTAT '; cat /proc/$pid/stat
printf 'END\n'
pid=${RPCD_PID:?set the observed rpcd PID}
printf 'BEGIN rpcd %s\n' "$pid"
cat /proc/$pid/stat
sha256sum /proc/$pid/exe
cat /proc/$pid/status
printf 'FDCOUNT '; ls /proc/$pid/fd | wc -l
printf 'FINALSTAT '; cat /proc/$pid/stat
printf 'END\n'
pid=${UBUSD_PID:?set the observed ubusd PID}
printf 'BEGIN ubusd %s\n' "$pid"
cat /proc/$pid/stat
sha256sum /proc/$pid/exe
cat /proc/$pid/status
printf 'FDCOUNT '; ls /proc/$pid/fd | wc -l
printf 'FINALSTAT '; cat /proc/$pid/stat
printf 'END\n'

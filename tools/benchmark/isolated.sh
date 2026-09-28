#!/bin/sh
# One component at a time, all dependencies from the exact original image.
# Usage (root): sh isolated.sh ROOTFS BUNDLE COMPONENT c|rs OUT [N]
# BUNDLE contains ns-exec, owrt-benchmark and the nine shipped Rust binaries.
# On a physical router this is a device mutation and requires its recovery gate.
set -eu
case "${OWRT_BENCH_TRACE:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_HTTPD_MATRIX:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_HTTPD_CGI_STRESS:-0}" in 0|1) ;; *) exit 2 ;; esac
if [ -n "${OWRT_HTTPD_WORKLOADS:-}" ]; then
    [ "${OWRT_HTTPD_MATRIX:-0}" = 1 ] || exit 2
    http_seen=' '
    for lane in $OWRT_HTTPD_WORKLOADS; do
        case "$lane" in
            jsonrpc|jsonrpc_c4|jsonrpc_large|jsonrpc_large_c4|cgi|cgi_c4|static_512_dat_c[14]|static_16k_dat_c[14]|static_16k_css_c[14]|static_image_css_c[14]|static_64k_dat_c[14]|static_1m_dat_c[14]) ;;
            *) echo "invalid HTTP workload: $lane" >&2; exit 2 ;;
        esac
        case "$http_seen" in *" $lane "*) exit 2 ;; esac
        http_seen="$http_seen$lane "
    done
fi
fw4_seen=' '
for lane in ${OWRT_FW4_WORKLOADS:-print check}; do
    case "$lane" in print|check) ;; *) echo "invalid fw4 workload: $lane" >&2; exit 2 ;; esac
    case "$fw4_seen" in *" $lane "*) echo "duplicate fw4 workload: $lane" >&2; exit 2 ;; esac
    fw4_seen="$fw4_seen$lane "
done
[ "$fw4_seen" != ' ' ] || exit 2
if [ -n "${OWRT_FW4_COUNT+x}" ]; then
    case "$OWRT_FW4_COUNT" in ''|*[!0-9]*) exit 2 ;; esac
    [ "$OWRT_FW4_COUNT" -gt 0 ] || exit 2
fi
case "${OWRT_FW4_WARMUP:-3}" in ''|*[!0-9]*) exit 2 ;; esac
[ "${OWRT_FW4_WARMUP:-3}" -le 100000 ] || exit 2
if [ -n "${OWRT_FW4_FIXTURE_SHA256+x}" ]; then
    case "$OWRT_FW4_FIXTURE_SHA256" in ''|*[!0-9a-f]*) exit 2 ;; esac
    [ "${#OWRT_FW4_FIXTURE_SHA256}" -eq 64 ] || exit 2
fi
case "${OWRT_HTTPD_RPC_PROFILE:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_HTTPD_MEMORY:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_HTTPD_DIAG:-0}" in 0|paced|memory) ;; *) exit 2 ;; esac
for diag_number in "${OWRT_HTTPD_DIAG_GAP_MS:-0}" "${OWRT_HTTPD_DIAG_CLIENTS:-4}" "${OWRT_HTTPD_DIAG_ROUNDS:-40}" "${OWRT_HTTPD_NETEM_MS:-0}"; do
    case "$diag_number" in ''|*[!0-9]*) exit 2 ;; esac
done
if [ "${OWRT_HTTPD_DIAG:-0}" != 0 ] && [ "$(( ${OWRT_HTTPD_MATRIX:-0} + ${OWRT_HTTPD_CGI_STRESS:-0} + ${OWRT_HTTPD_RPC_PROFILE:-0} + ${OWRT_HTTPD_MEMORY:-0} ))" -ne 0 ]; then
    echo 'HTTP diagnostics require their own run' >&2
    exit 2
fi
case "${OWRT_RPCD_MATRIX:-0}" in 0|1) ;; *) exit 2 ;; esac
if [ -n "${OWRT_RPCD_WORKLOADS:-}" ]; then
    [ "${OWRT_RPCD_MATRIX:-0}" = 1 ] || exit 2
    rpcd_seen=' '
    for lane in $OWRT_RPCD_WORKLOADS; do
        case "${lane%_c4}" in
            uci_configs|uci_get_network|file_stat|session_access|uci_get_64|uci_get_authorized|session_access_granted|file_list|session_access_64|uci_state_network|uci_get_delta|session_access_acl256|luci_version|luci_features|luci_devices) ;;
            *) echo "invalid RPCD workload: $lane" >&2; exit 2 ;;
        esac
        case "$rpcd_seen" in *" $lane "*) exit 2 ;; esac
        rpcd_seen="$rpcd_seen$lane "
    done
fi
case "${OWRT_PROCD_MATRIX:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_UCI_MATRIX:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_PROCD_WARMUP:-20}" in ''|*[!0-9]*) exit 2 ;; esac
[ "${OWRT_PROCD_WARMUP:-20}" -le 100000 ] || exit 2
if [ -n "${OWRT_PROCD_WORKLOADS:-}" ]; then
    [ "${OWRT_PROCD_MATRIX:-0}" = 1 ] || exit 2
    procd_seen=' '
    for lane in $OWRT_PROCD_WORKLOADS; do
        case "$lane" in
            system_info|system_info_c4|service_list_32|service_list_32_c4|service_list_128|service_list_128_c4|service_list_named_128|service_list_named_128_c4|service_list_instance_fields) ;;
            *) echo "invalid procd workload: $lane" >&2; exit 2 ;;
        esac
        case "$procd_seen" in *" $lane "*) exit 2 ;; esac
        procd_seen="$procd_seen$lane "
    done
fi
case "${OWRT_UBUSD_MATRIX:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_UBUSD_NORMALIZED:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_UBUSD_EXTENDED:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_RELOAD_CONFIG_MATRIX:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_RELOAD_CONFIG_WARMUP:-5}" in ''|*[!0-9]*) exit 2 ;; esac
[ "${OWRT_RELOAD_CONFIG_WARMUP:-5}" -le 100000 ] || exit 2
case "${OWRT_RELOAD_CONFIG_PACKAGES:-4}" in 4|24|64|128) ;; *) exit 2 ;; esac
case "${OWRT_NETIFD_MATRIX:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_NETIFD_SCALE:-32}" in 32|64|128) ;; *) exit 2 ;; esac
case "${OWRT_NETIFD_EVENT_CAPTURE:-0}" in 0|1) ;; *) exit 2 ;; esac
netifd_events=0
if [ "${OWRT_NETIFD_WORKLOADS:-}" = events_static2 ]; then netifd_events=1; fi
case " ${OWRT_NETIFD_WORKLOADS:-} " in *" events_static2 "*) [ "$netifd_events" = 1 ] || exit 2 ;; esac
netifd_scale=${OWRT_NETIFD_SCALE:-32}
netifd_digits=2
[ "$netifd_scale" -ne 128 ] || netifd_digits=3
case "${OWRT_NETIFD_WARMUP:-20}" in ''|*[!0-9]*) exit 2 ;; esac
case "${OWRT_RPCD_CLIENT_DIAGNOSTIC:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_RPCD_CLIENT_ORDER:-tree-first}" in tree-first|wire-first) ;; *) exit 2 ;; esac
case "${OWRT_RPCD_PROFILE:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_RPCD_PROFILE_KIND:-rpc}" in rpc|file|uci_reply|uci|readiness|session_acl|luci|lucirpc) ;; *) exit 2 ;; esac
if [ "${OWRT_RPCD_PROFILE:-0}" = 1 ] && [ "${OWRT_RPCD_MATRIX:-0}" = 1 ]; then
    echo 'RPC profiling and the performance matrix are separate runs' >&2
    exit 2
fi
if [ "${OWRT_RPCD_CLIENT_DIAGNOSTIC:-0}" = 1 ] && [ "$(( ${OWRT_RPCD_MATRIX:-0} + ${OWRT_RPCD_PROFILE:-0} ))" -ne 0 ]; then
    echo 'Client diagnostics are separate from the performance matrix and profiling' >&2
    exit 2
fi
if [ "$(( ${OWRT_HTTPD_MATRIX:-0} + ${OWRT_HTTPD_CGI_STRESS:-0} + ${OWRT_HTTPD_RPC_PROFILE:-0} + ${OWRT_HTTPD_MEMORY:-0} ))" -gt 1 ]; then
    echo 'HTTPD matrix, CGI stress, RPC profiling and held-connection memory are separate runs' >&2
    exit 2
fi

if [ "${1:-}" = --namespace ]; then
    shift
    [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
    image=$1; bundle=$2; component=$3; impl=$4; out=$5; n=$6; work=$7; script=$8
    root=$work/root
    mkdir "$root"
    mount --bind "$image" "$root"
    mount -o remount,bind,ro "$root"
    for dir in tmp etc dev; do mount -t tmpfs -o mode=0755 tmpfs "$root/$dir"; done
    chmod 1777 "$root/tmp"
    cp -a "$image/etc/." "$root/etc/"
    mkdir -p "$root/etc/config" "$root/tmp/bin" "$root/tmp/out" "$root/tmp/acl"
    cp -a "$image/usr/share/acl.d/." "$root/tmp/acl/"
    chown -R 0:0 "$root/tmp/acl"
    mount --bind "$root/tmp/acl" "$root/usr/share/acl.d"
    mount --bind "$bundle" "$root/tmp/bin"
    mount -o remount,bind,ro "$root/tmp/bin"
    if [ "$component" = netifd ] && [ -d "$bundle/netifd-fixture" ]; then
        mount --bind "$bundle/netifd-fixture/mac80211.sh" "$root/lib/netifd/wireless/mac80211.sh"
        mount -o remount,bind,ro "$root/lib/netifd/wireless/mac80211.sh"
    fi
    mount --bind "$out" "$root/tmp/out"
    mount --bind /proc "$root/proc"
    mount -t sysfs sysfs "$root/sys"
    mknod -m 666 "$root/dev/null" c 1 3
    mknod -m 666 "$root/dev/zero" c 1 5
    mknod -m 666 "$root/dev/random" c 1 8
    mknod -m 666 "$root/dev/urandom" c 1 9
    ln -s /proc/self/fd "$root/dev/fd"
    ln -s /proc/self/fd/0 "$root/dev/stdin"
    ln -s /proc/self/fd/1 "$root/dev/stdout"
    ln -s /proc/self/fd/2 "$root/dev/stderr"
    # kmsg is global even in a PID/net namespace. Neither implementation may
    # consume the router's kernel log or access its hardware watchdog.
    if [ "$component" = logd ]; then
        # /dev/null is perpetually readable to poll(), causing the Rust logd
        # to spin while the epoll-based original rejects that descriptor.
        # Keep both ends of an empty FIFO open to model an idle kernel log.
        mkfifo -m 600 "$root/dev/bench-kmsg"
        exec 3<>"$root/dev/bench-kmsg"
        mount --bind "$root/dev/bench-kmsg" "$root/proc/kmsg"
    else
        mount --bind "$root/dev/null" "$root/proc/kmsg"
    fi
    cp "$script" "$root/tmp/workload.sh"
    if [ "${OWRT_HTTPD_NETEM_MS:-0}" -gt 0 ]; then
        [ "${OWRT_HTTPD_DIAG:-0}" = paced ] && [ "$component" = httpd ]
        [ "$OWRT_HTTPD_NETEM_MS" -le 500 ]
        # This is the verified private network namespace, before chroot.
        # No production interface or management path receives a qdisc.
        ip link set lo up
        tc qdisc add dev lo root netem delay "${OWRT_HTTPD_NETEM_MS}ms"
        tc -s qdisc show dev lo > "$out/netem.txt"
    fi
    exec chroot "$root" /bin/sh /tmp/workload.sh --workload "$component" "$impl" "$n"
fi

if [ "${1:-}" = --workload ]; then
    shift
    [ "${OWRT_BENCH_NAMESPACE:-}" = 1 ] || exit 125
    component=$1; impl=$2; n=$3
    if [ "${OWRT_UBUSD_NORMALIZED:-0}" = 1 ]; then [ "$component" = ubusd ]; fi
    bench=/tmp/bin/owrt-benchmark
    rpc_mode=rpc
    out=/tmp/out
    sha256sum "$bench" /tmp/bin/ns-exec > "$out/benchmark-sha256.txt"
    sha256sum /tmp/workload.sh > "$out/harness-sha256.txt"
    socket=/var/run/ubus/ubus.sock
    cat /proc/cpuinfo > "$out/cpuinfo.txt"
    cat /proc/sys/kernel/random/boot_id > "$out/boot-id.txt"
    uname -r > "$out/kernel.txt"
    mkdir -p /var/run/ubus /var/lock /var/state /tmp/empty-init /tmp/empty-rc
    ip link set lo up
    cat > /etc/config/network <<'EOF'
config interface 'loopback'
    option device 'lo'
    option proto 'static'
    option ipaddr '127.0.0.1/8'
config device
    option name 'br-bench'
    option type 'bridge'
    option bridge_empty '1'
config interface 'lan'
    option device 'br-bench'
    option proto 'static'
    option ipaddr '192.0.2.1/24'
    option ip6addr '2001:db8:84::1/64'
EOF
    if [ "$netifd_events" = 1 ]; then
        [ "$component" = netifd ] && [ "${OWRT_NETIFD_MATRIX:-0}" = 1 ]
        cat > /etc/config/network <<'EOF'
config interface 'loopback'
 option device 'lo'
 option proto 'static'
 option ipaddr '127.0.0.1/8'
config device
 option name 'br-event0'
 option macaddr '02:00:00:ee:00:01'
 option type 'bridge'
 option bridge_empty '1'
config interface 'lan'
 option device 'br-event0'
 option proto 'static'
 option ipaddr '192.0.2.1/24'
config device
 option name 'br-event1'
 option macaddr '02:00:00:ee:00:02'
 option type 'bridge'
 option bridge_empty '1'
config interface 'wired'
 option device 'br-event1'
 option proto 'static'
 option ipaddr '198.51.100.1/24'
EOF
    fi
    if [ "$component" = netifd ] && [ -d /tmp/bin/netifd-fixture ]; then
        cp /tmp/bin/netifd-fixture/wireless /etc/config/wireless
    else
        : > /etc/config/wireless
    fi
    cat > /etc/config/firewall <<'EOF'
config defaults
    option input 'ACCEPT'
    option output 'ACCEPT'
    option forward 'REJECT'
config zone
    option name 'lan'
    list network 'lan'
    option input 'ACCEPT'
    option output 'ACCEPT'
    option forward 'ACCEPT'
EOF
    if [ "$component" = fw4 ]; then
        if [ -f /tmp/bin/fw4-firewall ] || [ -n "${OWRT_FW4_FIXTURE_SHA256:-}" ]; then
            [ -n "${OWRT_FW4_FIXTURE_SHA256:-}" ]
            [ "$(sha256sum /tmp/bin/fw4-firewall | cut -d ' ' -f 1)" = "$OWRT_FW4_FIXTURE_SHA256" ]
            cp /tmp/bin/fw4-firewall /etc/config/firewall
        fi
        sha256sum /etc/config/firewall > "$out/fw4-fixture.sha256"
        sha256sum /sbin/ubusd /sbin/netifd /sbin/uci /usr/sbin/nft /usr/bin/ucode \
            /sbin/fw4 /usr/share/ucode/fw4.uc /usr/share/firewall4/main.uc \
            > "$out/fw4-dependencies.sha256"
    fi
    # A larger, fixed config exercises UCI iteration and reload's MD5 walk.
    i=0
    while [ "$i" -lt 64 ]; do
        printf "config bench 'entry%s'\n option value 'fixed-%s'\n list members 'alpha'\n list members 'beta'\n" "$i" "$i"
        i=$((i + 1))
    done > /etc/config/r84fixture
    printf '{}\n' > /tmp/empty.json
    printf '{"ok":1}\n' > /tmp/ok.json
    printf '{"n":1}\n' > /tmp/ping.json
    : > /tmp/empty.bytes

    if [ "${OWRT_RPCD_PROFILE:-0}" = 1 ]; then
        [ "$component" = rpcd ] && [ "$impl" = rs ]
        kind=${OWRT_RPCD_PROFILE_KIND:-rpc}
        sha256sum "/tmp/bin/${kind}_profile" > "$out/profile-sha256.txt"
        sha256sum /etc/passwd /etc/group > "$out/profile-fixtures.sha256"
        if [ "$kind" = uci ]; then
            sha256sum /etc/config/network /etc/config/r84fixture >> "$out/profile-fixtures.sha256"
            /tmp/bin/uci_profile /etc/config "$n" "${OWRT_RPCD_PROFILE_FILTER:-}" > "$out/$kind-profile.csv"
        else
            "/tmp/bin/${kind}_profile" "$n" "${OWRT_RPCD_PROFILE_FILTER:-}" > "$out/$kind-profile.csv"
        fi
        touch "$out/COMPLETE"
        exit 0
    fi

    choose() { # component original candidate
        if [ "$component" = "$1" ] && [ "$impl" = rs ]; then
            printf '/tmp/bin/%s\n' "$3"
        else printf '%s\n' "$2"; fi
    }
    start_trace() {
        [ "${OWRT_BENCH_TRACE:-0}" = 1 ] || return 0
        sha256sum /tmp/bin/strace > "$out/strace-sha256.txt"
        printf 'strace syscall counts and blocked wall time; diagnostic only\n' > "$out/TRACE_DIAGNOSTIC"
        /tmp/bin/strace -f -c -w -S calls -o "$out/syscalls.txt" -p "$subject" > "$out/strace.log" 2>&1 & tracer=$!
        attempts=0
        until [ "$(awk '/^TracerPid:/ {print $2}' /proc/"$subject"/status)" = "$tracer" ]; do
            kill -0 "$tracer"
            [ "$attempts" -lt 5 ]
            sleep 1; attempts=$((attempts + 1))
        done
    }
    wait_object() {
        object=$1; pid=$2; tries=0
        while [ "$tries" -lt 100 ]; do
            kill -0 "$pid" || { echo "daemon exited before registering $object" >&2; exit 1; }
            if ubus -t 1 list "$object" 2>/dev/null | grep -qx "$object"; then return; fi
            sleep 1; tries=$((tries + 1))
        done
        echo "object readiness failed: $object" >&2; exit 1
    }
    netifd_lane_selected() {
        [ "$component" = netifd ] && [ -n "${OWRT_NETIFD_WORKLOADS:-}" ] || return 0
        case " $OWRT_NETIFD_WORKLOADS " in *" $1 "*) return 0 ;; *) return 1 ;; esac
    }
    procd_lane_selected() {
        [ "$component" = procd ] && [ -n "${OWRT_PROCD_WORKLOADS:-}" ] || return 0
        case " $OWRT_PROCD_WORKLOADS " in *" $1 "*) return 0 ;; *) return 1 ;; esac
    }
    rpc_warmup=20
    [ "$component" != procd ] || rpc_warmup=${OWRT_PROCD_WARMUP:-20}
    [ "$component" != netifd ] || rpc_warmup=${OWRT_NETIFD_WARMUP:-20}
    netifd_no_spawn() ( # lane phase; all work is outside benchmark intervals
        [ "$component" = netifd ] || return 0
        set -eu
        nsp_lane=$1; nsp_phase=$2; nsp_root=${3:-/proc}
        nsp_dir=$out/no-spawn/$nsp_lane/$nsp_phase
        [ ! -e "$nsp_dir" ]; mkdir -p "$nsp_dir"
        trap 'nsp_rc=$?; if [ "$nsp_rc" -ne 0 ]; then printf "%s\n" "$nsp_rc" > "$nsp_dir/FAILED"; fi' EXIT
        nsp_roles=bus
        [ "$nsp_lane" != events_static2 ] || nsp_roles='bus listen subscribe'
        printf 'schema=1\nlane=%s\nphase=%s\nexpected_ppid=%s\n' "$nsp_lane" "$nsp_phase" "$$" > "$nsp_dir/scope.txt"
        # Keep the complete census and read errors. Missing/unreadable status
        # is never accepted as an empty child set.
        set --
        for nsp_proc in "$nsp_root"/[0-9]*; do
            [ -d "$nsp_proc" ]; set -- "$@" "$nsp_proc/status"
        done
        if awk '
            function flush() { if (file != "") { if (pid !~ /^[0-9]+$/ || parent !~ /^[0-9]+$/) bad=1; else print pid, parent, file } }
            FNR == 1 { flush(); file=FILENAME; pid=""; parent="" }
            $1 == "Pid:" { pid=$2 } $1 == "PPid:" { parent=$2 }
            END { flush(); if (bad) exit 1 }
        ' "$@" > "$nsp_dir/ppid-census.txt" 2> "$nsp_dir/ppid-census.stderr"; then nsp_scan_rc=0; else nsp_scan_rc=$?; fi
        printf '%s\n' "$nsp_scan_rc" > "$nsp_dir/ppid-census.rc"
        [ "$nsp_scan_rc" = 0 ] && [ ! -s "$nsp_dir/ppid-census.stderr" ] && [ -s "$nsp_dir/ppid-census.txt" ] || exit 1
        for nsp_role in $nsp_roles; do
            case "$nsp_role" in
                bus) nsp_pid=$bus; nsp_exe=/sbin/ubusd; nsp_sha=cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88; nsp_id=c-ubusd-24864e78 ;;
                listen) nsp_pid=$event_listen; nsp_exe=/bin/ubus; nsp_sha=9bc20e73e500c724e0ad8132b894e7dba7ca49a41cd20c38dd0b9fa23f9412eb; nsp_id=c-ubus-cli-24864e78-listen ;;
                subscribe) nsp_pid=$event_subscribe; nsp_exe=/bin/ubus; nsp_sha=9bc20e73e500c724e0ad8132b894e7dba7ca49a41cd20c38dd0b9fa23f9412eb; nsp_id=c-ubus-cli-24864e78-subscribe ;;
            esac
            case "$nsp_pid" in ''|*[!0-9]*) exit 1 ;; esac
            [ "$nsp_pid" -gt 1 ] && [ "$nsp_pid" != "$$" ] && [ "$nsp_pid" != "$subject" ] || exit 1
            nsp_one=$nsp_dir/$nsp_role; mkdir "$nsp_one"
            printf '%s %s %s\n' "$nsp_role" "$nsp_pid" "$nsp_exe" >> "$nsp_dir/targets.txt"
            awk -v parent="$nsp_pid" '$2 == parent' "$nsp_dir/ppid-census.txt" > "$nsp_one/children.txt"
            [ ! -s "$nsp_one/children.txt" ]
            cat "$nsp_root/$nsp_pid/stat" > "$nsp_one/stat.before"
            cat "$nsp_root/$nsp_pid/status" > "$nsp_one/status.before"
            readlink "$nsp_root/$nsp_pid/exe" > "$nsp_one/exe-link.txt"
            sha256sum "$nsp_root/$nsp_pid/exe" > "$nsp_one/exe.sha256"
            [ "$(awk '{print $1}' "$nsp_one/exe.sha256")" = "$nsp_sha" ]
            cat "$nsp_root/$nsp_pid/maps" > "$nsp_one/maps.txt"
            : > "$nsp_one/non-file-mappings.txt"
            # A pathname with whitespace/escapes, deleted file or unknown
            # pseudo-path is unsupported and fails; raw maps remain intact.
            awk -v special="$nsp_one/non-file-mappings.txt" '
                NF < 5 { exit 1 }
                NF == 5 { if ($2 ~ /x/ || $5 != "0") exit 1; print "anonymous\t" $0 >> special; next }
                NF != 6 { exit 1 }
                $6 ~ /^\// { if ($6 ~ /\\/) exit 1; print $6; next }
                $6 ~ /^\[(heap|stack|vdso|vvar|vvar_vclock)\]$/ || $6 ~ /^\[anon(_shmem)?:[^]]+\]$/ { if ($2 ~ /x/ && $6 != "[vdso]") exit 1; print $6 "\t" $0 >> special; next }
                { exit 1 }
            ' "$nsp_one/maps.txt" > "$nsp_one/mapped-paths.unsorted"
            LC_ALL=C sort -u "$nsp_one/mapped-paths.unsorted" > "$nsp_one/mapped-paths.txt"
            [ -s "$nsp_one/mapped-paths.txt" ]; : > "$nsp_one/mapped-files.sha256"
            while IFS= read -r nsp_file; do
                nsp_real=$(readlink -f "$nsp_file")
                [ -f "$nsp_real" ] && [ -r "$nsp_real" ] || exit 1
                printf '%s\t%s\n' "$nsp_file" "$nsp_real" >> "$nsp_one/mapped-canonical.tsv"
                sha256sum "$nsp_real" >> "$nsp_one/mapped-files.sha256"
            done < "$nsp_one/mapped-paths.txt"
            # Filter real NUL records, not newline projections. Non-LD values
            # never reach disk/stdout even if they contain fake LD_ lines.
            mkfifo "$nsp_one/environ.pipe"
            hexdump -v -e '1/1 "%u "' "$nsp_root/$nsp_pid/environ" > "$nsp_one/environ.pipe" 2> "$nsp_one/environ-read.stderr" & nsp_reader=$!
            if LC_ALL=C awk '
                { for (i=1; i<=NF; i++) { b=$i; if (b !~ /^[0-9]+$/ || b>255) exit 1;
                  if (b==0) { if (keep && eq) print hex; n=0; keep=1; eq=0; hex=""; continue }
                  n++; if ((n==1 && b!=76) || (n==2 && b!=68) || (n==3 && b!=95)) keep=0;
                  if (keep) { hex=hex sprintf("%02x",b); if (n>3 && b==61) eq=1 }
                } }
                BEGIN { keep=1 } END { if (n!=0) exit 1 }
            ' < "$nsp_one/environ.pipe" > "$nsp_one/LD-environ.hex"; then nsp_filter_rc=0; else nsp_filter_rc=$?; fi
            if wait "$nsp_reader"; then nsp_read_rc=0; else nsp_read_rc=$?; fi
            rm "$nsp_one/environ.pipe"
            [ "$nsp_filter_rc" = 0 ] && [ "$nsp_read_rc" = 0 ] && [ ! -s "$nsp_one/environ-read.stderr" ] || exit 1
            cat "$nsp_root/$nsp_pid/stat" > "$nsp_one/stat.after"
            cat "$nsp_root/$nsp_pid/status" > "$nsp_one/status.after"
            sha256sum "$nsp_root/$nsp_pid/exe" > "$nsp_one/exe-after.sha256"
            cmp "$nsp_one/exe.sha256" "$nsp_one/exe-after.sha256"
            for nsp_point in before after; do
                awk -v pid="$nsp_pid" -v parent="$$" '
                    { if (NR != 1 || $1 != pid) exit 1; sub(/^[0-9]+ \(.*\) /,"",$0);
                      if (NF<20 || $2!=parent || $14!=0 || $15!=0 || $20 !~ /^[0-9]+$/) exit 1;
                      print pid, $2, $20 }
                    END { if (NR != 1) exit 1 }
                ' "$nsp_one/stat.$nsp_point" > "$nsp_one/identity.$nsp_point"
                [ "$(awk '$1=="Pid:" {print $2}' "$nsp_one/status.$nsp_point")" = "$nsp_pid" ]
                [ "$(awk '$1=="PPid:" {print $2}' "$nsp_one/status.$nsp_point")" = "$$" ]
            done
            cmp "$nsp_one/identity.before" "$nsp_one/identity.after"
            nsp_start=$(awk '{print $3}' "$nsp_one/identity.before")
            if [ "$nsp_phase" = after ]; then
                nsp_before=$out/no-spawn/$nsp_lane/before/$nsp_role
                for nsp_identity in identity.before exe-link.txt exe.sha256 mapped-files.sha256 mapped-canonical.tsv LD-environ.hex; do
                    cmp "$nsp_before/$nsp_identity" "$nsp_one/$nsp_identity"
                done
            fi
            printf '{"schema":1,"lane":"%s","phase":"%s","pid":%s,"ppid":%s,"expected_ppid":%s,"start_ticks":%s,"role":"%s","proposed_exemption_id":"%s","exe_sha256":"%s","child_user_ticks":0,"child_system_ticks":0,"status":"evidence-ready","requires_static_proof":true}\n' "$nsp_lane" "$nsp_phase" "$nsp_pid" "$$" "$$" "$nsp_start" "$nsp_role" "$nsp_id" "$nsp_sha" > "$nsp_one/identity.json"
        done
        printf 'evidence-ready; static no-spawn closure required\n' > "$nsp_dir/EVIDENCE_READY"
    )
    rpcd_lane_selected() {
        [ "$component" = rpcd ] && [ -n "${OWRT_RPCD_WORKLOADS:-}" ] || return 0
        case " $OWRT_RPCD_WORKLOADS " in *" $1 "*) return 0 ;; *) return 1 ;; esac
    }
    rpcd_extra_selected() {
        [ -n "${OWRT_RPCD_WORKLOADS:-}" ] || return 1
        rpcd_lane_selected "$1" || rpcd_lane_selected "${1}_c4"
    }
    run_rpc() { # label object method input expected [iterations]
        netifd_lane_selected "$1" || return 0
        rpcd_lane_selected "$1" || return 0
        procd_lane_selected "$1" || return 0
        label=$1; object=$2; method=$3; input=$4; expected=$5; count=${6:-$n}
        printf '%s\n' "$input" > /tmp/input.json
        printf '%s\n' "$expected" > /tmp/expect.json
        netifd_no_spawn "$label" before
        "$bench" "$rpc_mode" "$socket" "$object" "$method" /tmp/input.json /tmp/expect.json "$count" "$rpc_warmup" "$monitors" > "$out/$label.json"
        netifd_no_spawn "$label" after
    }
    rpc_four() { # label object method input expected [total iterations]
        netifd_lane_selected "$1" || return 0
        rpcd_lane_selected "$1" || return 0
        procd_lane_selected "$1" || return 0
        label=$1; object=$2; method=$3; input=$4; expected=$5; total=${6:-$n}
        printf '%s\n' "$input" > /tmp/input.json
        printf '%s\n' "$expected" > /tmp/expect.json
        count=$((total / 4)); [ "$count" -gt 0 ] || count=1
        mkdir "$out/$label"
        printf '{"clients":4,"iterations_per_client":%s,"warmup_per_client":%s}\n' "$count" "$rpc_warmup" > "$out/$label/group.json"
        netifd_no_spawn "$label" before
        "$bench" snapshot "$monitors" > "$out/$label/before.json"
        clients=''; j=1
        while [ "$j" -le 4 ]; do
            "$bench" "$rpc_mode" "$socket" "$object" "$method" /tmp/input.json /tmp/expect.json "$count" "$rpc_warmup" "$monitors" > "$out/$label/client-$j.json" &
            clients="$clients $!"; j=$((j + 1))
        done
        failed=0
        for client in $clients; do wait "$client" || failed=1; done
        "$bench" snapshot "$monitors" > "$out/$label/after.json"
        netifd_no_spawn "$label" after
        [ "$failed" = 0 ]
    }
    rpc_pair() { # c1 then c4 with identical arguments and validation
        run_rpc "$@"
        rpc_four "$1"_c4 "$2" "$3" "$4" "$5" "${6:-$n}"
    }
    lookup_four() { # label path total; same outer CPU interval as rpc_four
        label=$1; lookup_path=$2; total=$3
        count=$((total / 4)); [ "$count" -gt 0 ] || count=1
        mkdir "$out/$label"
        printf '{"clients":4,"iterations_per_client":%s,"warmup_per_client":20}\n' "$count" > "$out/$label/group.json"
        "$bench" snapshot "$monitors" > "$out/$label/before.json"
        clients=''; j=1
        while [ "$j" -le 4 ]; do
            "$bench" lookup "$socket" "$lookup_path" "$count" 20 "$monitors" > "$out/$label/client-$j.json" &
            clients="$clients $!"; j=$((j + 1))
        done
        failed=0
        for client in $clients; do wait "$client" || failed=1; done
        "$bench" snapshot "$monitors" > "$out/$label/after.json"
        [ "$failed" = 0 ]
    }
    check_bus_objects() {
        # The frozen timing client checks bench.target on every lookup. Check
        # the complete path set separately before/after each matrix phase.
        object_index=1
        : > /tmp/ubusd-objects.expected
        while [ "$object_index" -lt "$1" ]; do
            printf 'bench.filler%04d\n' "$object_index" >> /tmp/ubusd-objects.expected
            object_index=$((object_index + 1))
        done
        printf 'bench.target\n' >> /tmp/ubusd-objects.expected
        ubus list 'bench.*' > "$out/objects-$1-$2.txt"
        cmp /tmp/ubusd-objects.expected "$out/objects-$1-$2.txt"
    }
    large_uci_expect() {
        printf '{"values":{' > /tmp/expect-large.json
        i=0; sep=''
        while [ "$i" -lt 64 ]; do
            printf '%s"entry%s":{".anonymous":false,".type":"bench",".name":"entry%s",".index":%s,"value":"fixed-%s","members":["alpha","beta"]}' "$sep" "$i" "$i" "$i" "$i" >> /tmp/expect-large.json
            sep=,; i=$((i + 1))
        done
        printf '}}\n' >> /tmp/expect-large.json
    }
    service_list_expect() {
        # Validate every service's data using the same frozen RPC client.
        service_index=0; service_sep=''
        printf '{'
        while [ "$service_index" -lt "$1" ]; do
            printf '%s"r84fixture%s":{"data":{"index":%s}}' "$service_sep" "$service_index" "$service_index"
            service_sep=,; service_index=$((service_index + 1))
        done
        printf '}\n'
    }
    procd_instance_fixture() {
        # Full verbose query: 32 fielded declarations plus running/exited instances.
        # Setup and cleanup polling are outside the native query interval.
        instance_index=0
        while [ "$instance_index" -lt 128 ]; do
            ubus call service delete "{\"name\":\"r84fixture$instance_index\"}" >/dev/null
            instance_index=$((instance_index + 1))
        done
        # respawn uses atoi(blobmsg_get_string()), so its values must be strings.
        cat > /tmp/procd-instance-set.json <<'EOF'
{"name":"r84instances","data":{"purpose":"supervision","generation":1},"triggers":[["procd.bench.never",["run_script","/bin/true"],1]],"instances":{"active":{"command":["/bin/sleep","600"],"term_timeout":1,"env":{"BENCH":"fixed","MODE":"query"},"data":{"enabled":true,"index":7},"limits":{"core":"0"},"reload_signal":1,"respawn":["600","1","1"],"triggers":[["procd.instance.never",["run_script","/bin/true"],1]]},"exited":{"command":["/bin/true"],"term_timeout":1,"data":{"reason":"completed"}},"declared":{"data":{"index":9},"env":{"ROLE":"declaration"},"term_timeout":2}}}
EOF
        cat > /tmp/procd-instance-expect.template <<'EOF'
{"r84instances":{"data":{"purpose":"supervision","generation":1},"instances":{"active":{"running":true,"pid":@PID@,"command":["/bin/sleep","600"],"term_timeout":1,"env":{"BENCH":"fixed","MODE":"query"},"data":{"enabled":true,"index":7},"limits":{"core":"0"},"reload_signal":1,"respawn":{"threshold":600,"timeout":1,"retry":1},"triggers":[["procd.instance.never",["run_script","/bin/true"],1]]},"exited":{"running":false,"command":["/bin/true"],"term_timeout":1,"exit_code":0,"data":{"reason":"completed"}},"declared":{"running":false,"term_timeout":2,"exit_code":0,"env":{"ROLE":"declaration"},"data":{"index":9}}},"triggers":[["procd.bench.never",["run_script","/bin/true"],1]]}
EOF
        : > /tmp/procd-fielded-sets.jsonl
        instance_index=0
        while [ "$instance_index" -lt 32 ]; do
            instance_name=$(printf 'r84fields%02d' "$instance_index")
            printf '{"name":"%s","data":{"index":%s,"group":"management","enabled":true},"instances":{"declared":{"term_timeout":5,"env":{"INTERFACE":"%s","LOG_LEVEL":"info","MODE":"managed"},"data":{"label":"%s","config":{"enabled":true,"network":"lan","protocol":"static","metric":100},"members":["alpha","beta","gamma"],"revision":1},"limits":{"core":"0","nofile":"1024"},"triggers":[["procd.fielded.never",["run_script","/bin/true"],1]]}},"triggers":[["procd.service.never",["run_script","/bin/true"],1]]}\n' "$instance_name" "$instance_index" "$instance_name" "$instance_name" >> /tmp/procd-fielded-sets.jsonl
            printf ',"%s":{"data":{"index":%s,"group":"management","enabled":true},"instances":{"declared":{"running":false,"term_timeout":5,"exit_code":0,"env":{"INTERFACE":"%s","LOG_LEVEL":"info","MODE":"managed"},"data":{"label":"%s","config":{"enabled":true,"network":"lan","protocol":"static","metric":100},"members":["alpha","beta","gamma"],"revision":1},"limits":{"core":"0","nofile":"1024"},"triggers":[["procd.fielded.never",["run_script","/bin/true"],1]]}},"triggers":[["procd.service.never",["run_script","/bin/true"],1]]}' "$instance_name" "$instance_index" "$instance_name" "$instance_name" >> /tmp/procd-instance-expect.template
            instance_index=$((instance_index + 1))
        done
        printf '}\n' >> /tmp/procd-instance-expect.template
        while IFS= read -r instance_config; do
            ubus call service set "$instance_config" >/dev/null
        done < /tmp/procd-fielded-sets.jsonl
        sha256sum /tmp/procd-instance-set.json /tmp/procd-fielded-sets.jsonl /tmp/procd-instance-expect.template >> "$out/procd-fixtures.sha256"
        ubus call service set "$(cat /tmp/procd-instance-set.json)" > "$out/instance-set-reply.json"
        sleep 1
        ubus call service list '{"verbose":true}' > "$out/instance-before.json"
        instance_pid=$(jsonfilter -i "$out/instance-before.json" -e '@.r84instances.instances.active.pid')
        case "$instance_pid" in ''|*[!0-9]*) echo 'missing instance pid' >&2; exit 1 ;; esac
        [ "$instance_pid" -gt 1 ] && kill -0 "$instance_pid"
        [ "$(awk '/^PPid:/ {print $2}' /proc/"$instance_pid"/status)" = "$subject" ]
        [ "$(jsonfilter -i "$out/instance-before.json" -e '@.r84instances.instances.exited.running')" = false ]
        sed "s/@PID@/$instance_pid/g" /tmp/procd-instance-expect.template > /tmp/procd-instance-expect.json
        run_rpc service_list_instance_fields service list '{"verbose":true}' "$(cat /tmp/procd-instance-expect.json)"
        ubus call service list '{"verbose":true}' > "$out/instance-after.json"
        cmp "$out/instance-before.json" "$out/instance-after.json"
        ubus call service delete '{"name":"r84instances"}' > "$out/instance-delete-reply.json"
        instance_tries=0
        while [ -e /proc/"$instance_pid" ]; do
            [ "$instance_tries" -lt 5 ]
            sleep 1; instance_tries=$((instance_tries + 1))
        done
        instance_index=0
        while [ "$instance_index" -lt 32 ]; do
            instance_name=$(printf 'r84fields%02d' "$instance_index")
            ubus call service delete "{\"name\":\"$instance_name\"}" >/dev/null
            instance_index=$((instance_index + 1))
        done
        ubus call service list '{}' > "$out/instance-closed.json"
        [ "$(tr -d ' \n\r\t' < "$out/instance-closed.json")" = '{}' ]
    }
    netifd_expect() { # total interfaces: the original two, then thirty static aliases
        printf '{"interface":['
        netifd_index=0; netifd_sep=''
        while [ "$netifd_index" -lt "$(($1 - 2))" ]; do
            printf '%s{"interface":"bench%0*d","up":true,"proto":"static","ipv4-address":[{"address":"198.18.%s.1","mask":24}]}' "$netifd_sep" "$netifd_digits" "$netifd_index" "$netifd_index"
            netifd_sep=,; netifd_index=$((netifd_index + 1))
        done
        printf '%s{"interface":"lan","up":true,"proto":"static","ipv4-address":[{"address":"192.0.2.1","mask":24}]},{"interface":"loopback","up":true,"proto":"static","ipv4-address":[{"address":"127.0.0.1","mask":8}]}]}\n' "$netifd_sep"
    }
    check_netifd_interfaces() { # full ordered names, beyond the frozen client's subset checks
        netifd_index=0
        : > /tmp/netifd-names.expected
        while [ "$netifd_index" -lt "$(($1 - 2))" ]; do
            printf 'bench%0*d\n' "$netifd_digits" "$netifd_index" >> /tmp/netifd-names.expected
            netifd_index=$((netifd_index + 1))
        done
        printf 'lan\nloopback\n' >> /tmp/netifd-names.expected
        ubus call network.interface dump > "$out/interfaces-$1-$2.json"
        jsonfilter -i "$out/interfaces-$1-$2.json" -e '@.interface[*].interface' > "$out/interface-names-$1-$2.txt"
        cmp /tmp/netifd-names.expected "$out/interface-names-$1-$2.txt"
        ubus list 'network.interface.*' > "$out/interface-objects-$1-$2.txt"
        sed 's/^/network.interface./' /tmp/netifd-names.expected > /tmp/netifd-objects.expected
        cmp /tmp/netifd-objects.expected "$out/interface-objects-$1-$2.txt"
    }
    netifd_children_reaped() {
        # This image does not expose /proc/PID/task/PID/children. Read PPid
        # from status instead, and never interpret a read failure as empty.
        netifd_children=$(awk -v parent="$subject" '$1 == "PPid:" && $2 == parent { print FILENAME }' \
            "${1:-/proc}"/[0-9]*/status 2>/dev/null) || return 1
        [ -z "$netifd_children" ]
    }
    wait_netifd_hotplug() { # check_netifd_interfaces has written the expected names
        # Interface UP precedes completion of its hotplug scripts. Wait for
        # every fixture's successful ifup callback and the parent to reap
        # all children, so query CPU cannot include setup work.
        netifd_tries=0
        while :; do
            kill -0 "$subject"; [ "$netifd_tries" -lt 90 ]
            awk '$2 == "ifup" && $3 == 0 { print $1 }' /tmp/netifd-hotplug.done | LC_ALL=C sort > /tmp/netifd-hotplug.names
            if cmp -s /tmp/netifd-names.expected /tmp/netifd-hotplug.names && netifd_children_reaped; then
                break
            fi
            sleep 1; netifd_tries=$((netifd_tries + 1))
        done
        cp /tmp/netifd-hotplug.done "$out/hotplug-settled-$1.txt"
        "$bench" snapshot "$monitors" > "$out/hotplug-settled-$1-before.json"
        sleep 2
        netifd_children_reaped
        printf 'proc-status-ppid\n' > "$out/hotplug-child-check-$1.txt"
        "$bench" snapshot "$monitors" > "$out/hotplug-settled-$1-after.json"
    }
    run_netifd_events() {
        # Invoked only for the separate two-bridge event fixture.
        event_root=$out/events_static2
        mkdir "$event_root"
        for channel in listen subscribe hotplug; do : > "$event_root/$channel.txt"; done
        ubus -S listen network.interface > "$event_root/listen.txt" 2> "$event_root/listen.stderr" & event_listen=$!
        ubus -S subscribe network.interface > "$event_root/subscribe.txt" 2> "$event_root/subscribe.stderr" & event_subscribe=$!
        monitors=$subject,$bus,$event_listen,$event_subscribe
        "$bench" snapshot "$monitors" > "$out/event-role-snapshot.json"
        printf '{"schema":1,"processes":[' > "$out/roles.json"
        role_index=0; role_sep=''
        for role_spec in "$subject:subject" "$bus:dependency" "$event_listen:caller_instrumentation" "$event_subscribe:caller_instrumentation"; do
            role_pid=${role_spec%:*}; role_name=${role_spec#*:}
            role_start=$(jsonfilter -i "$out/event-role-snapshot.json" -e "@.processes[$role_index].start_ticks")
            case "$role_start" in ''|*[!0-9]*) exit 1 ;; esac
            printf '%s{"pid":%s,"start_ticks":%s,"role":"%s"}' "$role_sep" "$role_pid" "$role_start" "$role_name" >> "$out/roles.json"
            role_sep=,; role_index=$((role_index + 1))
        done
        printf ']}\n' >> "$out/roles.json"
        cp /tmp/netifd-hotplug.done "$out/event-setup-hotplug.txt"
        "$bench" event-evidence mark "$event_root" "$event_root/cursor.json"
        cat > /tmp/netifd-cycle.sh <<'CYCLE'
#!/bin/sh
set -eu
bench=/tmp/bin/owrt-benchmark
root=/tmp/out/events_static2
iteration=${R84_ITERATION:-prelude}
case "$iteration" in prelude) cycle=$root/prelude ;; *) cycle=$(printf '%s/iteration-%06d' "$root" "$iteration") ;; esac
mkdir -p "$cycle"
fail() { printf '%s\n' "$1" > "$cycle/FAILED"; exit 1; }
trap 'rc=$?; if [ "$rc" -ne 0 ] && [ -d /tmp/netifd-event-action ]; then cp -a /tmp/netifd-event-action "$cycle/failed-action"; fi' EXIT
read -r cycle_start rest < /proc/uptime
cycle_start=${cycle_start%.*}
deadline() {
    read -r current rest < /proc/uptime
    [ "$(( ${current%.*} - cycle_start ))" -lt 30 ] || fail coarse-cycle-deadline
    kill -0 "$NETIFD_SUBJECT" "$NETIFD_LISTEN" "$NETIFD_SUBSCRIBE" || fail process-exited
}
child_scans=0; child_scan_errors=0
children_reaped() {
    child_scans=$((child_scans + 1))
    if children=$(awk -v parent="$NETIFD_SUBJECT" '$1 == "PPid:" && $2 == parent {print FILENAME}' /proc/[0-9]*/status 2>> "$cycle/child-scan-errors.txt"); then :; else
        child_scan_errors=$((child_scan_errors + 1)); return 1
    fi
    [ -z "$children" ]
}
for action in lan-down lan-up wired-down wired-up; do
    deadline
    interface=${action%-*}; method=${action#*-}; dir=/tmp/netifd-event-action
    rm -rf "$dir"; mkdir "$dir"
    : > "$dir/evidence-errors.txt"
    printf '%s\n' "$action" >> "$cycle/actions.txt"
    if ubus -S -t 2 call "network.interface.$interface" "$method" > "$dir/command.stdout" 2> "$dir/command.stderr"; then rc=0; else rc=$?; fi
    printf '%s\n' "$rc" > "$dir/command.rc"
    [ "$rc" = 0 ] || fail "$action-command"
    polls=0
    while :; do
        deadline
        if ubus -S -t 2 call "network.interface.$interface" status > "$dir/status.json" 2>> "$dir/status.stderr"; then :; else fail "$action-status"; fi
        cat "$dir/status.json" >> "$dir/status-polls.jsonl"
        polls=$((polls + 1)); printf '%s\n' "$polls" > "$dir/polls.txt"
        ip -o address show > "$dir/addresses.txt"
        sed 's/^[0-9]*: //' "$dir/addresses.txt" | LC_ALL=C sort > "$dir/kernel-addresses.txt"
        ip route show table all > "$dir/routes-unsorted.txt" || fail kernel-routes
        ip -6 route show table all > "$dir/routes6-unsorted.txt" || fail kernel-routes6
        LC_ALL=C sort "$dir/routes-unsorted.txt" > "$dir/routes.txt"
        LC_ALL=C sort "$dir/routes6-unsorted.txt" > "$dir/routes6.txt"
        if children_reaped; then
            if [ "$NETIFD_EVENT_MODE" = capture ]; then
                # Untimed reference discovery only. Measurement uses exact
                # frozen per-action transcripts, not this settling heuristic.
                "$bench" sleep-ms 250
            fi
            if "$bench" event-evidence "$NETIFD_EVENT_MODE" "$NETIFD_EVENT_CONTRACT" "$action" "$root" "$root/cursor.json" "$dir" "$cycle/records.jsonl" 2>> "$dir/evidence-errors.txt"; then break; fi
        fi
        "$bench" sleep-ms 5
    done
done
while ! children_reaped; do
    deadline
    "$bench" sleep-ms 5
done
ubus -S -t 2 call network.interface dump > "$cycle/final-interfaces.json" 2> "$cycle/final-interfaces.stderr" || fail final-dump
[ "$(jsonfilter -i "$cycle/final-interfaces.json" -e '@.interface[*].interface')" = "$(printf 'lan\nloopback\nwired')" ] || fail final-names
[ "$(jsonfilter -i "$cycle/final-interfaces.json" -e '@.interface[*].up')" = "$(printf 'true\ntrue\ntrue')" ] || fail final-up
[ "$(jsonfilter -i "$cycle/final-interfaces.json" -e '@.interface[*].pending')" = "$(printf 'false\nfalse\nfalse')" ] || fail final-pending
while ! children_reaped; do
    deadline
    "$bench" sleep-ms 5
done
cp "$root/cursor.json" "$cycle/cursor-final.json"
printf 'proc-status-ppid\n' > "$cycle/children-reaped.txt"
printf '{"scans":%s,"scan_errors":%s}\n' "$child_scans" "$child_scan_errors" > "$cycle/child-scans.json"
touch "$cycle/COMPLETE"
printf 'event-cycle-ok\n'
CYCLE
        export NETIFD_SUBJECT=$subject NETIFD_LISTEN=$event_listen NETIFD_SUBSCRIBE=$event_subscribe
        export NETIFD_EVENT_MODE=check NETIFD_EVENT_CONTRACT=/tmp/bin/event-contract.json
        if [ "${OWRT_NETIFD_EVENT_CAPTURE:-0}" = 1 ]; then
            NETIFD_EVENT_MODE=capture NETIFD_EVENT_CONTRACT=-
        else
            [ -s "$NETIFD_EVENT_CONTRACT" ]
            sha256sum "$NETIFD_EVENT_CONTRACT" > "$out/event-contract-sha256.txt"
            cp "$NETIFD_EVENT_CONTRACT" "$out/event-contract.json"
        fi
        # The full prelude is outside timing and proves both registrations by
        # receiving all expected records. A missing subscription fails here.
        "$bench" sleep-ms 50
        R84_ITERATION=prelude /bin/sh /tmp/netifd-cycle.sh > "$event_root/prelude.stdout"
        "$bench" sleep-ms 50
        "$bench" event-evidence mark "$event_root" "$event_root/prelude-cursor-after.json"
        cmp "$event_root/cursor.json" "$event_root/prelude-cursor-after.json"
        netifd_no_spawn events_static2 before
        if [ "${OWRT_NETIFD_EVENT_CAPTURE:-0}" = 1 ]; then netifd_no_spawn events_static2 after; return; fi
        printf 'event-cycle-ok\n' > /tmp/event.expected
        OWRT_BENCH_EXEC_JOURNAL=$out/events_static2-journal.jsonl \
        OWRT_BENCH_EXEC_ARTIFACTS=$event_root \
            "$bench" exec "$n" "$rpc_warmup" /tmp/event.expected "$monitors" -- /bin/sh /tmp/netifd-cycle.sh > "$out/events_static2.json"
        # Detect late extra records after the final completion boundary too.
        "$bench" sleep-ms 50
        "$bench" event-evidence mark "$event_root" "$event_root/cursor-after.json"
        cmp "$event_root/cursor.json" "$event_root/cursor-after.json"
        netifd_children_reaped
        [ ! -s "$event_root/listen.stderr" ] && [ ! -s "$event_root/subscribe.stderr" ]
        netifd_no_spawn events_static2 after
    }
    http_selected() {
        [ -z "${OWRT_HTTPD_WORKLOADS:-}" ] && return 0
        case " $OWRT_HTTPD_WORKLOADS " in *" $1 "*) return 0 ;; *) return 1 ;; esac
    }
    http_one() { # label method path body expected count warmup format
        http_selected "$1" || return 0
        "$bench" http 127.0.0.1:18080 "$2" "$3" "$4" "$5" "$6" "$7" "$monitors" "$8" > "$out/$1.json"
    }
    http_four() { # label method path body expected total format
        http_selected "$1" || return 0
        # Four clients share ONE outer CPU interval. Their overlapping
        # per-client daemon counters must never be summed.
        label=$1; method=$2; url=$3; body=$4; expected=$5; total=$6; format=$7
        count=$((total / 4)); [ "$count" -gt 0 ] || count=1
        mkdir "$out/$label"
        printf '{"clients":4,"iterations_per_client":%s,"warmup_per_client":20}\n' "$count" > "$out/$label/group.json"
        "$bench" snapshot "$monitors" > "$out/$label/before.json"
        clients=''; j=1
        while [ "$j" -le 4 ]; do
            "$bench" http 127.0.0.1:18080 "$method" "$url" "$body" "$expected" "$count" 20 "$monitors" "$format" > "$out/$label/client-$j.json" &
            clients="$clients $!"; j=$((j + 1))
        done
        failed=0
        for client in $clients; do wait "$client" || failed=1; done
        "$bench" snapshot "$monitors" > "$out/$label/after.json"
        [ "$failed" = 0 ]
    }
    count_exec=$((n / 20)); [ "$count_exec" -gt 0 ] || count_exec=1
    count_fw=$((n / 100)); [ "$count_fw" -gt 0 ] || count_fw=1
    count_fw=${OWRT_FW4_COUNT:-$count_fw}
    fw4_warmup=${OWRT_FW4_WARMUP:-3}
    bus_bin=$(choose ubusd /sbin/ubusd ubusd-rs)
    if [ "$component" = ubusd ] && [ "${OWRT_UBUSD_NORMALIZED:-0}" = 1 ]; then
        # Opt-in requires the separately identified exec-cpu-as helper.
        # Keep C and Rust daemon argv0 identical for the final matrix. The
        # helper execs in place, so $! remains the real daemon PID.
        "$bench" exec-cpu-as 1 "$bus_bin" /sbin/ubusd -s "$socket" > "$out/bus.log" 2>&1 & bus=$!
    else
        "$bus_bin" -s "$socket" > "$out/bus.log" 2>&1 & bus=$!
    fi
    tries=0
    until ubus -t 1 list >/dev/null 2>&1; do
        kill -0 "$bus"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
    done
    subject=$bus; monitors=$bus
    case "$component" in
        ubusd)
            bin=$bus_bin
            if [ "${OWRT_UBUSD_EXTENDED:-0}" = 1 ]; then
                # On the empty bus: ADD/REMOVE cycles (1 and 16 methods,
                # 8-byte names), then the same cycle with 1 or 8 matching
                # ubus.object.* listeners on one connection, or 1 unrelated.
                "$bench" register-cycle "$socket" 1 8 "$n" 20 "$monitors" > "$out/register_1.json"
                "$bench" register-cycle "$socket" 16 8 "$n" 20 "$monitors" > "$out/register_16.json"
                "$bench" register-watch "$socket" 1 1 "$n" 20 "$monitors" > "$out/event_1.json"
                "$bench" register-watch "$socket" 8 1 "$n" 20 "$monitors" > "$out/event_8.json"
                "$bench" register-watch "$socket" 1 0 "$n" 20 "$monitors" > "$out/event_nomatch.json"
            fi
            "$bench" serve "$socket" 64 > "$out/provider.log" 2>&1 & provider=$!
            wait_object bench.target "$provider"
            monitors=$bus,$provider
            if [ "${OWRT_UBUSD_MATRIX:-0}" = 1 ]; then
                wait_object bench.filler0063 "$provider"
                printf 'provider_objects=64,128\nmethod=ping\nargument=n:int32\nreply=ok:1\n' > /tmp/ubusd-fixtures
                sha256sum /tmp/ubusd-fixtures > "$out/ubusd-fixtures.sha256"
                check_bus_objects 64 before
            fi
            start_trace
            "$bench" lookup "$socket" bench.target "$n" 20 "$monitors" > "$out/lookup.json"
            "$bench" lookup "$socket" '*' "$n" 20 "$monitors" > "$out/lookup_all_64.json"
            run_rpc invoke bench.target ping '{"n":1}' '{"ok":1}'
            if [ "${OWRT_UBUSD_MATRIX:-0}" = 1 ]; then
                lookup_four lookup_c4 bench.target "$n"
                lookup_four lookup_all_64_c4 '*' "$n"
                rpc_four invoke_c4 bench.target ping '{"n":1}' '{"ok":1}' "$n"
                "$bench" lookup "$socket" 'bench.*' "$n" 20 "$monitors" > "$out/lookup_prefix_64.json"
                lookup_four lookup_prefix_64_c4 'bench.*' "$n"
                check_bus_objects 64 after
                kill "$provider"; wait "$provider" 2>/dev/null || true
                tries=0
                while ubus list bench.target 2>/dev/null | grep -q '^bench.target$'; do
                    [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
                done
                "$bench" serve "$socket" 128 > "$out/provider-128.log" 2>&1 & provider=$!
                wait_object bench.target "$provider"
                # bench.target registers first; wait for the final filler too.
                wait_object bench.filler0127 "$provider"
                monitors=$bus,$provider
                check_bus_objects 128 before
                "$bench" lookup "$socket" '*' "$n" 20 "$monitors" > "$out/lookup_all_128.json"
                lookup_four lookup_all_128_c4 '*' "$n"
                check_bus_objects 128 after
            fi
            ;;
        rpcd)
            bin=$(choose rpcd /sbin/rpcd rpcd-rs)
            "$bin" -s "$socket" -t 60 > "$out/daemon.log" 2>&1 & subject=$!
            wait_object uci "$subject"; wait_object file "$subject"
            monitors=$subject,$bus
            "$bench" snapshot "$monitors" > "$out/startup.json"
            run_rpc uci_configs uci configs '{}' '{"configs":[]}'
            run_rpc uci_get_network uci get '{"config":"network"}' '{"values":{"lan":{"proto":"static"}}}'
            run_rpc file_stat file stat '{"path":"/etc/config/network"}' '{"type":"file"}'
            run_rpc session_access session access '{"ubus_rpc_session":"00000000000000000000000000000000","scope":"ubus","object":"uci","function":"get"}' '{"access":false}'
            "$bench" snapshot "$monitors" > "$out/active.json"
            if [ "${OWRT_RPCD_CLIENT_DIAGNOSTIC:-0}" = 1 ]; then
                sha256sum /tmp/bin/rpc-client-probe > "$out/client-probe-sha256.txt"
                sha256sum /etc/config/network /etc/config/r84fixture > "$out/rpc-fixtures.sha256"
                large_uci_expect
                large=$((n / 10)); [ "$large" -gt 0 ] || large=1
                frozen_bench=$bench
                bench=/tmp/bin/rpc-client-probe
                modes='tree wire'
                [ "${OWRT_RPCD_CLIENT_ORDER:-tree-first}" = tree-first ] || modes='wire tree'
                printf '%s\n' "$modes" > "$out/client-probe-order.txt"
                for validation in $modes; do
                    rpc_mode=rpc
                    [ "$validation" = tree ] || rpc_mode=rpc-wire
                    rpc_pair "diagnostic_${validation}_64" uci get '{"config":"r84fixture"}' "$(cat /tmp/expect-large.json)" "$large"
                done
                rpc_mode=rpc
                bench=$frozen_bench
            fi
            if [ "${OWRT_RPCD_MATRIX:-0}" = 1 ]; then
                sha256sum /etc/config/network /etc/config/r84fixture > "$out/rpc-fixtures.sha256"
                rpc_four uci_configs_c4 uci configs '{}' '{"configs":[]}'
                rpc_four uci_get_network_c4 uci get '{"config":"network"}' '{"values":{"lan":{"proto":"static"}}}'
                rpc_four file_stat_c4 file stat '{"path":"/etc/config/network"}' '{"type":"file"}'
                rpc_four session_access_c4 session access '{"ubus_rpc_session":"00000000000000000000000000000000","scope":"ubus","object":"uci","function":"get"}' '{"access":false}'
                # Validate every section of the larger reply; N/10 keeps its
                # client-side JSON work from dominating the whole matrix.
                large_uci_expect
                large=$((n / 10)); [ "$large" -gt 0 ] || large=1
                rpc_pair uci_get_64 uci get '{"config":"r84fixture"}' "$(cat /tmp/expect-large.json)" "$large"
                sid=$(ubus call session create '{"timeout":0}' | jsonfilter -e '@.ubus_rpc_session')
                [ "${#sid}" = 32 ]
                printf '%s\n' "$sid" > /tmp/rpcd-session-ids
                ubus call session grant "{\"ubus_rpc_session\":\"$sid\",\"scope\":\"uci\",\"objects\":[[\"net*\",\"r*\"]]}" >/dev/null
                rpc_pair uci_get_authorized uci get "{\"config\":\"network\",\"ubus_rpc_session\":\"$sid\"}" '{"values":{"lan":{"proto":"static"}}}'
                access="{\"ubus_rpc_session\":\"$sid\",\"scope\":\"uci\",\"object\":\"network\",\"function\":\"read\"}"
                rpc_pair session_access_granted session access "$access" '{"access":true}'
                rpc_pair file_list file list '{"path":"/etc/config"}' '{"entries":[{}]}'
                if rpcd_extra_selected uci_state_network; then
                    printf "network.lan.bench_state='state-visible'\n" > /var/state/network
                    rpc_pair uci_state_network uci state '{"config":"network"}' '{"values":{"lan":{"proto":"static","bench_state":"state-visible"}}}'
                fi
                if rpcd_extra_selected uci_get_delta; then
                    ubus call session grant "{\"ubus_rpc_session\":\"$sid\",\"scope\":\"uci\",\"objects\":[[\"network\",\"write\"]]}" >/dev/null
                    ubus call uci set "{\"ubus_rpc_session\":\"$sid\",\"config\":\"network\",\"section\":\"lan\",\"values\":{\"bench_marker\":\"delta-visible\"}}" >/dev/null
                    rpc_pair uci_get_delta uci get "{\"ubus_rpc_session\":\"$sid\",\"config\":\"network\"}" '{"values":{"lan":{"bench_marker":"delta-visible"}}}'
                fi
                if rpcd_extra_selected session_access_acl256; then
                    printf '{"ubus_rpc_session":"%s","scope":"bench","objects":[' "$sid" > /tmp/acl256.json
                    i=0
                    while [ "$i" -lt 256 ]; do
                        [ "$i" -eq 0 ] || printf ',' >> /tmp/acl256.json
                        printf '["object%03d*","r[ea]ad"]' "$i" >> /tmp/acl256.json
                        i=$((i + 1))
                    done
                    printf ']}' >> /tmp/acl256.json
                    ubus call session grant "$(cat /tmp/acl256.json)" >/dev/null
                    rpc_pair session_access_acl256 session access "{\"ubus_rpc_session\":\"$sid\",\"scope\":\"bench\",\"object\":\"object255-suffix\",\"function\":\"read\"}" '{"access":true}'
                fi
                if rpcd_extra_selected luci_version; then
                    /usr/bin/ucode -e 'import { revision, branch } from "luci.version"; print({revision, branch});' > /tmp/luci-version.json
                    rpc_pair luci_version luci getVersion '{}' "$(cat /tmp/luci-version.json)"
                fi
                if rpcd_extra_selected luci_features; then
                    features=$((n / 100)); [ "$features" -gt 0 ] || features=1
                    # Stable exact-image capabilities; the complete dynamic
                    # feature object is checked separately by the feature gate.
                    rpc_pair luci_features luci getFeatures '{}' '{"firewall":true,"firewall4":true,"apk":true,"opkg":false,"wifi":true,"dropbear":true,"netifd_vrf":true}' "$features"
                fi
                if rpcd_extra_selected luci_devices; then
                    devices=$((n / 10)); [ "$devices" -gt 0 ] || devices=1
                    rpc_pair luci_devices luci-rpc getNetworkDevices '{}' '{"lo":{"name":"lo"}}' "$devices"
                fi
                i=0
                while [ "$i" -lt 62 ]; do
                    extra_sid=$(ubus call session create '{"timeout":3600}' | jsonfilter -e '@.ubus_rpc_session')
                    [ "${#extra_sid}" = 32 ]
                    printf '%s\n' "$extra_sid" >> /tmp/rpcd-session-ids
                    i=$((i + 1))
                done
                rpc_pair session_access_64 session access "$access" '{"access":true}'
                "$bench" snapshot "$monitors" > "$out/expanded.json"
                while read -r extra_sid; do
                    ubus call session destroy "{\"ubus_rpc_session\":\"$extra_sid\"}" >/dev/null
                done < /tmp/rpcd-session-ids
                sleep 1
                "$bench" snapshot "$monitors" > "$out/after-close.json"
            fi
            ;;
        procd)
            bin=$(choose procd /sbin/procd procd-rs)
            "$bin" -S -I /tmp/empty-init -R /tmp/empty-rc > "$out/daemon.log" 2>&1 & subject=$!
            wait_object service "$subject"
            sha256sum /proc/"$bus"/exe > "$out/dependencies-sha256.txt"
            i=0
            while [ "$i" -lt 32 ]; do
                ubus call service set "{\"name\":\"r84fixture$i\",\"data\":{\"index\":$i}}" >/dev/null
                i=$((i + 1))
            done
            monitors=$subject,$bus
            service32='{"r84fixture0":{}}'
            if [ "${OWRT_PROCD_MATRIX:-0}" = 1 ]; then
                service_list_expect 32 > /tmp/expect-service-32.json
                service32=$(cat /tmp/expect-service-32.json)
            fi
            start_trace
            run_rpc service_list_32 service list '{}' "$service32"
            run_rpc system_info system info '{}' '{"memory":{}}'
            if [ "${OWRT_PROCD_MATRIX:-0}" = 1 ]; then
                rpc_four service_list_32_c4 service list '{}' "$service32"
                rpc_four system_info_c4 system info '{}' '{"memory":{}}'
                i=32
                while [ "$i" -lt 128 ]; do
                    ubus call service set "{\"name\":\"r84fixture$i\",\"data\":{\"index\":$i}}" >/dev/null
                    i=$((i + 1))
                done
                service_list_expect 128 > /tmp/expect-service-128.json
                sha256sum /tmp/expect-service-32.json /tmp/expect-service-128.json > "$out/procd-fixtures.sha256"
                rpc_pair service_list_128 service list '{}' "$(cat /tmp/expect-service-128.json)"
                rpc_pair service_list_named_128 service list '{"name":"r84fixture127"}' '{"r84fixture127":{"data":{"index":127}}}'
                if [ -n "${OWRT_PROCD_WORKLOADS:-}" ] && procd_lane_selected service_list_instance_fields; then
                    procd_instance_fixture
                fi
            fi
            ;;
        netifd|fw4)
            bin=$(choose netifd /sbin/netifd netifd-rs)
            if [ "$component" = netifd ] && [ "${OWRT_NETIFD_MATRIX:-0}" = 1 ]; then
                : > /tmp/netifd-hotplug.done
                cat > /tmp/netifd-hotplug <<'EOF'
#!/bin/sh
/sbin/hotplug-call "$@"
status=$?
printf '%s %s %s\n' "$INTERFACE" "$ACTION" "$status" >> /tmp/netifd-hotplug.done
if [ -d /tmp/out/events_static2 ]; then
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$1" "${INTERFACE:-}" "${ACTION:-}" "${DEVICE:-}" "${IFUPDATE_ADDRESSES:-}" "${IFUPDATE_ROUTES:-}" "${IFUPDATE_PREFIXES:-}" "${IFUPDATE_DATA:-}" "$status" >> /tmp/out/events_static2/hotplug.txt
fi
exit "$status"
EOF
                chmod +x /tmp/netifd-hotplug
                "$bin" -h /tmp/netifd-hotplug > "$out/network.log" 2>&1 & subject=$!
            else
                "$bin" > "$out/network.log" 2>&1 & subject=$!
            fi
            wait_object network.interface.lan "$subject"
            ready=0; tries=0
            until [ "$ready" = true ]; do
                kill -0 "$subject"; [ "$tries" -lt 20 ]
                ready=$(ubus call network.interface.lan status | jsonfilter -e '@.up')
                sleep 1; tries=$((tries + 1))
            done
            monitors=$subject,$bus
            if [ "$component" = netifd ]; then
                if [ "$netifd_events" = 1 ]; then
                    wait_object network.interface.wired "$subject"
                    printf 'lan\nloopback\nwired\n' > /tmp/netifd-names.expected
                    wait_netifd_hotplug 3
                    sha256sum /etc/config/network /etc/config/wireless > "$out/netifd-fixtures.sha256"
                    run_netifd_events
                else
                interface_expected='{"interface":[]}'
                if [ "${OWRT_NETIFD_MATRIX:-0}" = 1 ]; then
                    netifd_expect 2 > /tmp/expect-interfaces-2.json
                    interface_expected=$(cat /tmp/expect-interfaces-2.json)
                    check_netifd_interfaces 2 before
                    wait_netifd_hotplug 2
                    sha256sum /etc/config/network /etc/config/wireless > "$out/netifd-fixtures.sha256"
                fi
                wireless_expected='{}'
                if [ -d /tmp/bin/netifd-fixture ]; then
                    tries=0
                    until ubus -S call network.wireless status > "$out/wireless-before.json" &&
                          cmp -s "$out/wireless-before.json" /tmp/bin/netifd-fixture/expected-wireless.json; do
                        kill -0 "$subject"; [ "$tries" -lt 30 ]; sleep 1; tries=$((tries + 1))
                    done
                    netifd_children_reaped
                    sha256sum /tmp/bin/netifd-fixture/* >> "$out/netifd-fixtures.sha256"
                    wireless_expected=$(cat /tmp/bin/netifd-fixture/expected-wireless.json)
                fi
                run_rpc interface_dump network.interface dump '{}' "$interface_expected"
                run_rpc lan_status network.interface.lan status '{}' '{"up":true,"proto":"static"}'
                run_rpc device_status network.device status '{"name":"br-bench"}' '{"present":true,"type":"bridge"}'
                run_rpc wireless_status network.wireless status '{}' "$wireless_expected"
                if [ "${OWRT_NETIFD_MATRIX:-0}" = 1 ]; then
                    rpc_four interface_dump_c4 network.interface dump '{}' "$interface_expected"
                    rpc_four lan_status_c4 network.interface.lan status '{}' '{"up":true,"proto":"static"}'
                    rpc_four device_status_c4 network.device status '{"name":"br-bench"}' '{"present":true,"type":"bridge"}'
                    rpc_four wireless_status_c4 network.wireless status '{}' "$wireless_expected"
                    rpc_pair device_status_all network.device status '{}' '{"br-bench":{"present":true,"type":"bridge"},"lo":{"present":true}}'
                    check_netifd_interfaces 2 after
                    # Multiple static interfaces on the same bridge exercise
                    # live status projection without requiring extra hardware.
                    netifd_index=0
                    while [ "$netifd_index" -lt "$((netifd_scale - 2))" ]; do
                        printf "config interface 'bench%0*d'\n option device 'br-bench'\n option proto 'static'\n option ipaddr '198.18.%s.1/24'\n" "$netifd_digits" "$netifd_index" "$netifd_index" >> /etc/config/network
                        netifd_index=$((netifd_index + 1))
                    done
                    ubus call network reload >/dev/null
                    netifd_last=$(printf "bench%0*d" "$netifd_digits" "$((netifd_scale - 3))")
                    wait_object "network.interface.$netifd_last" "$subject"
                    tries=0
                    until [ "$(ubus call "network.interface.$netifd_last" status | jsonfilter -e '@.up')" = true ]; do
                        kill -0 "$subject"; [ "$tries" -lt 20 ]; sleep 1; tries=$((tries + 1))
                    done
                    netifd_expect "$netifd_scale" > /tmp/expect-interfaces-scale.json
                    sha256sum /etc/config/network /tmp/expect-interfaces-2.json /tmp/expect-interfaces-scale.json >> "$out/netifd-fixtures.sha256"
                    check_netifd_interfaces "$netifd_scale" before
                    wait_netifd_hotplug "$netifd_scale"
                    rpc_pair "interface_dump_$netifd_scale" network.interface dump '{}' "$(cat /tmp/expect-interfaces-scale.json)"
                    rpc_pair "interface_named_$netifd_scale" "network.interface.$netifd_last" status '{}' "{\"up\":true,\"proto\":\"static\",\"ipv4-address\":[{\"address\":\"198.18.$((netifd_scale - 3)).1\",\"mask\":24}]}"
                    check_netifd_interfaces "$netifd_scale" after
                fi
                if [ -d /tmp/bin/netifd-fixture ]; then
                    ubus -S call network.wireless status > "$out/wireless-after.json"
                    cmp "$out/wireless-after.json" /tmp/bin/netifd-fixture/expected-wireless.json
                    netifd_children_reaped
                fi
                if [ -n "${OWRT_NETIFD_WORKLOADS:-}" ] && netifd_lane_selected reload_unchanged; then
                    # Existing H4 unchanged-reload contract: 32/64/128 settled
                    # static interfaces, synchronous RPC, unchanged scripts/state.
                    cp /tmp/netifd-hotplug.done "$out/hotplug-before-reload.txt"
                    if [ -f "$out/handler-calls.log" ]; then cp "$out/handler-calls.log" "$out/handler-before-reload.log"; fi
                    sha256sum /etc/config/network /etc/config/wireless > "$out/reload-config-before.sha256"
                    "$bench" snapshot "$monitors" > "$out/reload-before.json"
                    run_rpc reload_unchanged network reload '{}' '{}' "$n"
                    netifd_children_reaped
                    cmp /tmp/netifd-hotplug.done "$out/hotplug-before-reload.txt"
                    if [ -f "$out/handler-before-reload.log" ]; then cmp "$out/handler-before-reload.log" "$out/handler-calls.log"; fi
                    sha256sum /etc/config/network /etc/config/wireless > "$out/reload-config-after.sha256"
                    cmp "$out/reload-config-before.sha256" "$out/reload-config-after.sha256"
                    ubus -S -t 2 call network.wireless status > "$out/wireless-after-reload.json"
                    if [ -d /tmp/bin/netifd-fixture ]; then cmp "$out/wireless-after-reload.json" /tmp/bin/netifd-fixture/expected-wireless.json; else cmp "$out/wireless-after-reload.json" /tmp/empty.json; fi
                    check_netifd_interfaces "$netifd_scale" after-reload
                    cp /tmp/netifd-hotplug.done "$out/hotplug-after-reload.txt"
                    "$bench" snapshot "$monitors" > "$out/reload-after.json"
                    printf 'proc-status-ppid\n' > "$out/reload-children-reaped.txt"
                fi
                fi # query/reload fixture versus separate event fixture
            else
                bin=$(choose fw4 /sbin/fw4 fw4-rs)
                : > "$out/reference-stderr.log"
                for lane in ${OWRT_FW4_WORKLOADS:-print check}; do
                    # check executes real nft validation in the private network namespace.
                    /sbin/fw4 "$lane" > "/tmp/expected.$lane" 2>> "$out/reference-stderr.log"
                    "$bench" exec "$count_fw" "$fw4_warmup" "/tmp/expected.$lane" "$monitors" -- "$bin" "$lane" > "$out/$lane.json"
                done
            fi
            ;;
        logd)
            bin=$(choose logd /sbin/logd logd-rs)
            "$bin" -S 64 > "$out/daemon.log" 2>&1 & subject=$!
            wait_object log "$subject"
            monitors=$subject,$bus
            "$bench" idle 3 "$monitors" > "$out/kernel-log-idle.jsonl"
            "$bench" syslog /dev/log "$socket" "$((n * 10))" 100 "$monitors" > "$out/syslog_128.json"
            run_rpc log_read_100 log read '{"lines":100,"stream":false}' '{"log":[{}]}'
            ;;
        uci)
            monitors=-
            bin=$(choose uci /sbin/uci uci-rs)
            # Every path (including defaults/absolute paths and symlinks) is
            # beneath the read-only image or the namespace's private tmpfs.
            uci_exec() {
                lane=$1; expected=$2; shift 2
                "$@" > /tmp/uci-preflight.stdout 2> /tmp/uci-preflight.stderr
                cmp -s "$expected" /tmp/uci-preflight.stdout
                [ ! -s /tmp/uci-preflight.stderr ]
                "$bench" exec-strict "$count_exec" 5 "$expected" - -- "$@" > "$out/$lane.json"
                if [ -x /tmp/bin/exec-resource ]; then
                    # Separate, untimed full-lifetime samples, never an
                    # after-exit /proc snapshot or a zero-memory inference.
                    sample=0
                    while [ "$sample" -lt 3 ]; do
                        R84_ITERATION=$((count_exec + 5 + sample)) /tmp/bin/exec-resource \
                            "$out/$lane-resource-$sample.json" "$@" \
                            > /tmp/uci-resource.stdout 2> /tmp/uci-resource.stderr
                        cmp -s "$expected" /tmp/uci-resource.stdout
                        [ ! -s /tmp/uci-resource.stderr ]
                        sample=$((sample + 1))
                    done
                fi
            }
            sha256sum /sbin/uci /lib/libuci.so* /lib/ld-musl-aarch64.so.1 > "$out/uci-dependencies.sha256"
            /sbin/uci -S -n export network > /tmp/expected.network
            /sbin/uci -S -n export r84fixture > /tmp/expected.fixture
            uci_exec export_network /tmp/expected.network "$bin" -S -n export network
            uci_exec export_64 /tmp/expected.fixture "$bin" -S -n export r84fixture
            mkdir -p /tmp/uci-config /tmp/uci-save
            cp /etc/config/network /tmp/uci-config/
            uci_initial_mode=$(ls -ldn /tmp/uci-config/network | awk '{print $1, $3, $4}')
            cat > /tmp/write-uci.sh <<'EOF'
#!/bin/sh
set -eu
"$1" -c /tmp/uci-config -t /tmp/uci-save set "network.lan.r84=$R84_ITERATION"
"$1" -c /tmp/uci-config -t /tmp/uci-save commit network
value=$("$1" -c /tmp/uci-config -t /tmp/uci-save get network.lan.r84)
[ "$value" = "$R84_ITERATION" ]
EOF
            R84_ITERATION=preflight uci_exec set_commit_get /tmp/empty.bytes /bin/sh /tmp/write-uci.sh "$bin"
            # A successful get could otherwise hide a no-op commit by reading
            # its still-pending delta. Validate persisted bytes outside timing.
            final_iteration=$((count_exec + 4))
            [ ! -x /tmp/bin/exec-resource ] || final_iteration=$((count_exec + 7))
            mkdir /tmp/uci-verify-config /tmp/uci-verify-save /tmp/uci-verify-empty
            cp /etc/config/network /tmp/uci-verify-config/
            /sbin/uci -C '' -c /tmp/uci-verify-config -t /tmp/uci-verify-save set "network.lan.r84=$final_iteration"
            /sbin/uci -C '' -c /tmp/uci-verify-config -t /tmp/uci-verify-save commit network
            cmp -s /tmp/uci-verify-config/network /tmp/uci-config/network
            [ -f /tmp/uci-save/network ] && [ ! -s /tmp/uci-save/network ]
            [ "$(ls -ldn /tmp/uci-config/network | awk '{print $1, $3, $4}')" = "$uci_initial_mode" ]
            [ "$(/sbin/uci -C '' -c /tmp/uci-config -t /tmp/uci-verify-empty get network.lan.r84)" = "$final_iteration" ]
            printf '%s\n' "$final_iteration" > "$out/uci-persisted-value.txt"
            if [ "${OWRT_UCI_MATRIX:-0}" = 1 ]; then
                /sbin/uci get network.lan.proto > /tmp/expected.get
                uci_exec get_network /tmp/expected.get "$bin" get network.lan.proto
                mkdir -p /tmp/uci-multi /tmp/uci-delta
                for package in alpha beta gamma delta; do cp /etc/config/r84fixture /tmp/uci-multi/$package; done
                /sbin/uci -C '' -c /tmp/uci-multi export > /tmp/expected.multi
                uci_exec export_multi /tmp/expected.multi "$bin" -C '' -c /tmp/uci-multi export
                # 64 named sections, one 125-byte double-quoted value and
                # eight 128-byte list values per section, including quotes.
                awk 'BEGIN { v=""; for(j=0;j<120;j++)v=v "x"; for(i=0;i<64;i++) { printf "config bench entry%d\n option value \"%s\047tail\"\n",i,v; for(k=0;k<8;k++) printf " list members \"%s item-%02d\"\n",v,k } }' > /etc/config/ucilong
                /sbin/uci show ucilong > /tmp/expected.long
                uci_exec show_long /tmp/expected.long "$bin" show ucilong
                # Replay 32 current deltas on the unchanged 64-section base.
                i=0
                while [ "$i" -lt 32 ]; do
                    printf "r84fixture.entry%s.value='delta-%s'\n" "$i" "$i"
                    i=$((i + 1))
                done > /tmp/uci-delta/r84fixture
                /sbin/uci -C '' -t /tmp/uci-delta export r84fixture > /tmp/expected.delta
                uci_exec delta_64 /tmp/expected.delta "$bin" -C '' -t /tmp/uci-delta export r84fixture
                i=0
                while [ "$i" -lt 8 ]; do
                    printf 'get network.lan.proto\nget r84fixture.entry63.value\n'
                    i=$((i + 1))
                done > /tmp/uci-read.batch
                /sbin/uci -f /tmp/uci-read.batch batch > /tmp/expected.batch
                uci_exec batch_read16 /tmp/expected.batch "$bin" -f /tmp/uci-read.batch batch
                sha256sum /etc/config/network /etc/config/r84fixture /etc/config/ucilong \
                    /tmp/uci-multi/* /tmp/uci-delta/* /tmp/uci-read.batch /tmp/write-uci.sh \
                    /tmp/expected.* > "$out/uci-fixtures.sha256"
                wc -c /etc/config/network /etc/config/r84fixture /etc/config/ucilong \
                    /tmp/uci-multi/* /tmp/uci-delta/* > "$out/uci-fixtures-sizes.txt"
            fi
            ;;
        reload-config)
            bin=$(choose reload-config /sbin/reload_config reload_config_rs)
            fixture=/tmp/reload-fixture
            mkdir -p "$fixture/base" /etc/config
            # Fixed public corpus; no production configuration/delta/override.
            cp /etc/config/network /etc/config/firewall /etc/config/wireless /etc/config/r84fixture "$fixture/base/"
            reload_package=4
            while [ "$reload_package" -lt "${OWRT_RELOAD_CONFIG_PACKAGES:-4}" ]; do
                printf "config bench 'main'\n option value 'fixed'\n" > "$fixture/base/$(printf 'reloadp%03d' "$reload_package")"
                reload_package=$((reload_package + 1))
            done
            cp -a "$fixture/base" "$fixture/single"
            cp -a "$fixture/base" "$fixture/multi"
            cp -a "$fixture/base" "$fixture/comment"
            sed 's/192.0.2.1/192.0.2.2/' "$fixture/base/network" > "$fixture/single/network"
            cp "$fixture/single/network" "$fixture/multi/network"
            sed "s/REJECT/DROP/" "$fixture/base/firewall" > "$fixture/multi/firewall"
            sed "s/fixed-63/changed-63/" "$fixture/base/r84fixture" > "$fixture/multi/r84fixture"
            printf '\n# normalizes to the same UCI show bytes\n   \n' >> "$fixture/comment/network"
            # Freeze independently generated complete old/new baselines. Each
            # reference starts absent, so it cannot send service events.
            for variant in base single multi comment; do
                rm -f /etc/config/* /var/run/config.md5
                cp "$fixture/$variant/"* /etc/config/
                /sbin/reload_config > "$out/reference-$variant.stdout" 2> "$out/reference-$variant.stderr"
                [ ! -s "$out/reference-$variant.stdout" ] && [ ! -s "$out/reference-$variant.stderr" ]
                cp /var/run/config.md5 "$fixture/$variant.md5"
            done
            cmp "$fixture/base.md5" "$fixture/comment.md5"
            ! cmp -s "$fixture/base.md5" "$fixture/single.md5"
            ! cmp -s "$fixture/base.md5" "$fixture/multi.md5"
            sha256sum "$fixture"/*/* "$fixture"/*.md5 > "$out/reload-fixtures.sha256"
            cp "$fixture"/*.md5 "$out/"
            sha256sum /sbin/reload_config /bin/busybox /sbin/uci /bin/ubus /sbin/ubusd /sbin/logd /lib/libuci.so* /lib/libubus.so* /lib/libubox.so* /lib/libblobmsg_json.so* /lib/ld-musl-aarch64.so.1 > "$out/reload-dependencies.sha256"
            "$bench" reload-service "$socket" "$fixture/events.bin" > "$out/reload-service.stdout" 2> "$out/reload-service.stderr" & receiver=$!
            wait_object service "$receiver"
            # Preserve default runtime syslog observability in private /dev;
            # no production /dev/log or service trigger exists in this root.
            /sbin/logd -S 64 > "$out/reload-logd.log" 2>&1 & reload_logd=$!
            wait_object log "$reload_logd"
            [ -S /dev/log ]
            monitors=$bus,$receiver,$reload_logd
            printf '{"ubusd":%s,"receiver":%s,"logd":%s}\n' "$bus" "$receiver" "$reload_logd" > "$out/reload-roles.json"
            sha256sum /proc/"$bus"/exe /proc/"$receiver"/exe /proc/"$reload_logd"/exe > "$out/reload-running-dependencies.sha256"
            resource=-
            if [ -x /tmp/bin/exec-resource ]; then
                resource=/tmp/bin/exec-resource
                sha256sum /tmp/bin/exec-resource > "$out/reload-resource-probe.sha256"
            fi
            if [ -x /tmp/bin/exec-task-counts ]; then
                export OWRT_RELOAD_TASK_PROBE=/tmp/bin/exec-task-counts
                sha256sum /tmp/bin/exec-task-counts > "$out/reload-task-probe.sha256"
            fi
            reload_lanes=unchanged_config
            if [ "${OWRT_RELOAD_CONFIG_MATRIX:-0}" = 1 ]; then
                reload_lanes='first_baseline unchanged_config single_change multi_change comment_only'
            fi
            reload_lanes=${OWRT_RELOAD_CONFIG_WORKLOADS:-$reload_lanes}
            for lane in $reload_lanes; do
                "$bench" reload-exec "$lane" "$count_exec" "${OWRT_RELOAD_CONFIG_WARMUP:-5}" "$fixture" "$out/$lane" "$monitors" "$resource" -- "$bin" > "$out/$lane.json"
                kill -0 "$bus" "$receiver" "$reload_logd"
            done
            ubus -S call log read '{"lines":100,"stream":false}' > "$out/reload-syslog.json"
            [ ! -s "$out/reload-service.stdout" ] && [ ! -s "$out/reload-service.stderr" ]
            ;;
        httpd)
            /sbin/rpcd -s "$socket" -t 60 > "$out/rpcd.log" 2>&1 & rpc=$!
            wait_object session "$rpc"; wait_object uci "$rpc"
            sid=$(ubus call session create '{"timeout":3600}' | jsonfilter -e '@.ubus_rpc_session')
            [ "${#sid}" = 32 ]
            ubus call session grant "{\"ubus_rpc_session\":\"$sid\",\"scope\":\"ubus\",\"objects\":[[\"uci\",\"configs\"]]}" >/dev/null
            printf '{"jsonrpc":"2.0","id":1,"method":"call","params":["%s","uci","configs",{}]}\n' "$sid" > /tmp/http-post.json
            printf '{"jsonrpc":"2.0","id":1,"result":[0,{"configs":[]}]}\n' > /tmp/http-expect.json
            if [ "${OWRT_HTTPD_RPC_PROFILE:-0}" = 1 ]; then
                # Diagnostic stage timings, not HTTP throughput. The profiler
                # includes the actual bridge source and validates its result.
                sha256sum /tmp/bin/profile > "$out/profile-sha256.txt"
                /tmp/bin/profile "$n" rpc /tmp/http-post.json > "$out/profile.csv"
                touch "$out/COMPLETE"
                exit 0
            fi
            mkdir -p /tmp/www/cgi-bin
            dd if=/dev/zero of=/tmp/www/static.dat bs=16384 count=1 2>/dev/null
            printf 'r84 CGI response\n' > /tmp/expected.cgi
            cat > /tmp/www/cgi-bin/bench <<'EOF'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\nr84 CGI response\n'
EOF
            chmod 755 /tmp/www/cgi-bin/bench
            bin=$(choose httpd /usr/sbin/uhttpd httpd-rs)
            "$bin" -f -h /tmp/www -r OpenWrt -x /cgi-bin -u /ubus -t 60 -T 30 -k 20 -A 1 -n 3 -N 100 -R -p 127.0.0.1:18080 > "$out/daemon.log" 2>&1 & subject=$!
            monitors=$subject,$rpc,$bus
            sleep 1; kill -0 "$subject"
            sha256sum /proc/"$rpc"/exe /proc/"$bus"/exe > "$out/dependencies-sha256.txt"
            "$bench" snapshot "$monitors" > "$out/startup.json"
            start_trace
            if [ "${OWRT_HTTPD_DIAG:-0}" != 0 ]; then
                sha256sum /tmp/bin/http-diagnostics > "$out/diagnostic-sha256.txt"
                printf '%s\n' "$OWRT_HTTPD_DIAG" > "$out/diagnostic-mode.txt"
                if [ "$OWRT_HTTPD_DIAG" = paced ]; then
                    /tmp/bin/http-diagnostics http-paced 127.0.0.1:18080 /static.dat /tmp/www/static.dat "$n" "${OWRT_HTTPD_DIAG_CLIENTS:-4}" "${OWRT_HTTPD_DIAG_GAP_MS:-0}" "$subject" > "$out/paced.json"
                else
                    rounds=${OWRT_HTTPD_DIAG_ROUNDS:-40}
                    [ "$rounds" -ge 2 ] && [ "$rounds" -le 500 ]
                    round=1
                    while [ "$round" -le "$rounds" ]; do
                        /tmp/bin/http-diagnostics http-resident 127.0.0.1:18080 /static.dat /tmp/www/static.dat 64 "$subject" > "$out/memory-$round.json"
                        round=$((round + 1))
                    done
                    n=$((rounds * 128))
                fi
            elif [ "${OWRT_HTTPD_MEMORY:-0}" = 1 ]; then
                # A separate diagnostic client; the frozen timing client above
                # remains unchanged and no latency samples are mixed in here.
                sha256sum /tmp/bin/memory-probe > "$out/memory-probe-sha256.txt"
                /tmp/bin/memory-probe http-resident 127.0.0.1:18080 /static.dat /tmp/www/static.dat 64 "$subject" > "$out/memory.json"
                n=128
            elif [ "${OWRT_HTTPD_CGI_STRESS:-0}" = 1 ]; then
                # In this mode N is per client, for reproducible long-lived
                # connection stress without unrelated static/RPC traffic.
                http_four cgi_stress_c4 GET /cgi-bin/bench - /tmp/expected.cgi "$((n * 4))" bytes
            else
                if [ -z "${OWRT_HTTPD_WORKLOADS:-}" ]; then
                    http_one static_16k GET /static.dat - /tmp/www/static.dat "$n" 20 bytes
                elif http_selected static_16k_dat_c1; then
                    http_one static_16k_dat_c1 GET /static.dat - /tmp/www/static.dat "$n" 20 bytes
                fi
                http_one cgi GET /cgi-bin/bench - /tmp/expected.cgi "$count_exec" 5 bytes
                http_one jsonrpc POST /ubus /tmp/http-post.json /tmp/http-expect.json "$n" 20 json
                if [ "${OWRT_HTTPD_MATRIX:-0}" = 1 ]; then
                    dd if=/dev/zero of=/tmp/www/small.dat bs=512 count=1 2>/dev/null
                    cp /tmp/www/static.dat /tmp/www/static.css
                    cp /www/luci-static/bootstrap/cascade.css /tmp/www/cascade.css
                    dd if=/dev/zero of=/tmp/www/medium.dat bs=65536 count=1 2>/dev/null
                    dd if=/dev/zero of=/tmp/www/large.dat bs=65536 count=16 2>/dev/null
                    sha256sum /tmp/www/*.dat /tmp/www/*.css > "$out/static-fixtures.sha256"
                    wc -c /tmp/www/*.dat /tmp/www/*.css > "$out/static-fixtures-sizes.txt"
                    for label in static_512_dat static_16k_dat static_16k_css static_image_css static_64k_dat static_1m_dat; do
                        matrix_count=$n
                        case "$label" in
                            static_512_dat) filename=small.dat ;;
                            static_16k_dat) filename=static.dat ;;
                            static_16k_css) filename=static.css ;;
                            static_image_css) filename=cascade.css ;;
                            static_64k_dat) filename=medium.dat ;;
                            static_1m_dat) filename=large.dat; matrix_count=$((n / 10)) ;;
                        esac
                        [ "$matrix_count" -gt 0 ] || matrix_count=1
                        if [ "$label" = static_16k_dat ]; then
                            # This is the existing measurement, not a second
                            # independent sample of the same workload.
                            if [ -f "$out/static_16k.json" ]; then cp "$out/static_16k.json" "$out/${label}_c1.json"; fi
                        else
                            http_one "${label}_c1" GET "/$filename" - "/tmp/www/$filename" "$matrix_count" 20 bytes
                        fi
                        http_four "${label}_c4" GET "/$filename" - "/tmp/www/$filename" "$matrix_count" bytes
                    done
                    http_four cgi_c4 GET /cgi-bin/bench - /tmp/expected.cgi "$count_exec" bytes
                    http_four jsonrpc_c4 POST /ubus /tmp/http-post.json /tmp/http-expect.json "$n" json
                    if [ -n "${OWRT_HTTPD_WORKLOADS:-}" ] && { http_selected jsonrpc_large || http_selected jsonrpc_large_c4; }; then
                        # Exact C rpcd UCI reply: 256 strings of 120 bytes.
                        # Generate the independent expected JSON alongside the UCI input.
                        awk 'BEGIN { s=""; for(i=0;i<120;i++)s=s "x"; print "config bench item"; for(i=0;i<256;i++)printf " list value \047%s\047\n",s }' > /etc/config/httpbench
                        awk 'BEGIN { s=""; for(i=0;i<120;i++)s=s "x"; printf "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[0,{\"value\":["; for(i=0;i<256;i++)printf "%s\"%s\"",i?",":"",s; print "]}]}" }' > /tmp/http-large-expect.json
                        ubus call session grant "{\"ubus_rpc_session\":\"$sid\",\"scope\":\"ubus\",\"objects\":[[\"uci\",\"get\"]]}" >/dev/null
                        ubus call session grant "{\"ubus_rpc_session\":\"$sid\",\"scope\":\"uci\",\"objects\":[[\"httpbench\",\"read\"]]}" >/dev/null
                        printf '{"jsonrpc":"2.0","id":1,"method":"call","params":["%s","uci","get",{"config":"httpbench","section":"item","option":"value"}]}\n' "$sid" > /tmp/http-large-post.json
                        sha256sum /tmp/http-large-expect.json /etc/config/httpbench > "$out/large-fixture.sha256"
                        http_one jsonrpc_large POST /ubus /tmp/http-large-post.json /tmp/http-large-expect.json "$n" 20 json
                        http_four jsonrpc_large_c4 POST /ubus /tmp/http-large-post.json /tmp/http-large-expect.json "$n" json
                    fi
                fi
            fi
            ;;
        *) echo 'unknown component' >&2; exit 2 ;;
    esac
    "$bench" snapshot "$monitors" > "$out/resident.json"
    if [ "$component" = httpd ]; then
        sleep 1
        "$bench" snapshot "$monitors" > "$out/after-close.json"
        if [ -r /proc/"$subject"/task/"$subject"/children ]; then
            cat /proc/"$subject"/task/*/children > "$out/after-close-children.txt"
        else
            printf 'unavailable: kernel does not expose task children\n' > "$out/after-close-children.txt"
        fi
    fi
    case "$component" in uci|reload-config|fw4) subject=null ;; esac
    kernel_log_mask=dev-null
    [ "$component" != logd ] || kernel_log_mask=empty-held-fifo
    printf '{"component":"%s","implementation":"%s","subject_pid":%s,"dependencies":"original OpenWrt","iterations":%s,"kernel_log_mask":"%s"}\n' "$component" "$impl" "$subject" "$n" "$kernel_log_mask" > "$out/meta.json"
    sha256sum "$bin" > "$out/binary-sha256.txt"
    if [ "$subject" != null ]; then sha256sum /proc/"$subject"/exe > "$out/subject-sha256.txt"; fi
    if [ -n "${tracer:-}" ]; then
        kill -INT "$tracer"
        # An attached strace exits with SIGINT's 128+2 status after detaching.
        if wait "$tracer"; then :; else [ "$?" -eq 130 ]; fi
        kill -0 "$subject"
        [ "$(awk '/^TracerPid:/ {print $2}' /proc/"$subject"/status)" = 0 ]
        [ -s "$out/syscalls.txt" ]
    fi
    if [ "${OWRT_NETIFD_EVENT_CAPTURE:-0}" = 1 ]; then touch "$out/CAPTURE_COMPLETE"; else touch "$out/COMPLETE"; fi
    # Namespace PID 1 destroys every descendant after this shell exits.
    exit 0
fi

[ "$#" -ge 5 ] || { echo 'usage: isolated.sh ROOTFS BUNDLE COMPONENT c|rs OUT [N]' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'namespace setup requires root' >&2; exit 2; }
image=$(cd "$1" && pwd); bundle=$(cd "$2" && pwd); component=$3; impl=$4
case "$component" in uci|fw4|reload-config|logd|rpcd|httpd|procd|ubusd|netifd) ;; *) exit 2 ;; esac
if [ "${OWRT_BENCH_TRACE:-0}" = 1 ]; then
    case "$component" in ubusd|procd|httpd) ;; *) exit 2 ;; esac
fi
case "$impl" in c|rs) ;; *) exit 2 ;; esac
mkdir -p "$5"; out=$(cd "$5" && pwd)
[ ! -e "$out/STARTED" ] || { echo 'refusing to mix benchmark runs' >&2; exit 2; }
touch "$out/STARTED"
n=${6:-10000}
case "$n" in ''|*[!0-9]*) exit 2 ;; esac
[ "$n" -gt 0 ] || exit 2
script=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
work=$(mktemp -d /tmp/r84-isolated.XXXXXX)
trap 'rm -rf "$work"' EXIT INT TERM
if [ -n "${OWRT_BENCH_GUARD:-}" ]; then
    "$OWRT_BENCH_GUARD" 600 "$bundle/ns-exec" /bin/sh "$script" --namespace "$image" "$bundle" "$component" "$impl" "$out" "$n" "$work" "$script"
else
    "$bundle/ns-exec" /bin/sh "$script" --namespace "$image" "$bundle" "$component" "$impl" "$out" "$n" "$work" "$script"
fi
[ -e "$out/COMPLETE" ] || { [ "${OWRT_NETIFD_EVENT_CAPTURE:-0}" = 1 ] && [ -e "$out/CAPTURE_COMPLETE" ]; }

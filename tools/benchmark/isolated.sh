#!/bin/sh
# One component at a time, all dependencies from the exact original image.
# Usage (root): sh isolated.sh ROOTFS BUNDLE COMPONENT c|rs OUT [N]
# BUNDLE contains ns-exec, owrt-benchmark and the nine shipped Rust binaries.
# On a physical router this is a device mutation and requires its recovery gate.
set -eu
case "${OWRT_BENCH_TRACE:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_HTTPD_MATRIX:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_HTTPD_CGI_STRESS:-0}" in 0|1) ;; *) exit 2 ;; esac
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
case "${OWRT_UBUSD_MATRIX:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_UBUSD_NORMALIZED:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_UBUSD_EXTENDED:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_NETIFD_MATRIX:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_NETIFD_SCALE:-32}" in 32|64|128) ;; *) exit 2 ;; esac
netifd_scale=${OWRT_NETIFD_SCALE:-32}
netifd_digits=2
[ "$netifd_scale" -ne 128 ] || netifd_digits=3
case "${OWRT_NETIFD_WARMUP:-20}" in ''|*[!0-9]*) exit 2 ;; esac
case "${OWRT_RPCD_CLIENT_DIAGNOSTIC:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_RPCD_CLIENT_ORDER:-tree-first}" in tree-first|wire-first) ;; *) exit 2 ;; esac
case "${OWRT_RPCD_PROFILE:-0}" in 0|1) ;; *) exit 2 ;; esac
case "${OWRT_RPCD_PROFILE_KIND:-rpc}" in rpc|file|uci_reply|uci|readiness) ;; *) exit 2 ;; esac
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
    rpc_warmup=20
    [ "$component" != netifd ] || rpc_warmup=${OWRT_NETIFD_WARMUP:-20}
    run_rpc() { # label object method input expected [iterations]
        netifd_lane_selected "$1" || return 0
        label=$1; object=$2; method=$3; input=$4; expected=$5; count=${6:-$n}
        printf '%s\n' "$input" > /tmp/input.json
        printf '%s\n' "$expected" > /tmp/expect.json
        "$bench" "$rpc_mode" "$socket" "$object" "$method" /tmp/input.json /tmp/expect.json "$count" "$rpc_warmup" "$monitors" > "$out/$label.json"
    }
    rpc_four() { # label object method input expected [total iterations]
        netifd_lane_selected "$1" || return 0
        label=$1; object=$2; method=$3; input=$4; expected=$5; total=${6:-$n}
        printf '%s\n' "$input" > /tmp/input.json
        printf '%s\n' "$expected" > /tmp/expect.json
        count=$((total / 4)); [ "$count" -gt 0 ] || count=1
        mkdir "$out/$label"
        printf '{"clients":4,"iterations_per_client":%s,"warmup_per_client":%s}\n' "$count" "$rpc_warmup" > "$out/$label/group.json"
        "$bench" snapshot "$monitors" > "$out/$label/before.json"
        clients=''; j=1
        while [ "$j" -le 4 ]; do
            "$bench" "$rpc_mode" "$socket" "$object" "$method" /tmp/input.json /tmp/expect.json "$count" "$rpc_warmup" "$monitors" > "$out/$label/client-$j.json" &
            clients="$clients $!"; j=$((j + 1))
        done
        failed=0
        for client in $clients; do wait "$client" || failed=1; done
        "$bench" snapshot "$monitors" > "$out/$label/after.json"
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
    http_four() { # label method path body expected total format
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
            run_rpc uci_configs uci configs '{}' '{"configs":[]}'
            run_rpc uci_get_network uci get '{"config":"network"}' '{"values":{"lan":{"proto":"static"}}}'
            run_rpc file_stat file stat '{"path":"/etc/config/network"}' '{"type":"file"}'
            run_rpc session_access session access '{"ubus_rpc_session":"00000000000000000000000000000000","scope":"ubus","object":"uci","function":"get"}' '{"access":false}'
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
                ubus call session grant "{\"ubus_rpc_session\":\"$sid\",\"scope\":\"uci\",\"objects\":[[\"net*\",\"r*\"]]}" >/dev/null
                rpc_pair uci_get_authorized uci get "{\"config\":\"network\",\"ubus_rpc_session\":\"$sid\"}" '{"values":{"lan":{"proto":"static"}}}'
                access="{\"ubus_rpc_session\":\"$sid\",\"scope\":\"uci\",\"object\":\"network\",\"function\":\"read\"}"
                rpc_pair session_access_granted session access "$access" '{"access":true}'
                rpc_pair file_list file list '{"path":"/etc/config"}' '{"entries":[{}]}'
                i=0
                while [ "$i" -lt 62 ]; do
                    ubus call session create '{"timeout":3600}' >/dev/null
                    i=$((i + 1))
                done
                rpc_pair session_access_64 session access "$access" '{"access":true}'
            fi
            ;;
        procd)
            bin=$(choose procd /sbin/procd procd-rs)
            "$bin" -S -I /tmp/empty-init -R /tmp/empty-rc > "$out/daemon.log" 2>&1 & subject=$!
            wait_object service "$subject"
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
            else
                bin=$(choose fw4 /sbin/fw4 fw4-rs)
                /sbin/fw4 print > /tmp/expected.rules 2> "$out/reference-stderr.log"
                "$bench" exec "$count_fw" 3 /tmp/expected.rules "$monitors" -- "$bin" print > "$out/print.json"
                # Kernel nft parsing is part of both commands; this is check
                # mode inside the throwaway network namespace.
                /sbin/fw4 check > /tmp/expected.check 2>> "$out/reference-stderr.log"
                "$bench" exec "$count_fw" 3 /tmp/expected.check "$monitors" -- "$bin" check > "$out/check.json"
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
            /sbin/uci -S -n export network > /tmp/expected.network
            /sbin/uci -S -n export r84fixture > /tmp/expected.fixture
            "$bench" exec "$count_exec" 5 /tmp/expected.network - -- "$bin" -S -n export network > "$out/export_network.json"
            "$bench" exec "$count_exec" 5 /tmp/expected.fixture - -- "$bin" -S -n export r84fixture > "$out/export_64.json"
            mkdir -p /tmp/uci-config /tmp/uci-save
            cp /etc/config/network /tmp/uci-config/
            cat > /tmp/write-uci.sh <<'EOF'
#!/bin/sh
set -eu
"$1" -c /tmp/uci-config -t /tmp/uci-save set "network.lan.r84=$R84_ITERATION"
"$1" -c /tmp/uci-config -t /tmp/uci-save commit network
value=$("$1" -c /tmp/uci-config -t /tmp/uci-save get network.lan.r84)
[ "$value" = "$R84_ITERATION" ]
EOF
            "$bench" exec "$count_exec" 5 /tmp/empty.bytes - -- /bin/sh /tmp/write-uci.sh "$bin" > "$out/set_commit_get.json"
            ;;
        reload-config)
            monitors=-
            bin=$(choose reload-config /sbin/reload_config reload_config_rs)
            # Both sides invoke the original uci and have private /var/run.
            # Establish each implementation's baseline before timing no-ops.
            /sbin/reload_config > /tmp/reference.stdout 2> /tmp/reference.stderr
            cp /var/run/config.md5 /tmp/reference.md5
            rm /var/run/config.md5
            "$bin" > "$out/prime.stdout" 2> "$out/prime.stderr"
            cmp -s /var/run/config.md5 /tmp/reference.md5
            "$bench" exec "$count_exec" 5 /tmp/empty.bytes - -- "$bin" > "$out/unchanged_config.json"
            cmp -s /var/run/config.md5 /tmp/reference.md5
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
                "$bench" http 127.0.0.1:18080 GET /static.dat - /tmp/www/static.dat "$n" 20 "$monitors" bytes > "$out/static_16k.json"
                "$bench" http 127.0.0.1:18080 GET /cgi-bin/bench - /tmp/expected.cgi "$count_exec" 5 "$monitors" bytes > "$out/cgi.json"
                "$bench" http 127.0.0.1:18080 POST /ubus /tmp/http-post.json /tmp/http-expect.json "$n" 20 "$monitors" json > "$out/jsonrpc.json"
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
                            cp "$out/static_16k.json" "$out/${label}_c1.json"
                        else
                            "$bench" http 127.0.0.1:18080 GET "/$filename" - "/tmp/www/$filename" "$matrix_count" 20 "$monitors" bytes > "$out/${label}_c1.json"
                        fi
                        http_four "${label}_c4" GET "/$filename" - "/tmp/www/$filename" "$matrix_count" bytes
                    done
                    http_four cgi_c4 GET /cgi-bin/bench - /tmp/expected.cgi "$count_exec" bytes
                    http_four jsonrpc_c4 POST /ubus /tmp/http-post.json /tmp/http-expect.json "$n" json
                fi
            fi
            ;;
        *) echo 'unknown component' >&2; exit 2 ;;
    esac
    "$bench" snapshot "$monitors" > "$out/resident.json"
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
    touch "$out/COMPLETE"
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
[ -e "$out/COMPLETE" ]

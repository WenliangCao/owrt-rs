#!/bin/sh
# R46: the netifd-rs sys layer against iproute2, on the same kernel.
#
# The same sequence of operations is performed twice in two fresh network
# namespaces: once by iproute2, once by netifd-rs's netlink encoders. The
# resulting kernel state is then dumped identically and compared. A difference
# means an encoding is wrong, because the two namespaces started identical and
# saw the same requests.
#
# Usage: r46_netlink_diff.sh <sysprobe binary> [outdir]
set -eu
probe=$1; out=${2:-/tmp/r46-out}
mkdir -p "$out"

# Deterministic values only: random MACs and live lifetimes would differ
# between the two runs for reasons that are not about the encoding.
MAC0=02:00:00:00:00:0a
MAC1=02:00:00:00:00:0b
MAC2=02:00:00:00:00:0c
MAC3=02:00:00:00:00:0d
MAC_BR=02:00:00:00:00:c0

dump() {
	# -d for the bridge parameters; the address and route tables in full.
	ip -d link show
	echo "--- addr"
	ip -o addr show
	echo "--- route4"
	ip -4 route show table all
	echo "--- route6"
	ip -6 route show table all
	echo "--- bridge"
	bridge link show
}

# Normalise what cannot be equal by construction: interface indices, the
# lifetimes that tick down between the two runs, and the qdisc handle.
norm() {
	sed -E \
		-e 's/^[0-9]+: /N: /' \
		-e 's/\bif[0-9]+\b/ifN/g' \
		-e 's/valid_lft [0-9]+sec/valid_lft Lsec/g' \
		-e 's/preferred_lft [0-9]+sec/preferred_lft Lsec/g' \
		-e 's/\bnumtxqueues [0-9]+\b/numtxqueues N/g' \
		-e 's/\bnumrxqueues [0-9]+\b/numrxqueues N/g' \
		-e 's/\bgso_max_[a-z]+ [0-9]+\b/gso_max N/g' \
		-e 's/\btso_max_[a-z]+ [0-9]+\b/tso_max N/g' \
		-e 's/\bgro_max_size [0-9]+\b/gro_max_size N/g' \
		-e 's/\bparentbus [^ ]+//g' \
		-e 's/\bbridge_id [0-9a-f.:]+/bridge_id ID/g' \
		-e 's/\bdesignated_root [0-9a-f.:]+/designated_root ID/g' \
		-e 's/\broot_id [0-9a-f.:]+/root_id ID/g' \
		-e 's/\bgc_timer[ ]+[0-9.]+/gc_timer T/g' \
		-e 's/\bhello_timer[ ]+[0-9.]+/hello_timer T/g' \
		-e 's/\btcn_timer[ ]+[0-9.]+/tcn_timer T/g' \
		-e 's/\btopology_change_timer[ ]+[0-9.]+/topology_change_timer T/g' \
		-e 's/\bforward_delay_timer[ ]+[0-9.]+/forward_delay_timer T/g' \
		-e 's/\bmessage_age_timer[ ]+[0-9.]+/message_age_timer T/g' \
		-e 's/\bhold_timer[ ]+[0-9.]+/hold_timer T/g'
}

# The scaffolding both runs share: two veth pairs. veth/dummy creation is
# explicitly out of netifd-rs's scope (R45 §6), so iproute2 builds it in both.
scaffold() {
	ip link add veth0 type veth peer name veth1
	ip link add veth2 type veth peer name veth3
	# every MAC is fixed: a kernel-random one would make the derived
	# link-local addresses differ between the two runs for no reason of ours
	ip link set veth0 address $MAC0
	ip link set veth1 address $MAC1
	ip link set veth2 address $MAC2
	ip link set veth3 address $MAC3
}

run_iproute2() {
	scaffold
	# netifd's bridge defaults, in the kernel's own units
	ip link add name br0 address $MAC_BR type bridge \
		stp_state 0 forward_delay 800 mcast_snooping 0 mcast_querier 0 \
		mcast_hash_max 512 vlan_filtering 0 priority 32767 \
		hello_time 100 max_age 1000
	ip link set veth0 master br0
	ip link set veth2 master br0
	ip link set br0 up
	ip link set veth0 up
	ip link set veth1 up
	ip link set veth2 up
	ip link set veth3 up
	ip link set veth3 mtu 1400
	ip link set veth3 txqueuelen 42
	ip link set veth1 address 02:00:00:00:00:11

	ip addr add 192.168.1.1/24 dev br0
	ip -6 addr add fd00::1/64 dev br0 preferred_lft 1800 valid_lft 3600
	ip -6 addr add 2001:db8::1/64 dev br0 noprefixroute
	ip addr add 10.0.0.1/24 dev veth1

	ip route add default via 10.0.0.2 dev veth1 proto static
	ip route add 172.16.0.0/16 dev veth1 proto static scope link
	ip route add 10.9.0.0/24 via 10.0.0.2 dev veth1 proto static metric 77
	ip route add 10.8.0.0/24 via 10.0.0.2 dev veth1 proto static table 100
	ip route add 10.7.0.0/24 via 10.0.0.2 dev veth1 proto static table 1000
	ip -6 route add 2001:db8:1::/64 via fd00::2 dev br0 proto static
	dump
}

run_rust() {
	scaffold
	P=$probe
	"$P" addbr br0 >/dev/null
	"$P" mac br0 $MAC_BR >/dev/null
	"$P" setmaster veth0 br0 >/dev/null
	"$P" setmaster veth2 br0 >/dev/null
	"$P" up br0 >/dev/null
	"$P" up veth0 >/dev/null
	"$P" up veth1 >/dev/null
	"$P" up veth2 >/dev/null
	"$P" up veth3 >/dev/null
	"$P" mtu veth3 1400 >/dev/null
	"$P" txqlen veth3 42 >/dev/null
	"$P" mac veth1 02:00:00:00:00:11 >/dev/null

	"$P" addr br0 192.168.1.1/24 >/dev/null
	"$P" addr br0 fd00::1/64 1800 3600 >/dev/null
	"$P" addr br0 2001:db8::1/64 "" "" offlink >/dev/null
	"$P" addr veth1 10.0.0.1/24 >/dev/null

	"$P" route veth1 0.0.0.0/0 10.0.0.2 >/dev/null
	"$P" route veth1 172.16.0.0/16 - >/dev/null
	"$P" route veth1 10.9.0.0/24 10.0.0.2 77 >/dev/null
	"$P" route veth1 10.8.0.0/24 10.0.0.2 0 100 >/dev/null
	"$P" route veth1 10.7.0.0/24 10.0.0.2 0 1000 >/dev/null
	"$P" route br0 2001:db8:1::/64 fd00::2 >/dev/null
	dump
}

if [ "${R46_INNER:-}" = "iproute2" ]; then run_iproute2; exit 0; fi
if [ "${R46_INNER:-}" = "rust" ]; then run_rust; exit 0; fi

self=$(readlink -f "$0")
sudo -n env R46_INNER=iproute2 unshare -n sh "$self" "$probe" > "$out/iproute2.txt" 2>&1 || true
sudo -n env R46_INNER=rust unshare -n sh "$self" "$probe" > "$out/rust.txt" 2>&1 || true
norm < "$out/iproute2.txt" > "$out/iproute2.norm"
norm < "$out/rust.txt" > "$out/rust.norm"

if diff -u "$out/iproute2.norm" "$out/rust.norm" > "$out/diff.txt"; then
	echo "RESULT: identical kernel state"
	echo "lines: $(wc -l < "$out/rust.norm")"
else
	echo "RESULT: DIFFERENT"
	head -60 "$out/diff.txt"
	exit 1
fi

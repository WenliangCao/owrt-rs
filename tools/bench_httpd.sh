#!/bin/sh
# Runs on the Mac. Starts the stock uhttpd on the router on alternate ports with
# the same flags the running httpd-rs got from /etc/config/uhttpd, then drives
# both with tools/bench_http_client.py from the LAN (macOS ab stalls at ~140 ms/req). Stops the extra uhttpd afterwards.
#   bench_httpd.sh [host] [requests] [concurrency]
set -eu
HOST=${1:-192.168.1.1}; N=${2:-400}; C=${3:-4}
R() { ssh -o ConnectTimeout=10 openwrt "$@"; }

# Same command line as httpd-rs minus its call log, on 8080/8443 instead of 80/443.
rs_cmd=$(R "tr '\\0' ' ' < /proc/\$(pidof httpd-rs | cut -d' ' -f1)/cmdline")
u_cmd=$(printf '%s' "$rs_cmd" | sed -e 's#/usr/sbin/httpd-rs#/rom/usr/sbin/uhttpd#' \
	-e 's/ --call-log [^ ]*//' -e 's/-p 0\.0\.0\.0:80/-p 0.0.0.0:8080/' -e 's/-p \[::\]:80/-p [::]:8080/' \
	-e 's/-s 0\.0\.0\.0:443/-s 0.0.0.0:8443/' -e 's/-s \[::\]:443/-s [::]:8443/')
echo "# httpd-rs: $rs_cmd"
echo "# uhttpd  : $u_cmd"
R "$u_cmd </dev/null >/tmp/bench-uhttpd.log 2>&1 & sleep 1; pgrep -f '[u]httpd.*8080' >/dev/null && echo '# uhttpd(8080) started'"
stop_uhttpd() { R 'for p in $(pgrep -f "[u]httpd.*8080"); do kill $p; done; true' >/dev/null 2>&1 || true; }
trap stop_uhttpd EXIT INT TERM

postfile=$(mktemp); printf '%s' '{"jsonrpc":"2.0","id":1,"method":"call","params":["00000000000000000000000000000000","luci-rpc","getBoardJSON",{}]}' > "$postfile"

CLIENT="python3 $(dirname "$0")/bench_http_client.py"
run() { # label impl url [client extra args]
	label=$1; impl=$2; url=$3; shift 3
	$CLIENT "$url" -n "$N" -c "$C" --label "$label/$impl" "$@"
}

for impl in rs c; do
	case $impl in rs) p=80; ps=443;; c) p=8080; ps=8443;; esac
	run static_css   $impl "http://$HOST:$p/luci-static/bootstrap/cascade.css"
	run static_index $impl "http://$HOST:$p/"
	run cgi_luci     $impl "http://$HOST:$p/cgi-bin/luci/"
	run ubus_jsonrpc $impl "http://$HOST:$p/ubus" --post "$postfile" --json
	run tls_css      $impl "https://$HOST:$ps/luci-static/bootstrap/cascade.css"
done
rm -f "$postfile"
R 'for p in httpd-rs uhttpd; do pid=$(pidof $p | cut -d" " -f1); [ -n "$pid" ] && echo "rss $p $(grep VmRSS /proc/$pid/status | awk "{print \$2 \" kB\"}") size $(ls -l $(readlink -f /proc/$pid/exe) | awk "{print \$5}")"; done'

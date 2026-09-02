#!/bin/sh
# Hit a running HTTP front end with the key contract requests and print
# status lines plus selected headers. Usage: tools/r14_http_probe.sh http://host:port [https://host:port]
set -u
for base in "$@"; do
	k=""; case "$base" in https:*) k="-k";; esac
	echo "=== $base"
	for path in / /index.html /luci-static/ /nope.txt /cgi-bin/luci /cgi-bin/luci/admin/status/overview; do
		printf '%-45s ' "GET $path"; curl $k -s -o /dev/null -m 20 -w '%{http_code} %{size_download}B ct=%{content_type}\n' "$base$path"
	done
	printf '%-45s ' "POST /ubus list"; curl $k -s -m 10 -w ' (%{http_code})\n' "$base/ubus" -d '{"jsonrpc":"2.0","id":1,"method":"list","params":["session"]}' | cut -c1-120
	printf '%-45s ' "POST /ubus access(login)"; curl $k -s -m 10 -w ' (%{http_code})\n' "$base/ubus" -d '{"jsonrpc":"2.0","id":2,"method":"call","params":["00000000000000000000000000000000","session","access",{"scope":"ubus","object":"session","function":"login"}]}'
	printf '%-45s ' "POST /ubus denied uci"; curl $k -s -m 10 -w ' (%{http_code})\n' "$base/ubus" -d '{"jsonrpc":"2.0","id":3,"method":"call","params":["00000000000000000000000000000000","uci","get",{"config":"system"}]}'
	printf '%-45s ' "GET /ubus/list/session"; curl $k -s -o /dev/null -m 10 -w '%{http_code} %{size_download}B\n' "$base/ubus/list/session"
	printf '%-45s ' "OPTIONS /ubus"; curl $k -s -o /dev/null -m 10 -X OPTIONS -w '%{http_code}\n' "$base/ubus"
	printf '%-45s ' "GET /index.html If-None-Match"; etag=$(curl $k -s -I -m 10 "$base/index.html" | awk -F': ' '/^ETag/ {print $2}' | tr -d '\r'); curl $k -s -o /dev/null -m 10 -H "If-None-Match: $etag" -w '%{http_code}\n' "$base/index.html"
	printf '%-45s ' "HEAD /cgi-bin/luci headers"; curl $k -s -I -m 20 "$base/cgi-bin/luci" | grep -i -E "^(HTTP|x-luci|content-type|cache-control)" | tr -d '\r' | tr '\n' '|'; echo
	if [ -n "$k" ]; then printf '%-45s ' "TLS"; curl -k -s -o /dev/null -m 10 -w 'tls=%{ssl_verify_result} ver=%{http_version}\n' "$base/index.html"; fi
done

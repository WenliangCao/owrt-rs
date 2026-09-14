#!/usr/bin/env python3
"""Differential check of the rpcd core objects (`session`, `uci`, `rc`) of
rpcd-rs against the original rpcd, each inside a disposable copy of the exact
rootfs with the exact ubusd + rpcd.

original : ubusd + rpcd (all plugins)
candidate: ubusd + rpcd-rs (session/uci/rc/file/luci) + rpcd whose core
           registrations fail silently and whose file.so/ucode.so are removed,
           i.e. the shape owrt-rpcd-switch enable (r3) produces.

Session ids are random: every id obtained by `login`/`create` is recorded and
replaced by <SIDn> (order of capture) before comparison; `expires` values are
masked; /var/run/rpcd-rs is folded onto /var/run/rpcd in shell dumps.

Usage: r17_rpcd_core_check.py <rootfs-files> <rpcd-rs-musl-binary> [--report out.json]
"""
import json, os, re, subprocess, sys, tempfile

DEFAULT_SID = "00000000000000000000000000000000"
MISSING_SID = "deadbeefdeadbeefdeadbeefdeadbeef"
CRYPT_HASH = "$5$r17saltA$0cpREw.xOZqxLbbudRMwBmkCzxvsplI//ABMwxhwqHB"   # secret17
SHADOW_HASH = "$5$r17saltB$0MMv9bhkSyi2oJtxo6seQDQZio177.Q3MzNnpHzLX73"  # shadow17

RPCD_LOGINS = """
config login
	option username 'r17crypt'
	option password '%s'
	list read 'luci-base'
	list read 'luci-mod-status-*'
	list write 'luci-base'
	list write '!luci-base-*'

config login
	option username 'r17shadow'
	option password '$p$r17shadow'
	list read '*'
	list write 'luci-mod-status-processes'

config login
	option username 'r17empty'
	option password ''
	list read 'unauthenticated'
""" % CRYPT_HASH

SCENARIO = r"""
set -eu
root=$1
impl=$2
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t tmpfs tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
mknod -m 666 "$root/dev/random" c 1 8
trap 'umount "$root/dev" 2>/dev/null || true; umount "$root/proc" 2>/dev/null || true' EXIT
chroot "$root" /bin/sh /tmp/steps.sh "$impl"
"""

PRELUDE = r"""#!/bin/sh
impl=$1
mkdir -p /var/run/ubus /tmp/out/res /var/lock /var/state /var/lib /tmp/.uci
exec 2>/tmp/out/trace.txt
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
ubusd_pid=$!
sleep 1
rs_pid=
if [ "$impl" = candidate ]; then
  /tmp/rpcd-rs -s /var/run/ubus/ubus.sock -t 30 >/tmp/out/rpcd-rs.log 2>&1 &
  rs_pid=$!
  for i in 1 2 3 4 5 6 7 8 9 10; do ubus list session >/dev/null 2>&1 && break; sleep 1; done
fi
/sbin/rpcd -s /var/run/ubus/ubus.sock -t 30 >/tmp/out/rpcd.log 2>&1 &
rpcd_pid=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
  ubus list session >/dev/null 2>&1 && ubus list uci >/dev/null 2>&1 && ubus list rc >/dev/null 2>&1 &&
  ubus list file >/dev/null 2>&1 && ubus list luci-rpc >/dev/null 2>&1 && break
  sleep 1
done
if [ "$impl" = candidate ]; then core_pid=$rs_pid; else core_pid=$rpcd_pid; fi
SID=; SID2=; SID3=; SIDS=; SIDE=; SIDX=; SIDT=; SIDZ=; SIDB=
subst() { printf '%s' "$1" | sed "s/@SID@/$SID/g; s/@SID2@/$SID2/g; s/@SID3@/$SID3/g; s/@SIDS@/$SIDS/g; s/@SIDE@/$SIDE/g; s/@SIDX@/$SIDX/g; s/@SIDT@/$SIDT/g; s/@SIDZ@/$SIDZ/g; s/@SIDB@/$SIDB/g"; }
req() {
  id=$1; obj=$2; method=$3; args=$(subst "$4")
  ubus -S -t 60 call "$obj" "$method" "$args" >/tmp/out/res/$id.out 2>/tmp/out/res/$id.err; echo $? >/tmp/out/res/$id.rc
}
cap() {
  var=$1; shift
  req "$@"
  sid=$(sed -n 's/.*"ubus_rpc_session":"\([0-9a-f]\{32\}\)".*/\1/p' /tmp/out/res/$1.out | head -n1)
  eval "$var=\$sid"
  echo "$sid" >>/tmp/out/sids.txt
}
shx() {
  id=$1; shift
  ( eval "$(subst "$*")" ) >/tmp/out/res/$id.out 2>/tmp/out/res/$id.err; echo $? >/tmp/out/res/$id.rc
}
"""

EPILOGUE = r"""
kill $rs_pid $rpcd_pid $ubusd_pid 2>/dev/null || true
sleep 1
"""

STEPS = []   # (id, kind, ...)
def req(sid, obj, method, args):
    STEPS.append((sid, "req", obj, method, json.dumps(args)))
def cap(var, sid, obj, method, args):
    STEPS.append((sid, "cap", var, obj, method, json.dumps(args)))
def shx(sid, cmd):
    STEPS.append((sid, "sh", cmd))

SORT_KEYS = set()   # JSON object key order not compared
SORT_LINES = set()  # output lines compared as a multiset

# ---------------------------------------------------------------- structure
shx("objects", "ubus list | sort")
shx("sig_session", "ubus -v list session")
shx("sig_uci", "ubus -v list uci")
shx("sig_rc", "ubus -v list rc")

# ---------------------------------------------------------------- session
req("s_list_default", "session", "list", {})
req("s_list_bysid_default", "session", "list", {"ubus_rpc_session": DEFAULT_SID})
req("s_list_missing", "session", "list", {"ubus_rpc_session": MISSING_SID})
req("s_access_default_login", "session", "access", {"ubus_rpc_session": DEFAULT_SID, "object": "session", "function": "login"})
req("s_access_default_uci", "session", "access", {"ubus_rpc_session": DEFAULT_SID, "scope": "uci", "object": "network", "function": "read"})
cap("SIDX", "s_create", "session", "create", {"timeout": 60})
cap("SID3", "s_create_notimeout", "session", "create", {})
cap("SIDZ", "s_create_zero", "session", "create", {"timeout": 0})
cap("SIDB", "s_create_badtype", "session", "create", {"timeout": "60"})
req("s_grant", "session", "grant", {"ubus_rpc_session": "@SIDX@", "scope": "ubus",
    "objects": [["file", "read"], ["uci", "*"], ["luci*", "get*"], ["bad"], ["x", "y", "z"], "notarray", [1, 2], ["file", "read"]]})
req("s_grant_default_scope", "session", "grant", {"ubus_rpc_session": "@SIDX@", "objects": [["session", "access"]]})
req("s_grant_other_scope", "session", "grant", {"ubus_rpc_session": "@SIDX@", "scope": "uci", "objects": [["network", "read"], ["fw*", "write"]]})
req("s_grant_noobjects", "session", "grant", {"ubus_rpc_session": "@SIDX@", "scope": "uci"})
req("s_grant_nosid", "session", "grant", {"scope": "ubus", "objects": [["a", "b"]]})
req("s_grant_missing", "session", "grant", {"ubus_rpc_session": MISSING_SID, "objects": [["a", "b"]]})
req("s_access_dump", "session", "access", {"ubus_rpc_session": "@SIDX@"})
req("s_access_yes", "session", "access", {"ubus_rpc_session": "@SIDX@", "object": "luci-foo", "function": "getX"})
req("s_access_no", "session", "access", {"ubus_rpc_session": "@SIDX@", "object": "luci-foo", "function": "set"})
req("s_access_star", "session", "access", {"ubus_rpc_session": "@SIDX@", "object": "uci", "function": "anything"})
req("s_access_scope_yes", "session", "access", {"ubus_rpc_session": "@SIDX@", "scope": "uci", "object": "fwtest", "function": "write"})
req("s_access_scope_no", "session", "access", {"ubus_rpc_session": "@SIDX@", "scope": "uci", "object": "network", "function": "write"})
req("s_access_missing_sid", "session", "access", {"ubus_rpc_session": MISSING_SID, "object": "a", "function": "b"})
req("s_access_noargs", "session", "access", {})
req("s_set", "session", "set", {"ubus_rpc_session": "@SIDX@", "values": {"str": "v", "num": 5, "neg": -3, "big": 12345678901, "bool": True, "list": [1, "a", False], "obj": {"k": "v", "n": 1}, "": "skipped", "nul": None}})
req("s_set_replace", "session", "set", {"ubus_rpc_session": "@SIDX@", "values": {"str": 42}})
req("s_set_novalues", "session", "set", {"ubus_rpc_session": "@SIDX@"})
req("s_set_badvalues", "session", "set", {"ubus_rpc_session": "@SIDX@", "values": ["a"]})
req("s_get_all", "session", "get", {"ubus_rpc_session": "@SIDX@"})
req("s_get_keys", "session", "get", {"ubus_rpc_session": "@SIDX@", "keys": ["str", "nosuch", "bool", "obj"]})
req("s_get_badkeys", "session", "get", {"ubus_rpc_session": "@SIDX@", "keys": [1, "num", ["x"]]})
req("s_get_keys_notarray", "session", "get", {"ubus_rpc_session": "@SIDX@", "keys": "str"})
req("s_get_missing", "session", "get", {"ubus_rpc_session": MISSING_SID})
req("s_unset_keys", "session", "unset", {"ubus_rpc_session": "@SIDX@", "keys": ["str", "nosuch", 7]})
req("s_get_after_unset", "session", "get", {"ubus_rpc_session": "@SIDX@"})
req("s_unset_all", "session", "unset", {"ubus_rpc_session": "@SIDX@"})
req("s_get_after_unset_all", "session", "get", {"ubus_rpc_session": "@SIDX@"})
req("s_revoke_one", "session", "revoke", {"ubus_rpc_session": "@SIDX@", "scope": "ubus", "objects": [["luci*", "get*"], ["nosuch", "x"]]})
req("s_access_after_revoke", "session", "access", {"ubus_rpc_session": "@SIDX@"})
req("s_revoke_scope", "session", "revoke", {"ubus_rpc_session": "@SIDX@", "scope": "ubus"})
req("s_revoke_missing_scope", "session", "revoke", {"ubus_rpc_session": "@SIDX@", "scope": "nosuchscope"})
req("s_access_after_revoke_scope", "session", "access", {"ubus_rpc_session": "@SIDX@"})
req("s_list_x", "session", "list", {"ubus_rpc_session": "@SIDX@"})
cap("SID", "s_login_root", "session", "login", {"username": "root", "password": "anything"})
cap("SID2", "s_login_crypt_ok", "session", "login", {"username": "r17crypt", "password": "secret17", "timeout": 100})
req("s_login_crypt_bad", "session", "login", {"username": "r17crypt", "password": "wrong"})
cap("SIDS", "s_login_shadow_ok", "session", "login", {"username": "r17shadow", "password": "shadow17"})
req("s_login_shadow_bad", "session", "login", {"username": "r17shadow", "password": "nope"})
cap("SIDE", "s_login_empty_pw", "session", "login", {"username": "r17empty", "password": "whatever"})
req("s_login_unknown_user", "session", "login", {"username": "nobody17", "password": "x"})
req("s_login_nopassword", "session", "login", {"username": "root"})
req("s_login_noargs", "session", "login", {})
req("s_login_badtype", "session", "login", {"username": "root", "password": 1})
req("s_list_root", "session", "list", {"ubus_rpc_session": "@SID@"})
req("s_list_crypt", "session", "list", {"ubus_rpc_session": "@SID2@"})
req("s_list_shadow", "session", "list", {"ubus_rpc_session": "@SIDS@"})
req("s_list_empty", "session", "list", {"ubus_rpc_session": "@SIDE@"})
req("s_list_all", "session", "list", {})
SORT_LINES.add("s_list_all")
req("s_access_root_uci", "session", "access", {"ubus_rpc_session": "@SID@", "scope": "uci", "object": "network", "function": "write"})
req("s_access_crypt_uci_r", "session", "access", {"ubus_rpc_session": "@SID2@", "scope": "uci", "object": "system", "function": "read"})
req("s_access_crypt_uci_w", "session", "access", {"ubus_rpc_session": "@SID2@", "scope": "uci", "object": "system", "function": "write"})
req("s_access_crypt_group", "session", "access", {"ubus_rpc_session": "@SID2@", "scope": "access-group", "object": "luci-base", "function": "write"})
req("s_access_crypt_group_neg", "session", "access", {"ubus_rpc_session": "@SID2@", "scope": "access-group", "object": "luci-base-network-status", "function": "read"})
req("s_destroy_default", "session", "destroy", {"ubus_rpc_session": DEFAULT_SID})
req("s_destroy_x", "session", "destroy", {"ubus_rpc_session": "@SIDX@"})
req("s_list_x_gone", "session", "list", {"ubus_rpc_session": "@SIDX@"})
req("s_destroy_again", "session", "destroy", {"ubus_rpc_session": "@SIDX@"})
req("s_destroy_noargs", "session", "destroy", {})
cap("SIDT", "s_create_short", "session", "create", {"timeout": 2})
req("s_list_short_before", "session", "list", {"ubus_rpc_session": "@SIDT@"})
shx("sleep_expiry", "sleep 3")
req("s_list_short_gone", "session", "list", {"ubus_rpc_session": "@SIDT@"})
req("s_list_zero_alive", "session", "list", {"ubus_rpc_session": "@SIDZ@"})

# ---------------------------------------------------------------- uci
req("u_configs", "uci", "configs", {})
req("u_get_pkg", "uci", "get", {"config": "dhcptest"})
req("u_get_pkg_sid", "uci", "get", {"config": "dhcptest", "ubus_rpc_session": "@SID@"})
req("u_get_sec", "uci", "get", {"config": "fwtest", "section": "@zone[0]"})
req("u_get_sec_named", "uci", "get", {"config": "dhcptest", "section": "lan"})
req("u_get_opt", "uci", "get", {"config": "dhcptest", "section": "lan", "option": "interface"})
req("u_get_list_opt", "uci", "get", {"config": "fwtest", "section": "@zone[0]", "option": "network"})
req("u_get_missing_sec", "uci", "get", {"config": "dhcptest", "section": "nosuch"})
req("u_get_missing_opt", "uci", "get", {"config": "dhcptest", "section": "lan", "option": "nosuch"})
req("u_get_missing_cfg", "uci", "get", {"config": "nosuchcfg"})
req("u_get_dotted_cfg", "uci", "get", {"config": "../passwd"})
req("u_get_type", "uci", "get", {"config": "fwtest", "type": "zone"})
req("u_get_match", "uci", "get", {"config": "fwtest", "type": "zone", "match": {"name": "lan"}})
req("u_get_match_list", "uci", "get", {"config": "fwtest", "match": {"network": "wan"}})
req("u_get_match_int", "uci", "get", {"config": "dhcptest", "match": {"start": 100}})
req("u_get_match_bool", "uci", "get", {"config": "fwtest", "type": "zone", "match": {"masq": True}})
req("u_get_match_nomatch", "uci", "get", {"config": "fwtest", "match": {"name": "zzz"}})
req("u_get_match_empty", "uci", "get", {"config": "fwtest", "type": "defaults", "match": {}})
req("u_get_match_badtype", "uci", "get", {"config": "fwtest", "type": "zone", "match": {"name": ["lan"]}})
req("u_get_bad_ext", "uci", "get", {"config": "fwtest", "section": "@zone[9]"})
req("u_get_ext_neg", "uci", "get", {"config": "fwtest", "section": "@zone[-1]"})
req("u_get_ext_malformed", "uci", "get", {"config": "fwtest", "section": "@zone["})
req("u_get_noconfig", "uci", "get", {})
req("u_get_denied", "uci", "get", {"config": "dhcptest", "ubus_rpc_session": "@SID2@"})
req("u_get_allowed_crypt", "uci", "get", {"config": "system", "section": "@system[0]", "ubus_rpc_session": "@SID2@"})
req("u_get_default_sid", "uci", "get", {"config": "dhcptest", "ubus_rpc_session": DEFAULT_SID})
req("u_get_missing_sid", "uci", "get", {"config": "dhcptest", "ubus_rpc_session": MISSING_SID})
req("u_state_before", "uci", "state", {"config": "dhcptest", "section": "lan"})
shx("state_set", "uci -P /var/state set dhcptest.lan.statev=1 && uci -P /var/state set dhcptest.stsec=stype && cat /var/state/dhcptest")
req("u_state_after", "uci", "state", {"config": "dhcptest", "section": "lan"})
req("u_state_pkg", "uci", "state", {"config": "dhcptest"})
req("u_get_after_state", "uci", "get", {"config": "dhcptest", "section": "lan"})
req("u_add_anon", "uci", "add", {"config": "fwtest", "type": "rule", "values": {"name": "r17", "src": "lan", "proto": ["tcp", "udp"], "enabled": True, "dest_port": 22}, "ubus_rpc_session": "@SID@"})
req("u_add_named", "uci", "add", {"config": "fwtest", "type": "rule", "name": "r17named", "values": {"src": "wan", "neg": -5, "big": 12345678901, "off": False}, "ubus_rpc_session": "@SID@"})
req("u_add_named_again", "uci", "add", {"config": "fwtest", "type": "redirect", "name": "r17named", "ubus_rpc_session": "@SID@"})
req("u_add_bad_type", "uci", "add", {"config": "fwtest", "type": "bad type", "ubus_rpc_session": "@SID@"})
req("u_add_type_dash", "uci", "add", {"config": "fwtest", "type": "with-dash", "ubus_rpc_session": "@SID@"})
req("u_add_bad_name", "uci", "add", {"config": "fwtest", "type": "rule", "name": "bad-name", "ubus_rpc_session": "@SID@"})
req("u_add_bad_values", "uci", "add", {"config": "fwtest", "type": "rule", "values": {"bad-opt": "x", "good": "y"}, "ubus_rpc_session": "@SID@"})
req("u_add_badvalue_type", "uci", "add", {"config": "fwtest", "type": "rule", "values": {"tbl": {"a": "b"}, "good": "y"}, "ubus_rpc_session": "@SID@"})
req("u_add_noargs", "uci", "add", {"config": "fwtest", "ubus_rpc_session": "@SID@"})
req("u_add_missing_cfg", "uci", "add", {"config": "nosuchcfg", "type": "rule", "ubus_rpc_session": "@SID@"})
req("u_add_denied", "uci", "add", {"config": "fwtest", "type": "rule", "ubus_rpc_session": "@SID2@"})
req("u_add_nosid", "uci", "add", {"config": "fwtest", "type": "include", "values": {"path": "/tmp/r17.nft"}})
req("u_changes_fwtest", "uci", "changes", {"config": "fwtest", "ubus_rpc_session": "@SID@"})
req("u_changes_all", "uci", "changes", {"ubus_rpc_session": "@SID@"})
req("u_changes_all_nosid", "uci", "changes", {})
req("u_changes_fwtest_nosid", "uci", "changes", {"config": "fwtest"})
req("u_changes_denied", "uci", "changes", {"config": "fwtest", "ubus_rpc_session": "@SID2@"})
req("u_changes_all_crypt", "uci", "changes", {"ubus_rpc_session": "@SID2@"})
req("u_changes_missing_cfg", "uci", "changes", {"config": "nosuchcfg", "ubus_rpc_session": "@SID@"})
req("u_set_named", "uci", "set", {"config": "fwtest", "section": "r17named", "values": {"src": "lan", "proto": ["tcp"], "name": "n1"}, "ubus_rpc_session": "@SID@"})
req("u_set_same", "uci", "set", {"config": "fwtest", "section": "r17named", "values": {"src": "lan"}, "ubus_rpc_session": "@SID@"})
req("u_set_list_to_str", "uci", "set", {"config": "fwtest", "section": "r17named", "values": {"proto": "all"}, "ubus_rpc_session": "@SID@"})
req("u_set_str_to_list", "uci", "set", {"config": "fwtest", "section": "r17named", "values": {"src": ["lan", "wan"]}, "ubus_rpc_session": "@SID@"})
req("u_set_list_to_list", "uci", "set", {"config": "fwtest", "section": "r17named", "values": {"src": ["wan"]}, "ubus_rpc_session": "@SID@"})
req("u_set_ext", "uci", "set", {"config": "fwtest", "section": "@rule[-1]", "values": {"target": "ACCEPT"}, "ubus_rpc_session": "@SID@"})
req("u_set_by_type_match", "uci", "set", {"config": "fwtest", "type": "zone", "match": {"name": "wan"}, "values": {"r17mark": "1"}, "ubus_rpc_session": "@SID@"})
req("u_set_by_type_all", "uci", "set", {"config": "fwtest", "type": "zone", "values": {"r17all": "y"}, "ubus_rpc_session": "@SID@"})
req("u_set_by_type_nomatch", "uci", "set", {"config": "fwtest", "type": "zone", "match": {"name": "zzz"}, "values": {"x": "1"}, "ubus_rpc_session": "@SID@"})
req("u_set_bad_opt", "uci", "set", {"config": "fwtest", "section": "r17named", "values": {"bad opt": "1", "fine": "2"}, "ubus_rpc_session": "@SID@"})
req("u_set_missing_sec", "uci", "set", {"config": "fwtest", "section": "nosuch", "values": {"a": "b"}, "ubus_rpc_session": "@SID@"})
req("u_set_bad_section", "uci", "set", {"config": "fwtest", "section": "bad-sec", "values": {"a": "b"}, "ubus_rpc_session": "@SID@"})
req("u_set_noargs", "uci", "set", {"config": "fwtest", "values": {"a": "b"}, "ubus_rpc_session": "@SID@"})
req("u_set_novalues", "uci", "set", {"config": "fwtest", "section": "r17named", "ubus_rpc_session": "@SID@"})
req("u_set_empty_list", "uci", "set", {"config": "fwtest", "section": "r17named", "values": {"proto": []}, "ubus_rpc_session": "@SID@"})
req("u_set_int_bool", "uci", "set", {"config": "fwtest", "section": "r17named", "values": {"n": 7, "b": False, "big": 12345678901, "neg": -5, "tbl": {"x": 1}}, "ubus_rpc_session": "@SID@"})
req("u_set_denied", "uci", "set", {"config": "fwtest", "section": "r17named", "values": {"a": "b"}, "ubus_rpc_session": "@SID2@"})
req("u_set_nosid", "uci", "set", {"config": "fwtest", "section": "r17named", "values": {"nosid": "1"}})
req("u_get_named_after_set", "uci", "get", {"config": "fwtest", "section": "r17named", "ubus_rpc_session": "@SID@"})
req("u_get_named_nosid", "uci", "get", {"config": "fwtest", "section": "r17named"})
req("u_changes_after_set", "uci", "changes", {"config": "fwtest", "ubus_rpc_session": "@SID@"})
req("u_delete_opt", "uci", "delete", {"config": "fwtest", "section": "r17named", "option": "name", "ubus_rpc_session": "@SID@"})
req("u_delete_opts", "uci", "delete", {"config": "fwtest", "section": "r17named", "options": ["n", "nosuch", 5], "ubus_rpc_session": "@SID@"})
req("u_delete_opts_none", "uci", "delete", {"config": "fwtest", "section": "r17named", "options": ["nosuch"], "ubus_rpc_session": "@SID@"})
req("u_delete_opt_missing", "uci", "delete", {"config": "fwtest", "section": "r17named", "option": "nosuch", "ubus_rpc_session": "@SID@"})
req("u_delete_by_type_match", "uci", "delete", {"config": "fwtest", "type": "rule", "match": {"name": "r17"}, "ubus_rpc_session": "@SID@"})
req("u_delete_by_match_opt", "uci", "delete", {"config": "fwtest", "type": "zone", "match": {"r17all": "y"}, "option": "r17all", "ubus_rpc_session": "@SID@"})
req("u_delete_type_nomatch", "uci", "delete", {"config": "fwtest", "type": "rule", "match": {"name": "zzz"}, "ubus_rpc_session": "@SID@"})
req("u_delete_noargs", "uci", "delete", {"config": "fwtest", "ubus_rpc_session": "@SID@"})
req("u_delete_bad_type", "uci", "delete", {"config": "fwtest", "type": "bad type", "ubus_rpc_session": "@SID@"})
req("u_delete_bad_section", "uci", "delete", {"config": "fwtest", "section": "bad-sec", "ubus_rpc_session": "@SID@"})
req("u_delete_sec_missing", "uci", "delete", {"config": "fwtest", "section": "nosuch", "ubus_rpc_session": "@SID@"})
req("u_delete_denied", "uci", "delete", {"config": "fwtest", "section": "r17named", "ubus_rpc_session": "@SID2@"})
req("u_rename_sec", "uci", "rename", {"config": "fwtest", "section": "r17named", "name": "r17renamed", "ubus_rpc_session": "@SID@"})
req("u_rename_opt", "uci", "rename", {"config": "fwtest", "section": "r17renamed", "option": "proto", "name": "protocol", "ubus_rpc_session": "@SID@"})
req("u_rename_missing_opt", "uci", "rename", {"config": "fwtest", "section": "r17renamed", "option": "nosuch", "name": "x", "ubus_rpc_session": "@SID@"})
req("u_rename_bad_name", "uci", "rename", {"config": "fwtest", "section": "r17renamed", "name": "bad-name", "ubus_rpc_session": "@SID@"})
req("u_rename_missing_sec", "uci", "rename", {"config": "fwtest", "section": "nosuch", "name": "x", "ubus_rpc_session": "@SID@"})
req("u_rename_ext_sec", "uci", "rename", {"config": "fwtest", "section": "@zone[0]", "name": "x", "ubus_rpc_session": "@SID@"})
req("u_rename_noargs", "uci", "rename", {"config": "fwtest", "section": "r17renamed", "ubus_rpc_session": "@SID@"})
req("u_rename_denied", "uci", "rename", {"config": "fwtest", "section": "r17renamed", "name": "x", "ubus_rpc_session": "@SID2@"})
req("u_order", "uci", "order", {"config": "dhcptest", "sections": ["wan", "lan"], "ubus_rpc_session": "@SID@"})
req("u_get_dhcptest_after_order", "uci", "get", {"config": "dhcptest", "ubus_rpc_session": "@SID@"})
req("u_order_bad", "uci", "order", {"config": "dhcptest", "sections": ["nosuch", "lan"], "ubus_rpc_session": "@SID@"})
req("u_order_badtype", "uci", "order", {"config": "dhcptest", "sections": [1, "lan"], "ubus_rpc_session": "@SID@"})
req("u_order_ext", "uci", "order", {"config": "dhcptest", "sections": ["@dnsmasq[0]"], "ubus_rpc_session": "@SID@"})
req("u_order_noargs", "uci", "order", {"config": "dhcptest", "ubus_rpc_session": "@SID@"})
req("u_order_denied", "uci", "order", {"config": "dhcptest", "sections": ["lan"], "ubus_rpc_session": "@SID2@"})
req("u_changes_full_fw", "uci", "changes", {"config": "fwtest", "ubus_rpc_session": "@SID@"})
req("u_changes_full_dhcp", "uci", "changes", {"config": "dhcptest", "ubus_rpc_session": "@SID@"})
req("u_changes_full_all", "uci", "changes", {"ubus_rpc_session": "@SID@"})
req("u_get_fwtest_pending", "uci", "get", {"config": "fwtest", "ubus_rpc_session": "@SID@"})
req("u_revert_dhcptest", "uci", "revert", {"config": "dhcptest", "ubus_rpc_session": "@SID@"})
req("u_changes_dhcp_after_revert", "uci", "changes", {"config": "dhcptest", "ubus_rpc_session": "@SID@"})
req("u_revert_missing", "uci", "revert", {"config": "nosuchcfg", "ubus_rpc_session": "@SID@"})
req("u_revert_denied", "uci", "revert", {"config": "fwtest", "ubus_rpc_session": "@SID2@"})
req("u_revert_noargs", "uci", "revert", {"ubus_rpc_session": "@SID@"})
req("u_commit_fwtest", "uci", "commit", {"config": "fwtest", "ubus_rpc_session": "@SID@"})
shx("fwtest_after_commit", "cat /etc/config/fwtest; ls -l /etc/config/fwtest | awk '{print $1, $3, $4, $5}'")
req("u_changes_after_commit", "uci", "changes", {"config": "fwtest", "ubus_rpc_session": "@SID@"})
req("u_changes_after_commit_nosid", "uci", "changes", {"config": "fwtest"})
req("u_commit_missing", "uci", "commit", {"config": "nosuchcfg", "ubus_rpc_session": "@SID@"})
req("u_commit_denied", "uci", "commit", {"config": "fwtest", "ubus_rpc_session": "@SID2@"})
req("u_commit_noargs", "uci", "commit", {"ubus_rpc_session": "@SID@"})
req("u_commit_nosid", "uci", "commit", {"config": "fwtest"})
shx("fwtest_after_commit2", "cat /etc/config/fwtest; ls /tmp/.uci")
# apply / confirm
req("u_set_for_apply", "uci", "set", {"config": "dhcptest", "section": "lan", "values": {"r17apply": "1"}, "ubus_rpc_session": "@SID@"})
req("u_apply_rollback", "uci", "apply", {"ubus_rpc_session": "@SID@", "rollback": True, "timeout": 60})
shx("apply_state", "grep -c r17apply /etc/config/dhcptest; d=/var/run/rpcd; [ -d /var/run/rpcd-rs ] && d=/var/run/rpcd-rs; for s in $d/snapshot-files $d/snapshot-delta; do [ -d $s ] || continue; echo \"== $s\"; ls $s; for f in $s/*; do echo \"-- $f\"; cat $f; done; done")
req("u_commit_during_apply", "uci", "commit", {"config": "fwtest", "ubus_rpc_session": "@SID@"})
req("u_revert_during_apply", "uci", "revert", {"config": "fwtest", "ubus_rpc_session": "@SID@"})
req("u_apply_again_rollback", "uci", "apply", {"ubus_rpc_session": "@SID@", "rollback": True})
req("u_apply_again_norollback", "uci", "apply", {"ubus_rpc_session": "@SID@"})
req("u_confirm_wrong_sid", "uci", "confirm", {"ubus_rpc_session": "@SID2@"})
req("u_confirm_noargs", "uci", "confirm", {})
req("u_confirm", "uci", "confirm", {"ubus_rpc_session": "@SID@"})
req("u_confirm_again", "uci", "confirm", {"ubus_rpc_session": "@SID@"})
req("u_rollback_nodata", "uci", "rollback", {"ubus_rpc_session": "@SID@"})
req("u_rollback_nodata_noargs", "uci", "rollback", {})
shx("apply_state2", "grep -c r17apply /etc/config/dhcptest; d=/var/run/rpcd; [ -d /var/run/rpcd-rs ] && d=/var/run/rpcd-rs; ls $d")
# apply / rollback
req("u_set_for_rb", "uci", "set", {"config": "dhcptest", "section": "lan", "values": {"r17rb": "1"}, "ubus_rpc_session": "@SID@"})
req("u_apply_rb2", "uci", "apply", {"ubus_rpc_session": "@SID@", "rollback": True, "timeout": 60})
req("u_rollback_wrong", "uci", "rollback", {"ubus_rpc_session": "@SID2@"})
req("u_rollback_noargs", "uci", "rollback", {})
req("u_rollback", "uci", "rollback", {"ubus_rpc_session": "@SID@"})
shx("rb_state", "grep -c r17rb /etc/config/dhcptest; grep -c r17apply /etc/config/dhcptest; d=/var/run/rpcd; [ -d /var/run/rpcd-rs ] && d=/var/run/rpcd-rs; ls $d")
req("u_changes_after_rollback", "uci", "changes", {"config": "dhcptest", "ubus_rpc_session": "@SID@"})
req("u_rollback_after", "uci", "rollback", {"ubus_rpc_session": "@SID@"})
req("u_revert_after_rb", "uci", "revert", {"config": "dhcptest", "ubus_rpc_session": "@SID@"})
# apply / timer
req("u_set_for_timer", "uci", "set", {"config": "dhcptest", "section": "lan", "values": {"r17timer": "1"}, "ubus_rpc_session": "@SID@"})
req("u_apply_timer", "uci", "apply", {"ubus_rpc_session": "@SID@", "rollback": True, "timeout": 1})
shx("timer_state_before", "grep -c r17timer /etc/config/dhcptest")
shx("sleep_timer", "sleep 3")
shx("timer_state_after", "grep -c r17timer /etc/config/dhcptest; d=/var/run/rpcd; [ -d /var/run/rpcd-rs ] && d=/var/run/rpcd-rs; ls $d")
req("u_rollback_after_timer", "uci", "rollback", {"ubus_rpc_session": "@SID@"})
req("u_changes_after_timer", "uci", "changes", {"config": "dhcptest", "ubus_rpc_session": "@SID@"})
req("u_revert_after_timer", "uci", "revert", {"config": "dhcptest", "ubus_rpc_session": "@SID@"})
# apply edge cases
req("u_apply_nochanges", "uci", "apply", {"ubus_rpc_session": "@SID3@"})
req("u_apply_nosid", "uci", "apply", {})
req("u_apply_missing_sid", "uci", "apply", {"ubus_rpc_session": MISSING_SID})
req("u_apply_plain", "uci", "apply", {"ubus_rpc_session": "@SID@"})
req("u_set_apply_denied", "uci", "set", {"config": "system", "section": "@system[0]", "values": {"r17x": "1"}, "ubus_rpc_session": "@SID2@"})
req("u_apply_denied", "uci", "apply", {"ubus_rpc_session": "@SID2@"})
req("u_apply_empty_delta", "uci", "apply", {"ubus_rpc_session": "@SIDS@"})
shx("apply_denied_state", "grep -c r17x /etc/config/system; for d in /var/run/rpcd/uci-* /var/run/rpcd-rs/uci-*; do [ -d $d ] || continue; echo \"== $d\"; ls $d; done")

# ---------------------------------------------------------------- rc
shx("rc_prep", "cp /etc/init.d/cron /etc/init.d/r17bad && chmod 0777 /etc/init.d/r17bad && cp /etc/init.d/cron /etc/init.d/r17noexec && chmod 0644 /etc/init.d/r17noexec && printf '#!/bin/sh /etc/rc.common\\nSTART=0x1f\\nSTOP=010\\nUSE_PROCD=1\\n' > /etc/init.d/r17odd && chmod 0755 /etc/init.d/r17odd && printf '#!/bin/sh /etc/rc.common\\n# 1\\n# 2\\n# 3\\n# 4\\n# 5\\n# 6\\n# 7\\n# 8\\n# 9\\n# 10\\nSTART=55\\n' > /etc/init.d/r17late && chmod 0755 /etc/init.d/r17late && chown 0:0 /etc/init.d/r17*")
req("rc_list_skip", "rc", "list", {"skip_running_check": True})
SORT_KEYS.add("rc_list_skip")
req("rc_list_one", "rc", "list", {"name": "cron"})
req("rc_list_one_skip", "rc", "list", {"name": "cron", "skip_running_check": True})
req("rc_list_odd", "rc", "list", {"name": "r17odd"})
req("rc_list_late", "rc", "list", {"name": "r17late"})
req("rc_list_bad", "rc", "list", {"name": "r17bad"})
req("rc_list_noexec", "rc", "list", {"name": "r17noexec"})
req("rc_list_missing", "rc", "list", {"name": "nosuch"})
req("rc_list_badtype", "rc", "list", {"name": 5, "skip_running_check": True})
SORT_KEYS.add("rc_list_badtype")
req("rc_list_full", "rc", "list", {})
SORT_KEYS.add("rc_list_full")
req("rc_init_disable", "rc", "init", {"name": "cron", "action": "disable"})
req("rc_list_cron_disabled", "rc", "list", {"name": "cron", "skip_running_check": True})
req("rc_init_enable", "rc", "init", {"name": "cron", "action": "enable"})
req("rc_list_cron_enabled", "rc", "list", {"name": "cron", "skip_running_check": True})
req("rc_init_bad_action", "rc", "init", {"name": "cron", "action": "bogus"})
req("rc_init_missing", "rc", "init", {"name": "nosuch", "action": "disable"})
req("rc_init_dotdot", "rc", "init", {"name": "../passwd", "action": "disable"})
req("rc_init_slash", "rc", "init", {"name": "x/y", "action": "disable"})
req("rc_init_bad_perm", "rc", "init", {"name": "r17bad", "action": "disable"})
req("rc_init_noargs", "rc", "init", {"name": "cron"})
req("rc_init_badtype", "rc", "init", {"name": "cron", "action": 1})
req("rc_nomethod", "rc", "nosuch", {})

# ---------------------------------------------------------------- SIGHUP freeze/thaw
req("s_set_before_hup", "session", "set", {"ubus_rpc_session": "@SID@", "values": {"keep": "me", "n": 3, "flag": True}})
shx("hup", "kill -HUP $core_pid; for i in 1 2 3 4 5 6 7 8 9 10; do sleep 1; ubus list session >/dev/null 2>&1 && ubus -S call session list '{\"ubus_rpc_session\":\"@SID@\"}' >/dev/null 2>&1 && break; done; echo waited=$i")
req("s_list_root_after_hup", "session", "list", {"ubus_rpc_session": "@SID@"})
req("s_get_after_hup", "session", "get", {"ubus_rpc_session": "@SID@"})
req("s_list_crypt_after_hup", "session", "list", {"ubus_rpc_session": "@SID2@"})
req("s_list_zero_after_hup", "session", "list", {"ubus_rpc_session": "@SIDZ@"})
req("s_list_default_after_hup", "session", "list", {"ubus_rpc_session": DEFAULT_SID})
req("u_changes_after_hup", "uci", "changes", {"ubus_rpc_session": "@SID@"})
req("u_get_after_hup", "uci", "get", {"config": "dhcptest", "section": "lan", "ubus_rpc_session": "@SID@"})
shx("objects_after_hup", "ubus list | sort")
req("u_reload_config", "uci", "reload_config", {})

# ---------------------------------------------------------------- dumps
shx("d_tmp_uci", "ls /tmp/.uci; for f in /tmp/.uci/*; do [ -f \"$f\" ] || continue; echo \"== $f\"; cat \"$f\"; done")
shx("d_savedirs", "for d in /var/run/rpcd/uci-* /var/run/rpcd-rs/uci-*; do [ -d \"$d\" ] || continue; echo \"== $d\"; ls -l \"$d\" | awk 'NR>1{print $1, $3, $4, $5, $NF}'; for f in \"$d\"/*; do [ -f \"$f\" ] || continue; echo \"-- $f\"; cat \"$f\"; done; done")
shx("d_rundir", "d=/var/run/rpcd; [ -d /var/run/rpcd-rs ] && d=/var/run/rpcd-rs; ls -l $d | awk 'NR>1{print $1, $3, $4, $NF}'")
shx("d_configs", "for f in fwtest dhcptest system; do echo \"== $f\"; cat /etc/config/$f; ls -l /etc/config/$f | awk '{print $1, $3, $4, $5}'; done")
shx("d_state", "cat /var/state/dhcptest")
shx("d_rcd", "ls /etc/rc.d | sort")

# R85: list configs from fresh directory entries, including live symlink targets.
# This runs only in the disposable rootfs after the other config scenarios.
shx("u_listing_setup", "mv /etc/config /tmp/r85-listing-original && mkdir /etc/config")
req("u_listing_empty", "uci", "configs", {})
shx("u_listing_hidden_setup", "touch /etc/config/.hidden")
req("u_listing_hidden", "uci", "configs", {})
shx("u_listing_excluded_setup", "touch /etc/config/has.dot '/etc/config/bad name'; mkdir /etc/config/directory")
req("u_listing_excluded", "uci", "configs", {})
shx("u_listing_links_setup", "touch /etc/config/alpha /etc/config/zeta; ln -s zeta /etc/config/filelink; ln -s directory /etc/config/dirlink; ln -s missing /etc/config/broken")
req("u_listing_links", "uci", "configs", {})
shx("u_listing_changed_setup", "rm /etc/config/alpha /etc/config/zeta; mkdir /etc/config/zeta; rmdir /etc/config/directory; touch /etc/config/directory /etc/config/newconfig")
req("u_listing_changed", "uci", "configs", {})
shx("u_listing_restore", "rm -rf /etc/config && mv /tmp/r85-listing-original /etc/config")


def build_steps():
    lines = [PRELUDE]
    for st in STEPS:
        sid, kind = st[0], st[1]
        if kind == "req":
            lines.append("req %s %s %s %s" % (sid, st[2], st[3], shquote(st[4])))
        elif kind == "cap":
            lines.append("cap %s %s %s %s %s" % (st[2], sid, st[3], st[4], shquote(st[5])))
        else:
            lines.append("shx %s %s" % (sid, shquote(st[2])))
    lines.append(EPILOGUE)
    return "\n".join(lines) + "\n"


def shquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def sudo(*args, **kw):
    return subprocess.run(["sudo", "-n"] + list(args), check=kw.pop("check", True), **kw)


def run_side(rootfs, impl, binary, prepare_root=None):
    tmp = tempfile.mkdtemp(prefix="owrt-r17-")
    root = os.path.join(tmp, "root")
    sudo("cp", "-a", rootfs, root)
    sudo("chown", "-R", "root:root", os.path.join(root, "etc/init.d"), os.path.join(root, "etc/rc.d"), os.path.join(root, "etc/config"), os.path.join(root, "usr/share/acl.d"))
    sudo("sh", "-c", "cp %s/etc/config/firewall %s/etc/config/fwtest && cp %s/etc/config/dhcp %s/etc/config/dhcptest && chmod 0600 %s/etc/config/fwtest %s/etc/config/dhcptest" % ((root,) * 6))
    sudo("sh", "-c", "cat >> %s/etc/config/rpcd" % root, input=RPCD_LOGINS.encode())
    sudo("sh", "-c", "printf '%%s\\n' 'r17shadow:%s:0:0:99999:7:::' >> %s/etc/shadow" % (SHADOW_HASH, root))
    if prepare_root is not None:
        prepare_root(root)
    if impl == "candidate":
        sudo("rm", "-f", os.path.join(root, "usr/lib/rpcd/file.so"), os.path.join(root, "usr/lib/rpcd/ucode.so"))
        sudo("cp", binary, os.path.join(root, "tmp/rpcd-rs"))
        sudo("chmod", "755", os.path.join(root, "tmp/rpcd-rs"))
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(build_steps())
        steps = f.name
    sudo("cp", steps, os.path.join(root, "tmp/steps.sh"))
    os.unlink(steps)
    sudo("setsid", "-w", "unshare", "--mount", "--fork", "/bin/sh", "-c", SCENARIO, "sh", root, impl, check=False, timeout=1800)
    out = {}
    resdir = os.path.join(root, "tmp/out/res")
    names = sudo("ls", resdir, capture_output=True, text=True, check=False).stdout.split()
    for name in names:
        out[name] = sudo("cat", os.path.join(resdir, name), capture_output=True, check=False).stdout
    sids = sudo("cat", os.path.join(root, "tmp/out/sids.txt"), capture_output=True, text=True, check=False).stdout.split()
    logs = {}
    for name in ("rpcd.log", "rpcd-rs.log", "ubusd.log", "trace.txt"):
        logs[name] = sudo("cat", os.path.join(root, "tmp/out", name), capture_output=True, check=False).stdout.decode(errors="replace")[-3000:]
    sudo("rm", "-rf", "--", tmp, check=False)
    return out, sids, logs


def normalize(sid, data, sids):
    text = data.decode("utf-8", errors="replace")
    for i, s in enumerate(sids):
        if s:
            text = text.replace(s, "<SID%d>" % (i + 1))
    text = re.sub(r'"expires":\d+', '"expires":<N>', text)
    text = re.sub(r"^('[a-z-]+') @[0-9a-f]{8}$", r"\1 @<typeid>", text, flags=re.M)
    text = text.replace("/var/run/rpcd-rs", "/var/run/rpcd")
    if sid in SORT_KEYS:
        try:
            text = json.dumps(json.loads(text), sort_keys=True)
        except Exception:
            pass
    if sid in SORT_LINES:
        text = "\n".join(sorted(text.splitlines()))
    return text


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    report = None
    if "--report" in sys.argv:
        report = sys.argv[sys.argv.index("--report") + 1]
        args.remove(report)
    rootfs, binary = args[0], args[1]
    orig, osids, ologs = run_side(rootfs, "original", binary)
    cand, csids, clogs = run_side(rootfs, "candidate", binary)
    ndiff = 0
    details = []
    for st in STEPS:
        sid = st[0]
        same = True
        for ext in ("rc", "out", "err"):
            k = "%s.%s" % (sid, ext)
            if k not in orig or k not in cand or normalize(sid, orig[k], osids) != normalize(sid, cand[k], csids):
                same = False
        if same:
            print("OK   %s" % sid)
            continue
        ndiff += 1
        print("DIFF %s   [%s]" % (sid, " ".join(str(x) for x in st[1:])[:90]))
        for ext in ("rc", "out", "err"):
            k = "%s.%s" % (sid, ext)
            o = normalize(sid, orig.get(k, b""), osids)
            c = normalize(sid, cand.get(k, b""), csids)
            if o != c:
                print("   %s orig: %s" % (ext, o[:700]))
                print("   %s cand: %s" % (ext, c[:700]))
        details.append(sid)
    n = len(STEPS)
    print("\n%d steps: %d identical, %d differ" % (n, n - ndiff, ndiff))
    if ndiff:
        for name, v in clogs.items():
            if v.strip():
                print("[candidate %s]\n%s" % (name, v[-1200:]))
        for name, v in ologs.items():
            if v.strip() and name != "trace.txt":
                print("[original %s]\n%s" % (name, v[-600:]))
    if report:
        json.dump({"steps": n, "identical": n - ndiff, "differ": ndiff, "differing": details,
                   "sids_captured": [len(osids), len(csids)]}, open(report, "w"), indent=2)
    sys.exit(1 if ndiff else 0)


if __name__ == "__main__":
    main()

#!/bin/sh
# R83 / R81-F17 gate: an invalid option in `config defaults` -- or in `config
# include`, the same failure class one section type over -- must abort exactly
# like the upstream ucode fw4 -- no ruleset on stdout, exit 254 -- instead of
# falling through to an all-None Defaults and rendering `policy null;` (defaults)
# or to the "is disabled, ignoring section" branch (include).
#
# Both sides get the same fixture: our own `uci/firewall.json` shadowing the one
# in the upstream `tests/mocks` (the layout run_tests.sh builds), so the ucode
# reference and fw4-rs read byte-identical input. Every case compares the exit
# code and stdout byte for byte. stderr is compared with the ucode interpreter
# backtrace removed (the `Reference error:` line and everything after it): the
# crate mirrors fw4's own warnings, not the interpreter's traceback.
#
# Usage: sh tools/r83_fw4_defaults.sh <firewall4-src-dir> <fw4-rs-binary> [ucode]
#   e.g. sh tools/r83_fw4_defaults.sh ~/stage4/firewall4 \
#            components/fw4/target/release/fw4-rs
# Exit 0 only when every case matched and the sentinels below held.
#
# Sentinels (a green run must have compared something):
#   * abort cases: the reference must really have crashed -- rc 254 *and* a
#     `Reference error:` backtrace. If a future firewall4 stops crashing the
#     gate fails instead of silently agreeing with a dead reference.
#   * control cases (valid defaults / no defaults section / disabled include):
#     both sides must exit 0 with identical, non-empty rulesets containing a
#     real policy, so a two-sided empty output cannot pass.
set -u

SRC=${1:?firewall4 source dir}
BIN=${2:?fw4-rs binary}
UCODE=${3:-ucode}

SRC=$(cd "$SRC" && pwd) || exit 2
case $BIN in /*) ;; *) BIN=$(pwd)/$BIN ;; esac
[ -x "$BIN" ] || { echo "no such binary: $BIN" >&2; exit 2; }
[ -f "$SRC/root/usr/share/ucode/fw4.uc" ] || { echo "not a firewall4 checkout: $SRC" >&2; exit 2; }

W=$(mktemp -d "${TMPDIR:-/tmp}/r83fw4.XXXXXX") || exit 2
trap 'rm -rf "$W"' EXIT INT TERM

cat > "$W/case.in" <<'EOT'
{%
	include("./root/usr/share/firewall4/main.uc", {
		getenv: function(varname) {
			switch (varname) {
			case 'ACTION':
				return 'print';
			}
		}
	})
%}
EOT

# $1 = case name, $2 = extra `option` lines for the defaults section
fixture() {
	mkdir -p "$W/$1/files/uci"
	{
		printf '{\n\t"defaults": {\n\t\t"output": "ACCEPT"'
		[ -n "$2" ] && printf ',\n%s' "$2"
		printf '\n\t},\n'
		cat <<-'EOT'
			"zone": [
				{
					"name": "lan",
					"input": "ACCEPT",
					"output": "ACCEPT",
					"forward": "ACCEPT",
					"network": [ "lan" ]
				}
			],
			"rule": [
				{
					"name": "Allow-Ping",
					"family": "ipv4",
					"proto": "icmp",
					"src": "wan",
					"icmp_type": "echo-request",
					"target": "ACCEPT"
				}
			]
		}
		EOT
	} > "$W/$1/files/uci/firewall.json"
}

# $1 = case name, $2 = the `config include` section body
fixture_include() {
	mkdir -p "$W/$1/files/uci"
	{
		cat <<-'EOT'
			{
				"zone": [
					{
						"name": "lan",
						"input": "ACCEPT",
						"output": "ACCEPT",
						"forward": "ACCEPT",
						"network": [ "lan" ]
					}
				],
				"include": [
					{
		EOT
		printf '%s\n' "$2"
		cat <<-'EOT'
					}
				]
			}
		EOT
	} > "$W/$1/files/uci/firewall.json"
}

# same fixture without any `config defaults` at all: ucode's parse_defaults({})
fixture_nodefaults() {
	mkdir -p "$W/$1/files/uci"
	cat > "$W/$1/files/uci/firewall.json" <<-'EOT'
		{
			"zone": [
				{
					"name": "lan",
					"input": "ACCEPT",
					"output": "ACCEPT",
					"forward": "ACCEPT",
					"network": [ "lan" ]
				}
			]
		}
	EOT
}

run_both() {
	d=$W/$1
	( cd "$SRC" && $UCODE -S -T, -L./tests/lib -L./root/usr/share/ucode \
		-D MOCK_SEARCH_PATH="[\"$d/files\", \"./tests/mocks\"]" \
		-l mocklib -l fw4 - < "$W/case.in" > "$d/uc.out" 2> "$d/uc.err" )
	echo $? > "$d/uc.rc"
	( cd "$d" && FW4_MOCK_DIRS="$d/files:$SRC/tests/mocks" FW4_TRACE= \
		"$BIN" print > "$d/rs.out" 2> "$d/rs.err" )
	echo $? > "$d/rs.rc"
	# fw4's own warnings only; drop the ucode traceback from `Reference error:` on
	sed -n '/^\(Reference\|Type\|Syntax\) error: /q;p' "$d/uc.err" > "$d/uc.warn"
	cp "$d/rs.err" "$d/rs.warn"
}

fail=0
checked=0

case_fail() {
	echo "  FAIL[$1]: $2"
	fail=$((fail + 1))
}

# $1 = case name
compare() {
	d=$W/$1
	urc=$(cat "$d/uc.rc"); rrc=$(cat "$d/rs.rc")
	echo "== $1: ucode rc=$urc stdout=$(wc -c < "$d/uc.out")B stderr=$(wc -l < "$d/uc.err")L | fw4-rs rc=$rrc stdout=$(wc -c < "$d/rs.out")B stderr=$(wc -l < "$d/rs.err")L"
	[ "$urc" = "$rrc" ] || case_fail "$1" "exit code $rrc, reference $urc"
	cmp -s "$d/uc.out" "$d/rs.out" || {
		case_fail "$1" "stdout differs"
		diff -u "$d/uc.out" "$d/rs.out" | head -20
	}
	cmp -s "$d/uc.warn" "$d/rs.warn" || {
		case_fail "$1" "warnings differ"
		diff -u "$d/uc.warn" "$d/rs.warn" | head -20
	}
	grep -q 'policy null' "$d/rs.out" && case_fail "$1" 'rendered `policy null;`'
	checked=$((checked + 1))
}

# $1 = case name -- the reference must really abort, both sides silent on stdout
expect_abort() {
	d=$W/$1
	compare "$1"
	[ "$(cat "$d/uc.rc")" = 254 ] ||
		case_fail "$1" "reference did not abort (rc $(cat "$d/uc.rc")); sentinel: firewall4 changed"
	grep -q '^Reference error: ' "$d/uc.err" ||
		case_fail "$1" "reference aborted without a ucode backtrace; sentinel: check the reference"
	[ -s "$d/uc.out" ] && case_fail "$1" "reference printed a ruleset"
	[ -s "$d/rs.out" ] && case_fail "$1" "fw4-rs printed a ruleset"
	[ -s "$d/uc.warn" ] ||
		case_fail "$1" "reference printed no option warning; sentinel: fixture is not being read"
}

# $1 = case name -- control: a real ruleset must come out of both sides
expect_ruleset() {
	d=$W/$1
	compare "$1"
	[ "$(cat "$d/uc.rc")" = 0 ] || case_fail "$1" "reference failed (rc $(cat "$d/uc.rc"))"
	grep -q 'type filter hook input priority filter; policy ' "$d/rs.out" ||
		case_fail "$1" "no input policy in the ruleset; sentinel: nothing was compared"
	[ "$(wc -l < "$d/rs.out")" -gt 50 ] ||
		case_fail "$1" "ruleset too short to be real; sentinel: nothing was compared"
}

fixture bad_policy '		"input": "ACEPT"'
fixture bad_bool   '		"drop_invalid": "notabool"'
fixture bad_list   '		"input": [ "ACCEPT", "REJECT" ]'
fixture bad_limit  '		"synflood_rate": "25/fortnight"'
fixture bad_int    '		"synflood_burst": "0x"'
fixture good       '		"input": "REJECT",
		"forward": "REJECT",
		"syn_flood": "1"'
fixture_nodefaults no_defaults

# `config include`: fw4.uc:3220 dereferences the same `false`, so an invalid
# option there aborts too -- it must not degrade to "is disabled, ignoring
# section" and keep rendering.
fixture_include inc_bad_position '"path": "/etc/x.nft", "type": "nftables", "position": "BOGUS"'
fixture_include inc_bad_type     '"path": "/etc/x.nft", "type": "yes"'
fixture_include inc_bad_bool     '"path": "/etc/x.nft", "type": "nftables", "enabled": "maybe"'
fixture_include inc_no_path      '"type": "nftables"'
# control: `enabled 0` is a real ucode "ignoring section" path, rc 0 + ruleset
fixture_include inc_disabled     '"path": "/etc/x.nft", "type": "nftables", "enabled": "0"'

for c in bad_policy bad_bool bad_list bad_limit bad_int \
	inc_bad_position inc_bad_type inc_bad_bool inc_no_path; do
	run_both "$c"
	expect_abort "$c"
done
for c in good no_defaults inc_disabled; do
	run_both "$c"
	expect_ruleset "$c"
done

echo
echo "r83 fw4 defaults: $checked cases compared, $fail failures"
[ "$fail" = 0 ] || exit 1
[ "$checked" = 12 ] || { echo "expected 12 cases, ran $checked" >&2; exit 1; }
echo "r83 fw4 defaults: PASS"

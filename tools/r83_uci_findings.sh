#!/bin/bash
# R83: differential gate for the R81 F25 uci findings.
#
# Two disposable copies of the exact device rootfs. In the candidate copy the
# uci-rs musl binary is bind-mounted over /sbin/uci (the shape
# owrt-uci-switch enable produces), so argv[0] and every script path are
# identical. The same step script then runs inside both chroots and per-step
# stdout, stderr and exit code are recorded; afterwards the whole scratch tree
# (configs, delta files, /tmp/.uci) is compared byte for byte.
#
# Every step uses `-c <dir> -t <dir>/save`. `-t` and not `-P`: `-P` sets
# CLI_FLAG_NOCOMMIT in cli.c, which makes `uci commit` a silent no-op, and
# without `-t` both sides would share /tmp/.uci and contaminate each other.
#
# Usage: sudo r83_uci_findings.sh <rootfs-files> <uci-rs-musl-binary> [workdir]
# Exit 1 on any difference.
set -u

ROOTFS=${1:?rootfs-files}
CAND=${2:?uci-rs musl binary}
WORK=${3:-/tmp/r83-uci}

[ -x "$ROOTFS/sbin/uci" ] || { echo "no $ROOTFS/sbin/uci"; exit 2; }
[ -f "$CAND" ] || { echo "no $CAND"; exit 2; }

steps=$WORK/steps.sh
rm -rf "$WORK"
mkdir -p "$WORK"

cat > "$steps" <<'STEPS'
#!/bin/sh
# Runs inside the chroot. Each step: run <id> <shell command>.
set -u
OUT=/tmp/out
S=/tmp/scratch
mkdir -p $OUT $S
run() {
	id=$1; shift
	sh -c "$*" >"$OUT/$id.out" 2>"$OUT/$id.err"
	echo "$?" > "$OUT/$id.rc"
}
# fresh config dir + private savedir for one case
mk() {
	d=$S/$1; rm -rf "$d"; mkdir -p "$d/save"; shift
	printf '%b' "$*" > "$d/t"
	echo "$d"
}
# uci with this case's confdir and savedir
u() { d=$S/$1; shift; uci -c "$d" -t "$d/save" "$@"; }

########## F25-1  anonymous section retyped
mk retype 'config device\n\toption name '\''lan'\''\n' >/dev/null
run retype_set        'uci -c /tmp/scratch/retype -t /tmp/scratch/retype/save set t.@device[0]=interface'
run retype_delta      'cat /tmp/scratch/retype/save/t'
run retype_changes    'uci -c /tmp/scratch/retype -t /tmp/scratch/retype/save changes t'
run retype_show       'uci -c /tmp/scratch/retype -t /tmp/scratch/retype/save show t'
run retype_export     'uci -c /tmp/scratch/retype -t /tmp/scratch/retype/save export t'
run retype_commit     'uci -c /tmp/scratch/retype -t /tmp/scratch/retype/save commit t'
run retype_file       'cat /tmp/scratch/retype/t'
run retype_show2      'uci -c /tmp/scratch/retype -t /tmp/scratch/retype/save show t'

mk retype_same 'config device\n\toption name '\''lan'\''\n' >/dev/null
run rsame_set     'uci -c /tmp/scratch/retype_same -t /tmp/scratch/retype_same/save set t.@device[0]=bridge'
run rsame_show    'uci -c /tmp/scratch/retype_same -t /tmp/scratch/retype_same/save show t'
run rsame_commit  'uci -c /tmp/scratch/retype_same -t /tmp/scratch/retype_same/save commit t'
run rsame_file    'cat /tmp/scratch/retype_same/t'

mk retype_named 'config device '\''foo'\''\n\toption name '\''lan'\''\n' >/dev/null
run rnamed_set    'uci -c /tmp/scratch/retype_named -t /tmp/scratch/retype_named/save set t.foo=interface'
run rnamed_commit 'uci -c /tmp/scratch/retype_named -t /tmp/scratch/retype_named/save commit t'
run rnamed_file   'cat /tmp/scratch/retype_named/t'

# retype through a truncating extended index (int cast selects section 0)
mk retype_ext 'config a\n\toption k '\''zero'\''\nconfig a\n\toption k '\''one'\''\n' >/dev/null
run rext_set   'uci -c /tmp/scratch/retype_ext -t /tmp/scratch/retype_ext/save set "t.@a[4294967296]=zz"'
run rext_show  'uci -c /tmp/scratch/retype_ext -t /tmp/scratch/retype_ext/save show t'
run rext_export 'uci -c /tmp/scratch/retype_ext -t /tmp/scratch/retype_ext/save export t'

########## F25-2  delete with an empty / blank / non-numeric index
mk del 'config rule\n\toption opt '\''v'\''\n\tlist l '\''a'\''\n\tlist l '\''b'\''\n' >/dev/null
run del_empty_str   'uci -c /tmp/scratch/del -t /tmp/scratch/del/save delete t.@rule[0].opt='
run del_show1       'uci -c /tmp/scratch/del -t /tmp/scratch/del/save show t'
run del_empty_list  'uci -c /tmp/scratch/del -t /tmp/scratch/del/save delete t.@rule[0].l='
run del_show2       'uci -c /tmp/scratch/del -t /tmp/scratch/del/save show t'
run del_delta       'cat /tmp/scratch/del/save/t'
run del_commit      'uci -c /tmp/scratch/del -t /tmp/scratch/del/save commit t'
run del_file        'cat /tmp/scratch/del/t'

for v in ' ' 'abc' '-' '+' '-x' 'x1' '  1' '0x1' '1abc' '0' '2' '2147483648' '99999999999999999999999' '-1'; do
	id=$(echo "$v" | md5sum | cut -c1-8)
	mk "delv_$id" 'config rule\n\tlist l '\''a'\''\n\tlist l '\''b'\''\n\tlist l '\''c'\''\n' >/dev/null
	run "delv_${id}_del"  "uci -c /tmp/scratch/delv_$id -t /tmp/scratch/delv_$id/save delete 't.@rule[0].l=$v'"
	run "delv_${id}_show" "uci -c /tmp/scratch/delv_$id -t /tmp/scratch/delv_$id/save show t; echo value=[$v]"
done

########## F25-3  add_list with no option part
mk addlist 'config rule\n\toption opt '\''v'\''\n' >/dev/null
run al_add     'uci -c /tmp/scratch/addlist -t /tmp/scratch/addlist/save add_list "t.@rule[0]=x"'
run al_delta   'cat /tmp/scratch/addlist/save/t'
run al_changes 'uci -c /tmp/scratch/addlist -t /tmp/scratch/addlist/save changes t'
run al_show    'uci -c /tmp/scratch/addlist -t /tmp/scratch/addlist/save show t'
run al_commit  'uci -c /tmp/scratch/addlist -t /tmp/scratch/addlist/save commit t'
run al_file    'cat /tmp/scratch/addlist/t'
run al_delta2  'cat /tmp/scratch/addlist/save/t'
run al_batch   'printf "add_list t.@rule[0]=x\nshow t\nexport t\n" | uci -c /tmp/scratch/addlist -t /tmp/scratch/addlist/save batch'
# the ordinary form, for contrast
mk addlist_opt 'config rule\n\toption opt '\''v'\''\n' >/dev/null
run alo_add   'uci -c /tmp/scratch/addlist_opt -t /tmp/scratch/addlist_opt/save add_list "t.@rule[0].opt=x"'
run alo_delta 'cat /tmp/scratch/addlist_opt/save/t'
run alo_show  'uci -c /tmp/scratch/addlist_opt -t /tmp/scratch/addlist_opt/save show t'

########## rename to a name that is not UTF-8
mk ren 'config a s\n' >/dev/null
run ren_do      'uci -c /tmp/scratch/ren -t /tmp/scratch/ren/save rename "$(printf '"'"'t.s=\377\376'"'"')"'
run ren_delta   'wc -c < /tmp/scratch/ren/save/t; md5sum < /tmp/scratch/ren/save/t'
run ren_changes 'uci -c /tmp/scratch/ren -t /tmp/scratch/ren/save changes t'
run ren_show    'uci -c /tmp/scratch/ren -t /tmp/scratch/ren/save show t'
run ren_commit  'uci -c /tmp/scratch/ren -t /tmp/scratch/ren/save commit t'
run ren_file    'cat /tmp/scratch/ren/t'
mk ren_ok 'config a s\n' >/dev/null
run renok_do    'uci -c /tmp/scratch/ren_ok -t /tmp/scratch/ren_ok/save rename t.s=zz'
run renok_delta 'cat /tmp/scratch/ren_ok/save/t'

########## tuples that are not UTF-8 / extended index table
mk tuple 'config a s\n\toption o v\n' >/dev/null
run tup_pkg  'uci -c /tmp/scratch/tuple -t /tmp/scratch/tuple/save get "$(printf '"'"'t\377.s'"'"')"'
run tup_opt  'uci -c /tmp/scratch/tuple -t /tmp/scratch/tuple/save get "$(printf '"'"'t.s.o\377'"'"')"'
run tup_sec  'uci -c /tmp/scratch/tuple -t /tmp/scratch/tuple/save get "$(printf '"'"'t.\377.o'"'"')"'
run tup_4    'uci -c /tmp/scratch/tuple -t /tmp/scratch/tuple/save get "$(printf '"'"'t\377.s.o.x'"'"')"'
run tup_val  'uci -c /tmp/scratch/tuple -t /tmp/scratch/tuple/save set "$(printf '"'"'t.s.o=\377\376'"'"')" && cat /tmp/scratch/tuple/save/t | md5sum'
run tup_ctl  'uci -c /tmp/scratch/tuple -t /tmp/scratch/tuple/save set "$(printf '"'"'t.s.o=\001'"'"')"'

mk ext 'config a\n\toption k '\''zero'\''\nconfig a\n\toption k '\''one'\''\nconfig a\n\toption k '\''two'\''\n' >/dev/null
for i in '' ' ' '0' '1' '2' '3' '-1' '-3' '-4' ' 1' '1 ' '+1' '-' '+' '0x1' '1abc' '4294967296' '4294967297' \
         '99999999999999999999999' '-99999999999999999999999' '-4294967296' '-4294967295' '2147483647' '2147483648'; do
	id=$(echo "idx$i" | md5sum | cut -c1-8)
	run "ext_$id" "uci -c /tmp/scratch/ext -t /tmp/scratch/ext/save get 't.@a[$i].k'; echo idx=[$i]"
done

# the C locale's isspace() set in front of the index (strtol), including the
# vertical tab, which Rust's is_ascii_whitespace leaves out
for e in 011 012 013 014 015 040; do
	run "extws_$e" "uci -c /tmp/scratch/ext -t /tmp/scratch/ext/save get \"t.@a[\$(printf '\\$e')1].k\"; echo esc=$e"
done

########## batch error text (the ` (reason) at line N, byte B` suffix)
mk batch 'config rule\n' >/dev/null
run b_parse    'printf "set t.x.y.z=1\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_two      'printf "set t.x.y.z=1\nset t.a.b.c=2\nget t.nosuch.o\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_mixed    'printf "set t.x.y.z=1\nset t.@rule[0].a\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_quote    'printf "set '"'"'t.a.b=1\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_args     'printf "set a b c d e f\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_unknown  'printf "bogus t.x.y\nset\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_notfound 'printf "get t.nosuch.o\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_exit     'printf "get t.@rule[0]\nexit\nget t.x.y.z\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_nonbatch 'uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save set t.x.y.z=1'
# the batch parse context, and therefore the line counter in the message,
# survives across commands until one of them parses a file
run b_lines    'printf "set t.x.y.z=1\nset t.a.b.c=2\nset t.d.e.f=3\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_blanks   'printf "set t.x.y.z=1\n\n\nset t.a.b.c=2\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_afterload 'printf "get t.@rule[0]\nset t.x.y.z=1\nset t.a.b.c=2\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_afterfail 'printf "changes t\nset t.x.y.z=1\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_afternf  'printf "get t.nosuch.o\nset t.x.y.z=1\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_import   'printf "config a\n\toption o '"'"'unterminated\n" > /tmp/scratch/batch/u; uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save show u'
run b_afterimport 'printf "show u\nset t.x.y.z=1\n" | uci -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'
run b_afterimportS 'printf "show u\nset t.x.y.z=1\n" | uci -S -c /tmp/scratch/batch -t /tmp/scratch/batch/save batch'

########## NUL inside a long line
nulcase() { # <id> <n_a> <n_b>
	d=$S/nul_$1; rm -rf "$d"; mkdir -p "$d/save"
	{ printf 'config a\n\toption o '\'''
	  i=0; while [ $i -lt $2 ]; do printf a; i=$((i+1)); done
	  printf '\000'
	  i=0; while [ $i -lt $3 ]; do printf b; i=$((i+1)); done
	  printf "'\nconfig other\n"; } > "$d/t"
	run "nul_$1_show"  "uci -c $d -t $d/save show t"
	run "nul_$1_get"   "uci -c $d -t $d/save get t.@a[0].o | tr -d '\n' | wc -c"
	run "nul_$1_export" "uci -c $d -t $d/save export t"
}
nulcase a 40 30
nulcase b 100 100
nulcase c 5 5
nulcase d 0 0
nulcase e 1 200
nulcase f 200 1
nulcase g 30 30
nulcase h 31 31
nulcase i 62 62
nulcase j 63 63
d=$S/nul_start; rm -rf $d; mkdir -p $d/save
printf 'config a\n\000option o '\''v'\''\nconfig b\n' > $d/t
run nul_start_show 'uci -c /tmp/scratch/nul_start -t /tmp/scratch/nul_start/save show t'
d=$S/nul_multi; rm -rf $d; mkdir -p $d/save
printf 'config a\n\toption o '\''1\0002\0003'\''\nconfig b\n' > $d/t
run nul_multi_show 'uci -c /tmp/scratch/nul_multi -t /tmp/scratch/nul_multi/save show t'

########## import / commit volume (also exercises the buffered write path)
d=$S/bulk; rm -rf $d; mkdir -p $d/save
{ echo 'config s big'; i=0; while [ $i -lt 500 ]; do echo "	option o$i 'v$i'"; i=$((i+1)); done; } > $d/t
run bulk_show   'uci -c /tmp/scratch/bulk -t /tmp/scratch/bulk/save show t | md5sum'
run bulk_set    'i=0; while [ $i -lt 50 ]; do uci -c /tmp/scratch/bulk -t /tmp/scratch/bulk/save set "t.big.o$i=w$i"; i=$((i+1)); done'
run bulk_delta  'md5sum < /tmp/scratch/bulk/save/t; wc -c < /tmp/scratch/bulk/save/t'
run bulk_commit 'uci -c /tmp/scratch/bulk -t /tmp/scratch/bulk/save commit t'
run bulk_file   'md5sum < /tmp/scratch/bulk/t; wc -c < /tmp/scratch/bulk/t'

########## the real device configs, read only
for pkg in dhcp firewall network system; do
	[ -f /etc/config/$pkg ] || continue
	run "dev_show_$pkg"   "uci show $pkg"
	run "dev_export_$pkg" "uci export $pkg"
done
STEPS

side() { # <name> <extra>
	local name=$1 root=$WORK/$1
	mkdir -p "$root"
	cp -a "$ROOTFS/." "$root/"
	mkdir -p "$root/proc" "$root/dev" "$root/tmp"
	cp "$steps" "$root/tmp/steps.sh"
	chmod 755 "$root/tmp/steps.sh"
	if [ "$name" = rs ]; then
		cp "$CAND" "$root/tmp/uci-rs"
		chmod 755 "$root/tmp/uci-rs"
	fi
	mount -t proc proc "$root/proc" || return 1
	mount -t tmpfs tmpfs "$root/dev" || return 1
	mknod -m 666 "$root/dev/null" c 1 3
	mknod -m 666 "$root/dev/zero" c 1 5
	mknod -m 666 "$root/dev/urandom" c 1 9
	if [ "$name" = rs ]; then
		mount --bind "$root/tmp/uci-rs" "$root/sbin/uci" || return 1
	fi
	chroot "$root" /bin/sh /tmp/steps.sh >"$WORK/$name.log" 2>&1
	local rc=$?
	umount "$root/sbin/uci" 2>/dev/null
	umount "$root/dev" 2>/dev/null
	umount "$root/proc" 2>/dev/null
	return $rc
}

mount --make-rprivate / 2>/dev/null
side c || echo "warning: C side chroot returned $?"
side rs || echo "warning: candidate chroot returned $?"

echo "== implementation probe"
echo "  C     $(wc -c < "$ROOTFS/sbin/uci") bytes  $(md5sum < "$ROOTFS/sbin/uci" | cut -d' ' -f1)"
echo "  cand  $(wc -c < "$CAND") bytes  $(md5sum < "$CAND" | cut -d' ' -f1)"

fail=0
compared=0
for tree in out scratch; do
	if [ ! -d "$WORK/c/tmp/$tree" ] || [ ! -d "$WORK/rs/tmp/$tree" ]; then
		echo "MISSING /tmp/$tree on one side"
		fail=1
		continue
	fi
	n=$(find "$WORK/c/tmp/$tree" -type f | wc -l)
	compared=$((compared + n))
	if ! diff -r "$WORK/c/tmp/$tree" "$WORK/rs/tmp/$tree" > "$WORK/$tree.diff" 2>&1; then
		echo "DIFF /tmp/$tree  ($n files on the C side)"
		sed -n 1,200p "$WORK/$tree.diff"
		fail=1
	else
		echo "identical /tmp/$tree  ($n files)"
	fi
done

# a green run has to have compared something
if [ "$compared" -lt 200 ]; then
	echo "FAIL: only $compared files compared, the step script did not run"
	exit 1
fi
# and both sides must have produced the retype evidence at all
for f in out/retype_show.out out/al_delta.out out/nul_a_get.out; do
	for s in c rs; do
		[ -s "$WORK/$s/tmp/$f" ] || { echo "FAIL: $s/$f empty"; fail=1; }
	done
done

if [ $fail -ne 0 ]; then
	echo "R83 FAIL (see $WORK/*.diff)"
	exit 1
fi
echo "R83 PASS ($compared files compared)"

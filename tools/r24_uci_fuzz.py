#!/usr/bin/env python3
"""Differential fuzzing of uci-rs against the exact rootfs' /sbin/uci.

Seeds are the rootfs' own /etc/config files. Each case is a byte-level mutation
of one seed (non-UTF-8 bytes, odd whitespace, quoting, escapes, long tokens,
truncated lines, duplicated sections) plus a `set` with a mutated value. Both
implementations run the same step list on their own copy of the case directory
inside ONE copy of the rootfs (qemu-user chroot, like r19); every rc/stdout/
stderr and the committed file bytes must be identical.

Usage: r24_uci_fuzz.py <rootfs-files> <uci-rs-musl-binary> [--cases N] [--seed S] [--keep DIR]
Exit code 1 when any case differs. Differing cases are written to --keep.
"""
import os
import random
import re
import subprocess
import sys
import tempfile

WEIRD = [b"\xe9", b"\xff\xfe", b"\xc3\x28", b"\xf0\x9f\x98\x80", b"\x80", b"\t", b"\r", b"\\", b"'", b'"',
         b"\\'", b" ", b"#", b";", b"$", b"`", b"\x7f", b"\xed\xa0\x80", b"\xc0\xaf"]


def mutate(data: bytes, rng: random.Random) -> bytes:
    lines = data.split(b"\n")
    ops = rng.randint(1, 4)
    for _ in range(ops):
        kind = rng.randint(0, 11)
        if not lines:
            lines = [b"config foo 'bar'"]
        i = rng.randrange(len(lines))
        line = lines[i]
        if kind == 0 and line:            # insert weird bytes inside a token
            p = rng.randrange(len(line) + 1)
            lines[i] = line[:p] + rng.choice(WEIRD) + line[p:]
        elif kind == 1:                   # duplicate a line
            lines.insert(i, line)
        elif kind == 2 and line:          # truncate a line
            lines[i] = line[: rng.randrange(len(line))]
        elif kind == 3:                   # very long value
            lines[i] = b"\toption longval '" + b"x" * rng.choice([250, 1000, 5000]) + b"'"
        elif kind == 4:                   # unterminated quote
            lines[i] = b"\toption broken 'abc"
        elif kind == 5:                   # list with weird bytes
            lines[i] = b"\tlist l '" + rng.choice(WEIRD) + b"v'"
        elif kind == 6:                   # section without name / with weird name
            lines[i] = rng.choice([b"config zone", b"config 'zone' name-with-dash", b"config zone '" + rng.choice(WEIRD) + b"'", b"config"])
        elif kind == 7:                   # option without value / odd spacing
            lines[i] = rng.choice([b"\toption novalue", b"option  spaced   'v'", b"\t\toption tabs\t'v'", b"option x 'a' 'b'"])
        elif kind == 8:                   # comment / blank / garbage
            lines[i] = rng.choice([b"# comment", b"", b"garbage line here", b"package other", b"\toption x 'va\\lue'"])
        elif kind == 9 and line:          # swap two bytes
            b = bytearray(line); a, c = rng.randrange(len(b)), rng.randrange(len(b)); b[a], b[c] = b[c], b[a]; lines[i] = bytes(b)
        elif kind == 10:                  # unquoted value with special chars
            lines[i] = b"\toption raw " + rng.choice([b"a=b", b"a.b", b"1 2", b"'", b"\"q\"", b"x\\y"])
        else:                             # CRLF line ending
            lines[i] = line + b"\r"
    return b"\n".join(lines)


def build_cases(seeds, n, rng):
    cases = []
    for k in range(n):
        name, data = rng.choice(seeds)
        pkg = f"fz{k:04d}"
        text = mutate(data, rng)
        setval = rng.choice([b"plain", b"caf\xe9", b"\xff\xfe\xfd", b"with space", b"quo'te", b"back\\slash", b"tab\there",
                             b"x" * 300, b"\xf0\x9f\x98\x80", b"", b"new\nline"])
        cases.append((pkg, text, setval))
    return cases


def steps_for(impl, pkg, setval):
    d = f"/tmp/fz/{impl}"
    # private savedir per implementation: the default /tmp/.uci would leak one side's pending delta into the other
    u = ("/tmp/uci-rs" if impl == "candidate" else "/sbin/uci") + f" -P {d}/.uci"
    sv = setval.decode("latin-1").replace("\\", "\\\\").replace("'", "'\\''")
    return [
        f"{u} -c {d} export {pkg}",
        f"{u} -c {d} show {pkg}",
        f"{u} -c {d} -q get {pkg}.@*[0]",
        f"{u} -c {d} -q show {pkg}.@*[0]",
        f"{u} -c {d} set {pkg}.fuzzsec=fuzz && {u} -c {d} set \"{pkg}.fuzzsec.opt=$(printf '%s' '{sv}')\" && {u} -c {d} add_list \"{pkg}.fuzzsec.l=$(printf '%s' '{sv}')\" && {u} -c {d} changes {pkg} && {u} -c {d} commit {pkg}",
        f"cat {d}/{pkg}; echo; sha256sum {d}/{pkg} | cut -d' ' -f1",
        f"{u} -c {d} export {pkg}",
    ]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    n = int(sys.argv[sys.argv.index("--cases") + 1]) if "--cases" in sys.argv else 200
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 1
    keep = sys.argv[sys.argv.index("--keep") + 1] if "--keep" in sys.argv else None
    for opt in ("--cases", "--seed", "--keep"):
        if opt in sys.argv:
            v = sys.argv[sys.argv.index(opt) + 1]
            if v in args:
                args.remove(v)
    rootfs, binary = args[0], args[1]
    rng = random.Random(seed)
    seeds = []
    cfgdir = os.path.join(rootfs, "etc/config")
    for name in sorted(os.listdir(cfgdir)):
        p = os.path.join(cfgdir, name)
        if os.path.isfile(p):
            seeds.append((name, open(p, "rb").read()))
    cases = build_cases(seeds, n, rng)

    tmp = tempfile.mkdtemp(prefix="r24-")
    try:
        root = os.path.join(tmp, "root")
        subprocess.run(["sudo", "-n", "cp", "-a", rootfs, root], check=True)
        subprocess.run(["sudo", "-n", "cp", binary, os.path.join(root, "tmp/uci-rs")], check=True)
        subprocess.run(["sudo", "-n", "chmod", "755", os.path.join(root, "tmp/uci-rs")], check=True)
        stage = os.path.join(tmp, "fz")
        for impl in ("original", "candidate"):
            os.makedirs(os.path.join(stage, impl))
            for pkg, text, _ in cases:
                with open(os.path.join(stage, impl, pkg), "wb") as f:
                    f.write(text)
        script = ["#!/bin/sh", "mkdir -p /tmp/out", "cd /"]
        for pkg, _, setval in cases:
            for impl in ("original", "candidate"):
                for j, cmd in enumerate(steps_for(impl, pkg, setval)):
                    script.append(f"( {cmd} ) >/tmp/out/{pkg}.{j}.{impl}.out 2>/tmp/out/{pkg}.{j}.{impl}.err; echo $? >/tmp/out/{pkg}.{j}.{impl}.rc")
        sp = os.path.join(tmp, "steps.sh")
        # latin-1: every str char in the script is exactly the byte it stands for
        with open(sp, "wb") as f:
            f.write(("\n".join(script) + "\n").encode("latin-1"))
        subprocess.run(["sudo", "-n", "cp", "-a", stage, os.path.join(root, "tmp/fz")], check=True)
        subprocess.run(["sudo", "-n", "cp", sp, os.path.join(root, "tmp/steps.sh")], check=True)
        scenario = (
            "root=$1; mount -t tmpfs none $root/dev && mknod $root/dev/null c 1 3 && chmod 666 $root/dev/null; "
            "chroot $root /bin/sh /tmp/steps.sh"
        )
        subprocess.run(["sudo", "-n", "setsid", "-w", "unshare", "--mount", "--fork", "/bin/sh", "-c", scenario, "sh", root], check=True)
        outdir = os.path.join(root, "tmp/out")
        files = subprocess.run(["sudo", "-n", "ls", outdir], capture_output=True, text=True).stdout.split()
        data = {}
        for name in files:
            data[name] = subprocess.run(["sudo", "-n", "cat", os.path.join(outdir, name)], capture_output=True).stdout

        bad = 0
        for pkg, text, setval in cases:
            diffs = []
            for j in range(7):
                for ext in ("rc", "out", "err"):
                    o = data.get(f"{pkg}.{j}.original.{ext}", b"")
                    c = data.get(f"{pkg}.{j}.candidate.{ext}", b"")
                    # argv[0] differs between the binaries
                    o2 = re.sub(rb"steps.sh: line \d+:", b"steps.sh:", o.replace(b"/sbin/uci", b"uci")); c2 = re.sub(rb"steps.sh: line \d+:", b"steps.sh:", c.replace(b"/tmp/uci-rs", b"uci"))
                    if o2 != c2:
                        # show the first differing region, not just the head
                        k = 0
                        while k < min(len(o2), len(c2)) and o2[k] == c2[k]:
                            k += 1
                        lo = max(0, k - 60)
                        diffs.append((j, ext, o2[lo:k + 160], c2[lo:k + 160]))
            if diffs:
                bad += 1
                print(f"DIFF {pkg} set={setval!r}")
                for j, ext, o, c in diffs[:4]:
                    print(f"   step{j}.{ext}: orig={o!r}\n              cand={c!r}")
                if keep:
                    os.makedirs(keep, exist_ok=True)
                    with open(os.path.join(keep, pkg), "wb") as f:
                        f.write(text)
                    with open(os.path.join(keep, pkg + ".setval"), "wb") as f:
                        f.write(setval)
        print(f"cases={len(cases)} differing={bad}")
        return 1 if bad else 0
    finally:
        subprocess.run(["sudo", "-n", "rm", "-rf", tmp], check=False)


if __name__ == "__main__":
    sys.exit(main())

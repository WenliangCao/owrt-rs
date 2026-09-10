#!/usr/bin/env python3
"""Run the upstream firewall4 test suite against fw4-rs.

Usage: r09_fw4_check.py <firewall4-src-dir> <fw4-rs-binary> [test-file ...]

Each `tests/NN_*/MM_*` file is split exactly like upstream run_tests.sh; every
testcase runs fw4-rs with FW4_MOCK_DIRS=<per-test files dir>:<tests/mocks>,
the action taken from the testcase's getenv() switch, and stdout/stderr are
compared byte for byte with the expectations."""
import os, re, subprocess, sys, tempfile, difflib

def sections(text):
    out = []  # (tag, name, body)
    tag = None; name = None; buf = []
    for line in text.split("\n"):
        if line == "-- Testcase --":
            tag, name, buf = "test", None, []
        elif line == "-- Environment --":
            tag, name, buf = "env", None, []
        elif line in ("-- Expect stdout --", "-- Expect stderr --", "-- Expect exitcode --"):
            tag, name, buf = line[len("-- Expect "):-len(" --")], None, []
        elif line.startswith("-- File ") and line.endswith(" --"):
            tag, name, buf = "file", line[len("-- File "):-len(" --")].strip(), []
        elif line == "-- End --":
            if tag:
                out.append((tag, name, "\n".join(buf) + ("\n" if buf else "")))
            tag = None
        elif tag is not None:
            buf.append(line)
    return out

def run_file(src, binary, path):
    text = open(path).read()
    secs = sections(text)
    tmp = tempfile.mkdtemp(prefix="fw4rs.")
    files = os.path.join(tmp, "files")
    for tag, name, body in secs:
        if tag == "file":
            p = os.path.join(files, name)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write(body)
    cases = []
    cur = None
    for tag, name, body in secs:
        if tag == "test":
            cur = {"in": body, "stdout": "", "stderr": "", "code": None}
            cases.append(cur)
        elif tag in ("stdout", "stderr") and cur is not None:
            cur[tag] = body
        elif tag == "exitcode" and cur is not None:
            cur["code"] = int(body.strip() or 0)
    failed = 0
    for i, c in enumerate(cases, 1):
        m = re.search(r"case 'ACTION':\s*return '([a-z-]+)'", c["in"])
        action = m.group(1) if m else "print"
        env = dict(os.environ)
        env["FW4_MOCK_DIRS"] = files + ":" + os.path.join(src, "tests", "mocks")
        env["FW4_TRACE"] = "stderr" if "TRACE_CALLS" in c["in"] else ""
        argv = [binary, action]
        for var, flag in (("OBJECT", None), ("DEVICE", None)):
            mm = re.search(r"case '%s':\s*return '([^']*)'" % var, c["in"])
            if mm:
                argv.append(mm.group(1))
        r = subprocess.run(argv, env=env, capture_output=True, text=True, cwd=tmp)
        ok = True
        if r.stderr != c["stderr"]:
            ok = False
            print("Testcase #%d of %s: stderr differs" % (i, path))
            sys.stdout.writelines(difflib.unified_diff(c["stderr"].splitlines(True), r.stderr.splitlines(True), "expected", "fw4-rs"))
        if r.stdout != c["stdout"]:
            ok = False
            print("Testcase #%d of %s: stdout differs" % (i, path))
            sys.stdout.writelines(difflib.unified_diff(c["stdout"].splitlines(True), r.stdout.splitlines(True), "expected", "fw4-rs"))
        if c["code"] is not None and r.returncode != c["code"]:
            ok = False
            print("Testcase #%d of %s: exit code %d, expected %d" % (i, path, r.returncode, c["code"]))
        if not ok:
            failed += 1
    return len(cases), failed

def main():
    src, binary = sys.argv[1], sys.argv[2]
    selected = sys.argv[3:]
    tests = []
    for cat in sorted(os.listdir(os.path.join(src, "tests"))):
        if not re.match(r"\d\d_", cat):
            continue
        for f in sorted(os.listdir(os.path.join(src, "tests", cat))):
            if re.match(r"\d\d_", f):
                tests.append(os.path.join(src, "tests", cat, f))
    if selected:
        tests = [t for t in tests if any(t.endswith(s) for s in selected)]
    total = fails = 0
    for t in tests:
        n, f = run_file(src, binary, t)
        total += n; fails += f
        print("%-40s %s" % (os.path.basename(t), "OK" if f == 0 else "FAILED (%d/%d)" % (f, n)))
    print("\nRan %d testcases in %d files, %d failures" % (total, len(tests), fails))
    sys.exit(1 if fails else (0 if total else 2))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Linux Rust gates; compile as the caller and isolate privileged test executables."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
COMPONENTS = (
    "platform", "ubus", "uci", "reload-config", "logd", "httpd", "fw4",
    "rpcd", "ubusd", "netifd", "procd", "dnsmasq/platform", "dnsmasq", "odhcpd",
)
# These ignored tests require only the namespace supplied by our runner. The
# remaining ignored tests require an independently built exact-C oracle/corpus.
DNS_NAMESPACE_PREFIXES = (
    "net::", "interfaces::", "interfaces_ipv4::", "listeners::",
    "tftp_listener::", "dhcp::service::", "tftp_admission_tests::",
    "tests::dns_listener_factories_preserve_bound_ipv4_policy_on_rebind",
)


def linux_only():
    if platform.system() != "Linux":
        raise RuntimeError("Rust gates require Linux; use ssh oracle or CI, not a Mac build")


def run_test(arguments):
    """Cargo runner: only the already-built ELF crosses the sudo boundary."""
    linux_only()
    if not arguments or not Path(arguments[0]).is_file():
        raise RuntimeError("Cargo runner requires a built test executable")
    temporary = tempfile.mkdtemp(prefix="owrt-rust-test-")
    try:
        command = [
            "sudo", "-n", "env", f"TMPDIR={temporary}",
            "sh", str(ROOT / "tools/dnsmasq/run_isolated.sh"), *arguments,
        ]
        return subprocess.run(command, cwd=ROOT).returncode
    finally:
        # Tests can create root-owned mode-0700 fixtures. The parent owns this
        # freshly generated directory; never clean caller-supplied paths here.
        subprocess.run(["sudo", "-n", "rm", "-rf", "--", temporary], check=True)


def configuration(manifest):
    text = manifest.read_text()
    features = bool(re.search(r"^\[features\]$", text, re.M))
    library = re.search(r"^\[lib\]\n(.*?)(?=^\[|\Z)", text, re.M | re.S)
    docs = (manifest.parent / "src/lib.rs").is_file() and not (
        library and re.search(r"^doctest\s*=\s*false\s*$", library[1], re.M)
    )
    return features, docs


def runner_config(host):
    # A TOML array preserves spaces in the checkout path; no shell evaluation.
    runner = [sys.executable, str(Path(__file__).resolve()), "run-test"]
    return ["--config", f"target.{host}.runner={json.dumps(runner)}"]


def commands(mode, manifest, host):
    features, docs = configuration(manifest)
    base = ["--locked", "--manifest-path", str(manifest), "--target", host]
    feature_sets = [([], "default")]
    if features:
        feature_sets.append((["--all-features"], "all-features"))
    isolated = manifest.parent.name in ("dnsmasq", "procd")
    runner = runner_config(host) if isolated else []
    if mode == "fmt-check":
        yield "fmt", ["mbx", "fmt", "--manifest-path", str(manifest), "--check"]
    elif mode == "build":
        yield "build", ["mbx", "build", *base, "--release"]
    elif mode == "check":
        for flags, label in feature_sets:
            yield f"check-{label}", ["mbx", "check", *base, *flags, "--all-targets"]
            yield f"clippy-{label}", ["mbx", "clippy", *base, *flags, "--all-targets", "--", "-D", "warnings"]
            if any((manifest.parent / "examples").glob("*.rs")):
                yield f"examples-{label}", ["mbx", "check", *base, *flags, "--examples"]
    else:
        for flags, label in feature_sets:
            yield f"test-{label}", [
                "mbx", "test", *base, *flags, *runner, "--all-targets",
                "--", "--test-threads=1",
            ]
        if docs:
            flags = ["--all-features"] if features else []
            yield "doc", ["mbx", "test", *base, *flags, "--doc"]


def execute(command, log, env):
    print("+ " + " ".join(command), flush=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as stream:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        print("\n".join(log.read_text(errors="replace").splitlines()[-60:]), file=sys.stderr)
        raise subprocess.CalledProcessError(result.returncode, command)


def namespace_tests(manifest, host, output, env):
    # Run each ignored namespace case in its own new namespace: some cases
    # deliberately leave loopback aliases or process limits changed.
    for target in (["--lib"], ["--bin", "dnsmasq-rs"]):
        label = "lib" if target == ["--lib"] else "bin"
        base = ["mbx", "test", "--locked", "--manifest-path", str(manifest), "--target", host,
                "--all-features", *runner_config(host), *target]
        listing = output / f"dnsmasq-ignored-{label}.log"
        execute([*base, "--", "--ignored", "--list"], listing, env)
        names = [line.removesuffix(": test") for line in listing.read_text().splitlines()
                 if line.endswith(": test")]
        for index, name in enumerate(names):
            if not name.startswith(DNS_NAMESPACE_PREFIXES):
                print(f"requires separate oracle/corpus: {name}", flush=True)
                continue
            execute([*base, name, "--", "--exact", "--ignored", "--test-threads=1"],
                    output / f"dnsmasq-namespace-{label}-{index}.log", env)


def main(arguments):
    if arguments and arguments[0] == "run-test":
        return run_test(arguments[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("test", "check", "build", "fmt-check"))
    parser.add_argument("--benchmark", action="store_true", help="check only tools/benchmark")
    parser.add_argument("--output", type=Path, default=ROOT / "work/out/rust-host")
    args = parser.parse_args(arguments)
    linux_only()
    if os.geteuid() == 0:
        raise RuntimeError("run Rust gates as an ordinary user; only the test runner uses sudo")
    if shutil.which("mbx") is None:
        raise RuntimeError("mbx is required; CI installs the pinned verified release")
    host = subprocess.check_output(["rustc", "-vV"], text=True).split("host: ", 1)[1].splitlines()[0]
    env = os.environ.copy()
    env["CARGO_INCREMENTAL"] = "0"
    for key in ("RUSTFLAGS", "RUSTDOCFLAGS"):
        env[key] = (env.get(key, "") + " -Dwarnings").strip()
    manifests = [ROOT / "tools/benchmark/Cargo.toml"] if args.benchmark else [
        ROOT / "components" / name / "Cargo.toml" for name in COMPONENTS
    ]
    if args.mode == "fmt-check" and not args.benchmark:
        manifests.append(ROOT / "tools/benchmark/Cargo.toml")
    for manifest in manifests:
        name = "benchmark" if args.benchmark else manifest.parent.relative_to(ROOT).as_posix().replace("/", "-")
        for step, command in commands(args.mode, manifest, host):
            execute(command, args.output / f"{name}-{step}.log", env)
        if args.mode == "test" and manifest.parent == ROOT / "components/dnsmasq":
            namespace_tests(manifest, host, args.output, env)
    print(f"Rust {args.mode}: passed ({len(manifests)} crates)", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"rust-check: {error}", file=sys.stderr)
        raise SystemExit(1)

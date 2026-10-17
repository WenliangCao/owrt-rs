#!/usr/bin/env python3
"""Host tests and real-SDK builds for the nine non-dnsmasq candidates.

Uses the existing package/core recipes. This workflow neither constructs the
native ten-component release nor changes dnsmasq's identity/qualification gate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

from dnsmasq.compiler_warnings import scan

REPO = Path(__file__).resolve().parent.parent
COMPONENTS = ("platform", "ubus", "uci", "reload-config", "logd", "httpd", "fw4", "rpcd", "ubusd", "netifd", "procd")
COMMON = {"platform", "ubus", "uci"}
LINK_FLAGS = "-Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs"


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def warnings(output, logs):
    result = scan([path for path in logs if path.is_file()])
    write(output, result)
    print(f"compiler/unclassified warnings: {len(result['compiler_or_unclassified'])}; "
          f"SDK metadata warnings: {len(result['sdk_metadata'])}", flush=True)
    return result


def run(command, log, env):
    print("+ " + " ".join(map(str, command)), flush=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as stream:
        completed = subprocess.run(list(map(str, command)), cwd=REPO, env=env,
                                   stdout=stream, stderr=subprocess.STDOUT)
    if completed.returncode:
        print("\n".join(log.read_text(errors="replace").splitlines()[-40:]), flush=True)
    return completed.returncode


def environment():
    env = os.environ.copy()
    for key in ("RUSTFLAGS", "RUSTDOCFLAGS"):
        env[key] = (env.get(key, "") + " -Dwarnings").strip()
    env["CARGO_INCREMENTAL"] = "0"
    return env


def host(work, env, report):
    out = work / "out/core-host"
    out.mkdir(parents=True, exist_ok=True)
    for component in COMPONENTS:
        crate = REPO / "components" / component
        manifest = crate / "Cargo.toml"
        common = ["cargo", "test", "--locked", "--manifest-path", manifest]
        # --tests retains the normal lib/bin/integration test targets. Turning
        # examples which include src modules into extra libtest roots would
        # duplicate their tests in an unsupported crate-root environment.
        compile_code = run(common + ["--tests", "--no-run"], out / f"build-{component}.log", env)
        test_code = doc_code = example_code = None
        if compile_code == 0:
            options = ["--", "--test-threads=1"] if component == "platform" else []
            test_code = run(common + ["--tests", "--no-fail-fast"] + options, out / f"test-{component}.log", env)
            if (crate / "src/lib.rs").is_file():
                doc_code = run(common + ["--doc"], out / f"doc-{component}.log", env)
        if any((crate / "examples").glob("*.rs")):
            example_code = run(["cargo", "check", "--locked", "--examples", "--manifest-path", manifest],
                               out / f"examples-{component}.log", env)
        report["commands"].append({"component": component, "compile": compile_code,
                                   "test": test_code, "doc": doc_code, "examples": example_code})
        if component in COMMON and (compile_code or test_code or doc_code):
            break
    return out, len(report["commands"]) == len(COMPONENTS) and all(
        row["compile"] == 0 and row["test"] == 0 and row["doc"] in (0, None)
        and row["examples"] in (0, None) for row in report["commands"])


def sdk_check(work, env, report):
    out = work / "out"
    out.mkdir(parents=True, exist_ok=True)
    for script in ("ci_build_image.sh", "ci_build_core.sh"):
        code = run(["sh", REPO / "tools" / script, work], out / f"driver-{script}.txt", env)
        report["commands"].append({"recipe": script, "returncode": code})
        if code:
            return out, False
    version = env["OPENWRT_VERSION"]
    staging, = work.glob(f"openwrt-sdk-{version}-*/staging_dir")
    linker, = staging.glob("toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc")
    check_env = env.copy()
    check_env.update({
        "CARGO_BUILD_TARGET": "aarch64-unknown-linux-musl",
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": str(linker),
        "CC_aarch64_unknown_linux_musl": str(linker),
        "AR_aarch64_unknown_linux_musl": str(linker.with_name(linker.name[:-3] + "ar")),
        "STAGING_DIR": str(staging),
        "RUSTFLAGS": env["RUSTFLAGS"] + " " + LINK_FLAGS,
    })
    # Shipped release ELFs above use the unchanged fixed SDK/core source slots.
    # Also compile business tests and normal examples for the router architecture; these
    # check-only products cannot be substituted for those release artifacts.
    for component in COMPONENTS:
        code = run(["cargo", "check", "--locked", "--tests", "--manifest-path",
                    REPO / "components" / component / "Cargo.toml", "--target-dir", work / "target-check"],
                   out / f"check-target-{component}.log", check_env)
        report["commands"].append({"target_check": component, "returncode": code})
        if code and component in COMMON:
            return out, False
        crate = REPO / "components" / component
        if any((crate / "examples").glob("*.rs")):
            example_code = run(["cargo", "check", "--locked", "--examples", "--manifest-path",
                                crate / "Cargo.toml", "--target-dir", work / "target-check"],
                               out / f"check-examples-{component}.log", check_env)
            report["commands"].append({"target_examples": component, "returncode": example_code})
    if any(row.get("returncode", 0) for row in report["commands"]):
        return out, False
    candidates = out / "core-candidates"
    candidates.mkdir(exist_ok=True)
    hashes = {}
    for filename, source in (("binary-sha256.txt", work / "verify/rootfs/usr/sbin"),
                             ("core-binary-sha256.txt", out / "core-binaries")):
        for line in (out / filename).read_text().splitlines():
            expected, name = line.split()
            binary = source / name
            actual = hashlib.sha256(binary.read_bytes()).hexdigest()
            if actual != expected or name in hashes:
                raise ValueError(f"candidate identity mismatch: {name}")
            shutil.copy2(binary, candidates / name)
            hashes[name] = actual
    if set(hashes) != {"uci-rs", "reload_config_rs", "logd-rs", "httpd-rs", "fw4-rs",
                       "rpcd-rs", "ubusd-rs", "netifd-rs", "procd-rs"}:
        raise ValueError("expected all nine actual recipe outputs")
    report["binary_sha256"] = hashes
    return out, True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("host", "target"):
        sub.add_parser(mode).add_argument("work", type=Path)
    warning_parser = sub.add_parser("warnings")
    warning_parser.add_argument("output", type=Path)
    warning_parser.add_argument("logs", nargs="+", type=Path)
    args = parser.parse_args()
    if args.mode == "warnings":
        return 0 if warnings(args.output, args.logs)["strict_compiler_warnings_zero"] else 1
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("use an independent x86_64 Linux CI runner; no Mac builds")
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    out = work / ("out/core-host" if args.mode == "host" else "out")
    env = environment()
    env.setdefault("OPENWRT_VERSION", "25.12.5")
    report = {"status": "running", "phase": args.mode, "commands": [],
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
              "scope": "nine non-dnsmasq candidates; no publication or deployment"}
    passed = False
    try:
        out, passed = (host if args.mode == "host" else sdk_check)(work, env, report)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    finally:
        report["warnings"] = warnings(out / f"core-{args.mode}-warnings.json", sorted(out.glob("*.log")))
        passed = passed and report["warnings"]["strict_compiler_warnings_zero"]
        report["status"] = "passed" if passed else "failed"
        write(out / f"core-{args.mode}-check.json", report)
    print(f"{args.mode}: {report['status']}", flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

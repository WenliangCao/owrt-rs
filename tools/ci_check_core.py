#!/usr/bin/env python3
"""Host tests and real-SDK builds for the non-dnsmasq candidates.

Uses the existing package/core recipes. This workflow neither constructs the
native ten-component release nor changes dnsmasq's identity/qualification gate.
odhcpd is an opt-in standalone SDK output, not a qualified image component.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tomllib

from dnsmasq.compiler_warnings import scan

REPO = Path(__file__).resolve().parent.parent
COMPONENTS = ("platform", "ubus", "uci", "reload-config", "logd", "httpd", "fw4", "rpcd", "ubusd", "netifd", "procd", "odhcpd")
COMMON = {"platform", "ubus", "uci"}
LINK_FLAGS = "-Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs"


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def warnings(output, logs):
    result = scan([path for path in logs if path.is_file()])
    # The unmodified ImageBuilder checks its local repository before generating
    # the initial index. Keep that one known metadata message separate, only
    # in its image log; the common compiler scanner stays unchanged.
    initial_index = re.compile(
        r"^WARNING: opening /[^\s]+/openwrt-imagebuilder-[0-9]+\.[0-9]+\.[0-9]+-"
        r"[^/\s]+/packages/packages\.adb: No such file or directory$")
    compiler = []
    for entry in result["compiler_or_unclassified"]:
        if entry["log"] == "image.log" and initial_index.fullmatch(entry["text"]):
            result["sdk_metadata"].append(entry)
        else:
            compiler.append(entry)
    result["compiler_or_unclassified"] = compiler
    result["strict_compiler_warnings_zero"] = not compiler
    write(output, result)
    print(f"compiler/unclassified warnings: {len(result['compiler_or_unclassified'])}; "
          f"SDK metadata warnings: {len(result['sdk_metadata'])}", flush=True)
    return result


def run(command, log, env):
    if command[0] == "cargo":
        version = subprocess.check_output(["cargo", "-V"], env=env, text=True)
        if "huacnlee/cargo" not in version:
            raise RuntimeError("expected huacnlee/cargo: " + version.strip())
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
    channel = tomllib.loads((REPO / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    env["RUSTUP_TOOLCHAIN"] = channel
    env["RUSTC"] = subprocess.check_output(
        ["rustup", "which", "--toolchain", channel, "rustc"], text=True).strip()
    for key in ("RUSTFLAGS", "RUSTDOCFLAGS"):
        env[key] = (env.get(key, "") + " -Dwarnings").strip()
    env["CARGO_INCREMENTAL"] = "0"
    return env


def comparison_source(runner, work, source_ref):
    """Freeze the product revision while recording the current build adapters."""
    if not re.fullmatch(r"[0-9a-f]{40}", source_ref):
        raise ValueError("comparison source must be a full commit SHA")
    commit = subprocess.check_output(
        ["git", "-C", str(runner), "rev-parse", source_ref + "^{commit}"], text=True).strip()
    source = work / "comparison-source"
    subprocess.run(["git", "-C", str(runner), "worktree", "add", "--detach", str(source), commit], check=True)
    # Historical product and benchmark code keep their compiler and lockfiles.
    # Only execution/packaging adapters come from the workflow checkout.
    for directory in ("tools", "packaging/openwrt"):
        shutil.copytree(runner / directory, source / directory, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("benchmark", "archive", "__pycache__", "*.pyc"))
    verify_comparison_source(source)
    adapters = {}
    for directory in (source / "tools", source / "packaging/openwrt"):
        for path in sorted(directory.rglob("*")):
            if path.is_file() and not {"benchmark", "archive", "__pycache__"}.intersection(path.relative_to(source).parts):
                adapters[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, {
        "source_commit": commit,
        "runner_commit": subprocess.check_output(
            ["git", "-C", str(runner), "rev-parse", "HEAD"], text=True).strip(),
        "component_tree": subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD:components"], text=True).strip(),
        "toolchain_sha256": hashlib.sha256((source / "rust-toolchain.toml").read_bytes()).hexdigest(),
        "adapter_files": adapters,
    }


def verify_comparison_source(source):
    subprocess.run(["git", "-C", str(source), "diff", "--exit-code", "HEAD", "--",
                    "components", "rust-toolchain.toml", "tools/benchmark"], check=True)


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
            # Process fixtures fork/exec while other cases create executables.
            # Match the main Rust gate's serial execution: a concurrent fork
            # can otherwise inherit a writable script FD and cause ETXTBSY.
            options = ["--", "--test-threads=1"]
            test_code = run(common + ["--tests", "--no-fail-fast"] + options, out / f"test-{component}.log", env)
            lib_config = re.search(r"^\[lib\]\n(.*?)(?=^\[|\Z)", manifest.read_text(), re.M | re.S)
            docs_disabled = lib_config and re.search(r"^doctest\s*=\s*false\s*$", lib_config.group(1), re.M)
            if (crate / "src/lib.rs").is_file() and not docs_disabled:
                doc_code = run(common + ["--doc"], out / f"doc-{component}.log", env)
        if any((crate / "examples").glob("*.rs")):
            example_code = run(["cargo", "check", "--locked", "--examples", "--manifest-path", manifest],
                               out / f"examples-{component}.log", env)
        report["commands"].append({"component": component, "compile": compile_code,
                                   "test": test_code, "doc": doc_code, "examples": example_code})
        if component in COMMON and (compile_code or test_code or doc_code):
            break
    passed = len(report["commands"]) == len(COMPONENTS) and all(
        row["compile"] == 0 and row["test"] == 0 and row["doc"] in (0, None)
        and row["examples"] in (0, None) for row in report["commands"])
    # The existing benchmark checks validate the client that will measure all
    # candidates. Run once after component gates pass, with its locked graph.
    report["benchmark_returncode"] = None
    if passed:
        report["benchmark_returncode"] = run(["make", "check-benchmark"], out / "benchmark.log", env)
        passed = report["benchmark_returncode"] == 0
    return out, passed


def sdk_check(work, env, report):
    out = work / "out"
    out.mkdir(parents=True, exist_ok=True)
    for script in ("ci_build_image.sh", "ci_build_core.sh"):
        # Only this diagnostic pipeline opts in. The release-image workflow's
        # direct core invocation retains its qualified three-binary inventory.
        recipe_env = dict(env, OWRT_CORE_INCLUDE_ODHCPD="1") if script == "ci_build_core.sh" else env
        code = run(["sh", REPO / "tools" / script, work], out / f"driver-{script}.txt", recipe_env)
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
                    REPO / "components" / component / "Cargo.toml"],
                   out / f"check-target-{component}.log", check_env)
        report["commands"].append({"target_check": component, "returncode": code})
        if code and component in COMMON:
            return out, False
        crate = REPO / "components" / component
        if any((crate / "examples").glob("*.rs")):
            example_code = run(["cargo", "check", "--locked", "--examples", "--manifest-path",
                                crate / "Cargo.toml"],
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
                       "rpcd-rs", "ubusd-rs", "netifd-rs", "procd-rs", "odhcpd-rs"}:
        raise ValueError("expected all ten actual non-dnsmasq recipe outputs")
    report["binary_sha256"] = hashes
    return out, True


def main():
    global REPO
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("host", "target"):
        command = sub.add_parser(mode)
        command.add_argument("work", type=Path)
        command.add_argument("--source-ref", default="", help="full product commit for a comparison build")
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
    comparison = None
    if args.source_ref:
        REPO, comparison = comparison_source(REPO, work, args.source_ref)
    out = work / ("out/core-host" if args.mode == "host" else "out")
    env = environment()
    env.setdefault("OPENWRT_VERSION", "25.12.5")
    report = {"status": "running", "phase": args.mode, "commands": [],
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
              "scope": "ten non-dnsmasq candidates; no publication or deployment"}
    if comparison is not None:
        report["comparison_source"] = comparison
    passed = False
    try:
        out, passed = (host if args.mode == "host" else sdk_check)(work, env, report)
        if comparison is not None:
            verify_comparison_source(REPO)
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

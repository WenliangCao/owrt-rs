#!/usr/bin/env python3
"""DYN1 diagnostic only: frozen 574f5ed sources, image musl and PIE linkage.

Never changes the package recipe, installs a package, assembles an image or
contacts a router. Coordinate its build window before running it.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = "574f5ed88d8d3c9453f0ac9c25a891933b5a128b"
TARGET = "aarch64-unknown-linux-musl"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, log, env=None):
    with log.open("wb") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, env=env)
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}; see {log}")
    return log.read_text(errors="replace")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "private") or output.exists():
        parser.error("new private output directory required")
    frozen = json.loads(args.freeze.read_text())
    if frozen["commit"] != PRODUCT or hashlib.sha256(json.dumps(frozen["inputs"], sort_keys=True, separators=(",", ":")).encode()).hexdigest() != frozen["source_digest"]:
        parser.error("frozen product identity mismatch")
    output.mkdir(parents=True)
    report = {"status": "failed", "candidate": "DYN1", "product_commit": PRODUCT,
              "freeze_sha256": digest(args.freeze), "source_digest": frozen["source_digest"],
              "tool_sha256": digest(Path(__file__)), "source_files": {},
              "scope": "isolated linkage/size diagnostic, no default adoption or performance acceptance"}
    try:
        source = output / "source"
        for name, expected in frozen["inputs"].items():
            if digest(args.snapshot / name) != expected:
                raise RuntimeError(f"snapshot changed: {name}")
            if name.startswith("components/"):
                destination = source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(args.snapshot / name, destination)
                report["source_files"][name] = digest(destination)
                if report["source_files"][name] != expected:
                    raise RuntimeError(f"source copy changed: {name}")
        sdk = args.sdk.resolve()
        tc = sdk / "staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl"
        cargo = Path.home() / ".cargo/bin/cargo"
        env = os.environ.copy()
        for name in ("CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "CARGO_TARGET_DIR"):
            env.pop(name, None)
        env.update(RUSTUP_TOOLCHAIN="1.98.1", CARGO_BUILD_TARGET=TARGET,
                   CARGO_PROFILE_RELEASE_PANIC="abort", SOURCE_DATE_EPOCH=str(frozen["epoch"]),
                   CC_aarch64_unknown_linux_musl=str(tc / "bin/aarch64-openwrt-linux-musl-gcc"),
                   AR_aarch64_unknown_linux_musl=str(tc / "bin/aarch64-openwrt-linux-musl-ar"),
                   CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=str(tc / "bin/aarch64-openwrt-linux-musl-gcc"))
        base_flags = [f"--remap-path-prefix={source / 'components'}=/build",
                      f"--remap-path-prefix={Path.home() / '.cargo'}=/cargo", "-Clink-arg=-fuse-ld=bfd",
                      "-Clink-arg=-Wl,-z,max-page-size=4096", "-Clink-arg=-Wl,-z,now",
                      "-Clink-arg=-Wl,-z,relro", "-Clink-arg=-Wl,-z,pack-relative-relocs"]
        candidate_flags = ["-Ctarget-feature=-crt-static", "-Clink-self-contained=no", "-Clink-arg=-pie"]
        env["RUSTFLAGS"] = " ".join([*base_flags, *candidate_flags, f"-Clink-arg=-Wl,-Map,{output / 'link.map'}"])
        command = [str(cargo), "build", "--release", "--frozen", "--manifest-path",
                   str(source / "components/dnsmasq/Cargo.toml"), "--bin", "dnsmasq-rs", "--target-dir", str(output / "target")]
        report.update(command=command, base_flags=base_flags, candidate_flags=candidate_flags,
                      rustflags=env["RUSTFLAGS"], sdk=str(sdk))
        run(command, output / "build.log", env)
        original = output / f"target/{TARGET}/release/dnsmasq-rs"
        binary = output / "dnsmasq-rs"
        shutil.copy2(original, binary)
        run([str(sdk / "staging_dir/host/bin/sstrip"), "-z", str(binary)], output / "strip.log")
        elf = run([str(tc / "bin/aarch64-openwrt-linux-musl-readelf"), "-h", "-l", "-d", str(binary)], output / "readelf.log")
        required = ("DYN (Position-Independent Executable file)", "AArch64", "/lib/ld-musl-aarch64.so.1", "GNU_RELRO", "BIND_NOW", "PIE")
        if not all(value in elf for value in required) or "TEXTREL" in elf:
            raise RuntimeError("dynamic PIE/RELRO/NOW ELF gate failed")
        report.update(status="built-structural-check-passed", elf_sha256=digest(binary),
                      elf_size=binary.stat().st_size, pre_strip_sha256=digest(original),
                      size_screen_passed=binary.stat().st_size <= 940491,
                      remaining="verify program-header permissions, exact image dependency resolution and frozen functional gates")
    except (OSError, RuntimeError) as error:
        report["error"] = str(error)
    finally:
        report["warnings"] = [line for log in output.glob("*.log") for line in log.read_text(errors="replace").splitlines()
                              if "warning" in line.lower() or "ld.so" in line.lower()]
        (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("status", "elf_size", "size_screen_passed", "error") if key in report}))
    return int(report["status"] != "built-structural-check-passed")


if __name__ == "__main__":
    raise SystemExit(main())

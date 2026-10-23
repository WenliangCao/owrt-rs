#!/usr/bin/env python3
"""Append explicit PGO flags after the unchanged SDK recipe sets flags."""
import hashlib
import json
import os
from pathlib import Path
import sys


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare(plan, argv, env):
    if argv == ["--version"]:
        return None
    build = Path(plan["build_dir"])
    expected_argv = ["build", "--release", "--frozen", "--manifest-path",
                     str(build / "dnsmasq/Cargo.toml"), "--bin", "dnsmasq-rs",
                     "--target-dir", str(build / "dnsmasq/target")]
    if argv != expected_argv:
        raise ValueError("unexpected SDK Cargo invocation")
    adapter = plan.get("build_adapter")
    if not adapter or sha(adapter["path"]) != adapter["sha256"]:
        raise ValueError("mbx build adapter identity missing or changed")
    expected = plan["recipe_environment"]
    for name, value in expected.items():
        if env.get(name) != value:
            raise ValueError("unexpected SDK recipe environment: " + name)
    for name, value in env.items():
        if value and (name in {"CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER",
                              "RUSTC_WORKSPACE_WRAPPER", "LLVM_PROFILE_FILE", "CARGO_TARGET_DIR"}
                      or name.startswith("CARGO_PROFILE_") and name != "CARGO_PROFILE_RELEASE_PANIC"):
            raise ValueError("unexpected compiler/profile override: " + name)
    linker = env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"]
    if sha(linker) != plan["static_pie_linker_sha256"]:
        raise ValueError("static PIE linker identity changed")
    mapping = plan.get("map_compiler")
    if mapping is not None:
        if (env["DNSMASQ_STATIC_PIE_CC"] != mapping["wrapper"]
                or env["PERF_SDK_CC"] != mapping["sdk_cc"]
                or env["PERF_LINK_MAP"] != mapping["output_path"]
                or sha(mapping["wrapper"]) != mapping["wrapper_sha256"]
                or sha(mapping["sdk_cc"]) != mapping["sdk_cc_sha256"]):
            raise ValueError("link-map wrapper or SDK compiler identity changed")
    recipe_flags = env["RUSTFLAGS"]
    if "profile-" in recipe_flags or "pgo-" in recipe_flags:
        raise ValueError("recipe already supplies PGO flags")
    mode = plan.get("mode", "use")
    if mode == "generate":
        if any(key in plan for key in ("profile", "profile_sha256", "profile_bytes")):
            raise ValueError("instrumentation must not consume a profile")
        directory = Path(plan["profile_output_dir"])
        if not directory.is_absolute() or any(c.isspace() for c in str(directory)):
            raise ValueError("invalid instrumentation profile output directory")
        added = f"-Cprofile-generate={directory}"
        identity = {"profile_output_dir": str(directory)}
    elif mode == "use":
        profile = Path(plan["profile"])
        if (not profile.is_absolute() or any(c.isspace() for c in str(profile))
                or profile.stat().st_size != plan["profile_bytes"] or sha(profile) != plan["profile_sha256"]):
            raise ValueError("frozen PGO profile identity changed")
        added = f"-Cprofile-use={profile} -Cllvm-args=-pgo-warn-missing-function"
        identity = {"profile_sha256": plan["profile_sha256"], "profile_bytes": plan["profile_bytes"]}
    else:
        raise ValueError("unknown PGO mode")
    return {"mode": mode, "argv": argv, "cargo_verbosity": "normal", "recipe_environment": expected,
            "build_adapter": adapter,
            "recipe_rustflags": recipe_flags, "added_rustflags": added,
            "effective_rustflags": recipe_flags + " " + added,
            **identity,
            **({"map_compiler": mapping} if mapping is not None else {}),
            "static_pie_linker_sha256": sha(linker), "wrapper_sha256": sha(__file__)}


def main():
    plan_path = Path(os.environ["DNSMASQ_PGO_BUILD_PLAN"])
    plan = json.loads(plan_path.read_text())
    argv = sys.argv[1:]
    receipt = prepare(plan, argv, os.environ)
    executable = plan["cargo"]
    if receipt is not None:
        executable = receipt["build_adapter"]["path"]
        receipt["plan_sha256"] = sha(plan_path)
        with Path(plan["receipt"]).open("x") as stream:
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
        os.environ["RUSTFLAGS"] = receipt["effective_rustflags"]
    # Preserve normal recipe verbosity. Diagnostic -vv also changes dependency
    # --cap-lints from allow to warn and emits Cargo's ignored-hint advisories.
    os.execv(executable, [executable, *argv])


if __name__ == "__main__":
    main()

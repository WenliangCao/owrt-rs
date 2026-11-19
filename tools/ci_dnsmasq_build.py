"""Explicit compiler identity and SDK adaptation for the shared Cargo fork."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def compiler(channel, env, out, run):
    # A rustup proxy has the same path for different compilers. Bind the actual
    # binary so Cargo's shared rustc-info cache cannot select another toolchain.
    path = Path(run(["rustup", "which", "--toolchain", channel, "rustc"],
                    out / "rustc-path.log", env=env).strip()).resolve(strict=True)
    env["RUSTC"] = str(path)
    version = run([str(path), "-Vv"], out / "rustc-version.log", env=env).strip()
    if f"release: {channel}\n" not in version + "\n":
        raise ValueError("resolved rustc release differs from frozen toolchain")
    return {"path": str(path), "sha256": sha(path), "version": version}


def recipe(source, out, report):
    """Retain the frozen recipe; adapt only the obsolete output-directory flag."""
    dest = out / "runner-recipe"
    shutil.copytree(source, dest)
    makefile = dest / "Makefile"
    before = makefile.read_text()
    legacy = " --target-dir $(PKG_BUILD_DIR)/dnsmasq/target"
    if before.count(legacy) > 1:
        raise ValueError("unexpected historical target-directory arguments")
    after = before.replace(legacy, "")
    if "--target-dir" in after or "CARGO_TARGET_DIR" in after or "mbx" in after:
        raise ValueError("unrecognized obsolete SDK build adapter")
    makefile.write_text(after)
    report["recipe_adaptation"] = {
        "original_sha256": sha(source / "Makefile"), "adapted_sha256": sha(makefile),
        "changes": ["remove explicit Cargo target-directory argument"] if before != after else [],
        "output_selection": "Cargo compiler-artifact executable; copied for SDK installation",
        "historical_source_map_modified": False,
    }
    return dest


def compile_artifact(plan, argv, env):
    """Read Cargo's actual executable output; never guess its shared cache path."""
    cargo = plan["cargo"]
    version = subprocess.check_output([cargo, "-V"], env=env, text=True).strip()
    if "huacnlee/cargo" not in version:
        raise ValueError("build requires huacnlee/cargo")
    dest = Path(plan["install_elf"])
    receipt = Path(plan["artifact_receipt"])
    dest.parent.mkdir(parents=True, exist_ok=True)
    build = Path(plan["build_dir"]) / "dnsmasq"
    product, platform = [], []
    command = [plan["build_adapter"]["path"], *argv, "--message-format=json-render-diagnostics"]
    with receipt.with_suffix(".jsonl").open("x") as raw:
        with subprocess.Popen(command, stdout=subprocess.PIPE, text=True, env=env) as process:
            for line in process.stdout:
                raw.write(line)
                try:
                    row = json.loads(line)
                except ValueError:
                    sys.stdout.write(line)
                    continue
                if row.get("reason") == "compiler-message":
                    sys.stdout.write(row["message"].get("rendered") or line)
                if row.get("reason") == "compiler-artifact":
                    target = row["target"]
                    if (target["name"] == "dnsmasq-rs" and target["kind"] == ["bin"]
                            and row.get("manifest_path") == str(build / "Cargo.toml")):
                        product.append(row)
                    elif (target["name"] == "dnsmasq_platform" and target["kind"] == ["lib"]
                            and row.get("manifest_path") == str(build / "platform/Cargo.toml")):
                        platform.append(row)
            status = process.wait()
    if status:
        return status
    if not (len(product) == len(platform) == 1 and product[0].get("executable")
            and all(type(row.get("fresh")) is bool for row in (product[0], platform[0]))):
        raise ValueError("expected one Cargo executable and platform library for the prepared source")
    elf = Path(product[0]["executable"])
    if not elf.is_absolute() or not elf.is_file():
        raise ValueError("Cargo executable is missing or has a relative path")
    libraries = [Path(name) for name in platform[0].get("filenames", []) if name.endswith(".rlib")]
    if not libraries or any(not path.is_absolute() or not path.is_file() for path in libraries):
        raise ValueError("Cargo platform library output is missing or has a relative path")
    shutil.copy2(elf, dest)
    with receipt.open("x") as stream:
        json.dump({"cargo_version": version, "argv": command, "compiler_artifact": product[0],
                   "platform_artifact": platform[0],
                   "platform_rlibs": [{"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path)}
                                      for path in libraries],
                   "installed_elf": str(dest), "sha256": sha(dest)}, stream, indent=2)
        stream.write("\n")
    return 0

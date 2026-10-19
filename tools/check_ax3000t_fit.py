#!/usr/bin/env python3
"""Check the exact CI FIT patch offline. Requires Linux DT/U-Boot tools.

The ImageBuilder input remains unchanged. Four independent copies test the
missing-property baseline, deterministic output and final-image identity gate.
No kernel or Rust compilation, device access, or firmware deployment occurs.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


REPO = Path(__file__).resolve().parent.parent
LINUX = Path("build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic")
FIT = "xiaomi_mi-router-ax3000t-kernel.bin"
DTB = "image-mt7981b-xiaomi-mi-router-ax3000t.dtb"
ITS = FIT + ".its"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--imagebuilder", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    original, output = args.imagebuilder.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("native_image", REPO / "tools/native_image.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = REPO / "tools/ci_build_image.sh"
    lines = source.read_text().splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if "<<'FITPY'" in line)
    end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "FITPY")
    block = output / "fit_block.py"
    block.write_text("".join(lines[start + 1:end]))
    inputs = {name: sha(original / LINUX / name) for name in (FIT, DTB, ITS)}
    plan = {
        "prediction": "Four copies yield the same FIT despite different mtimes and external epochs; stock misses the new property.",
        "falsifier": "Any differing output byte, kernel payload change, extra DTB mutation, or accepted incomplete metadata.",
        "resolution": "One byte, zero measurement noise; no runtime or boot-speed inference.",
        "regime": "Exact pinned IB payloads and CI Python block on Oracle; final x86 release-image remains required.",
        "stop": "Four positive/baseline pairs and negative identity controls; retain every failure.",
    }
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    result = {"passed": False, "inputs": inputs, "script_sha256": sha(source),
              "verifier_sha256": sha(REPO / "tools/native_image.py"), "rounds": []}
    try:
        for repeat in range(1, 5):
            case = output / str(repeat)
            ib, out = case / "imagebuilder", case / "out"
            (ib / LINUX).mkdir(parents=True)
            out.mkdir()
            (ib / "staging_dir").mkdir()
            (ib / "staging_dir/host").symlink_to(original / "staging_dir/host", target_is_directory=True)
            for name in inputs:
                path = ib / LINUX / name
                shutil.copyfile(original / LINUX / name, path)
                os.utime(path, (1000000000 + repeat * 1000,) * 2)
            # Baseline is the same pinned stock DTB in each independent copy.
            red = subprocess.run(["fdtget", "-t", "s", str(ib / LINUX / DTB),
                                  "/chosen", "bootargs-append"], capture_output=True)
            (case / "before.stderr").write_bytes(red.stderr)
            assert red.returncode != 0 and b"FDT_ERR_NOTFOUND" in red.stderr
            with (case / "build.log").open("wb") as log:
                subprocess.run([sys.executable, str(block), "25.12.5", str(ib), str(case), str(out)],
                               env=dict(os.environ, SOURCE_DATE_EPOCH=str(repeat)),
                               stdout=log, stderr=subprocess.STDOUT, check=True)
            metadata = json.loads((out / "ax3000t-fit.json").read_text())
            final, stock = ib / LINUX / FIT, original / LINUX / FIT
            module.verify_ax3000t_fit(final, stock, metadata)
            dtb = case / "final.dtb"
            subprocess.run(["dumpimage", "-T", "flat_dt", "-p", "1", "-o", str(dtb), str(final)],
                           stdout=subprocess.DEVNULL, check=True)
            appended = subprocess.check_output(["fdtget", "-t", "s", str(dtb), "/chosen", "bootargs-append"])
            assert appended == b" loglevel=4\n"
            negative = []
            for changed in ({**metadata, "bootargs_append": "loglevel=4"},
                            {**metadata, "fit_sha256": inputs[FIT]}):
                try:
                    module.verify_ax3000t_fit(final, stock, changed)
                except AssertionError as error:
                    negative.append(str(error))
                else:
                    raise AssertionError("invalid final-image metadata was accepted")
            result["rounds"].append({"repeat": repeat, "baseline_missing_property": True,
                                     "bootargs_append": appended.decode().rstrip("\n"),
                                     "metadata": metadata, "rejected": negative})
            (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        assert len({r["metadata"]["fit_sha256"] for r in result["rounds"]}) == 1
        assert inputs == {name: sha(original / LINUX / name) for name in inputs}
        result.update(passed=True, original_inputs_unchanged=True)
    finally:
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

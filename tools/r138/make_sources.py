#!/usr/bin/env python3
"""Freeze R136 and one silent-REMOVE reply candidate; do not alter runtime."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

BASE = "12dd2c0"


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"expected one source match: {old[:80]}")
    return text.replace(old, new)


def candidate(path):
    text = path.read_text()
    text = replace(text,
        "    /// A successful ADD has no action left between DATA and STATUS, so it can\n"
        "    /// send both together without a monitor. REMOVE still sends DATA before\n"
        "    /// freeing the object and emitting notifications, then returns STATUS.\n",
        "    /// Callers may include STATUS only when no notification belongs between\n"
        "    /// the two replies. Monitors retain the per-message send boundaries.\n")
    text = replace(text,
        "request: &InMsg, id: u32, type_id: Option<u32>) -> Outcome {",
        "request: &InMsg, id: u32, type_id: Option<u32>, with_status: bool) -> Outcome {")
    text = replace(text,
        "if request.header.ty == ty::ADD_OBJECT && self.monitors.is_empty() {",
        "if with_status && self.monitors.is_empty() {")
    text = replace(text,
        "        self.send_object_reply(client, msg, id, reply_type)\n",
        "        self.send_object_reply(client, msg, id, reply_type, true)\n")
    text = replace(text,
        "        self.send_object_reply(client, msg, id, reply_type);\n",
        "        // With no observer of teardown, finish it before submitting both\n"
        "        // replies together. Keep free_object intact, including event epochs.\n"
        "        let silent = self.monitors.is_empty()\n"
        "            && o.targets.is_empty() && o.subscribers.is_empty()\n"
        "            && (o.path.is_none() || self.patterns.is_empty());\n"
        "        if silent {\n"
        "            self.free_object(id);\n"
        "            return self.send_object_reply(client, msg, id, reply_type, true);\n"
        "        }\n"
        "        self.send_object_reply(client, msg, id, reply_type, false);\n")
    path.write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[2]
    archive = subprocess.check_output(["git", "-C", str(repo), "archive", BASE,
                                       "components/ubusd", "components/ubus"])
    subprocess.run(["tar", "-xf", "-", "-C", str(args.out)], input=archive, check=True)
    records = []
    for label in ("r136", "silent-remove"):
        dest = args.out / label / "components"
        shutil.copytree(args.out / "components", dest)
        if label == "silent-remove":
            candidate(dest / "ubusd/src/server.rs")
        sources = {str(p.relative_to(dest)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted(dest.rglob("*")) if p.is_file()}
        records.append(dict(label=label, source_sha256=sources))
    shutil.rmtree(args.out / "components")
    (args.out / "sources.json").write_text(json.dumps(
        dict(base_commit=BASE, variants=records), indent=2) + "\n")


if __name__ == "__main__":
    main()

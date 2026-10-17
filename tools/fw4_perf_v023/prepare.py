#!/usr/bin/env python3
"""Assemble private measurement inputs; never connects to a physical router."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("old_elf", type=Path)
    parser.add_argument("new_elf", type=Path)
    parser.add_argument("helpers", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    expected = {
        "fw4-v022": "ee5a9c5685f7363be3fc2bd5039546b2f01327633afc24031b446fc0fb7f5b55",
        "fw4-v023": "2a077d0d268fca821463919219ee339b629c37cab2f47b2584b382074a83a72c",
    }
    for name, source in (("fw4-v022", args.old_elf), ("fw4-v023", args.new_elf)):
        assert sha(source) == expected[name], (name, "ELF identity changed")
    config_source = args.capture / "firewall-and-renew-readonly.txt"
    source = config_source.read_text()
    config = source[source.index("config defaults"):source.index("\nRULESET")]
    assert "option flow_offloading '1'" in config
    assert "option flow_offloading_hw '0'" in config
    assert "config include" not in config
    assert config.count("option dest_port '68'") == 1
    changed = config.replace("option dest_port '68'", "option dest_port '41001'")
    comments = args.capture / "10-custom-filter-chains.nft"
    assert all(not line.strip() or line.lstrip().startswith("#") for line in comments.read_text().splitlines())
    network_sources = [args.capture / f"fw4-input-diff/case-{i:02d}/ubus/network.interface~dump.json" for i in (0, 1)]
    for path in network_sources:
        assert {x["interface"] for x in json.loads(path.read_text())["interface"]} == {"lan", "loopback", "wan", "wan6"}
    args.output.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    for name in ("driver.sh", "fixture.uc"):
        shutil.copyfile(here / name, args.output / name)
    for name in ("ns-exec", "exec-sample"):
        shutil.copyfile(args.helpers / name, args.output / name)
    for name, source in (("fw4-v022", args.old_elf), ("fw4-v023", args.new_elf), ("comments.nft", comments),
                         ("network-a.json", network_sources[0]), ("network-b.json", network_sources[1])):
        shutil.copyfile(source, args.output / name)
    (args.output / "firewall-a").write_text(config)
    (args.output / "firewall-b").write_text(changed)
    for name in ("ns-exec", "exec-sample", "fw4-v022", "fw4-v023", "driver.sh"):
        (args.output / name).chmod(0o700)
    manifest = {
        "schema": 1,
        "input_source_sha256": {str(p): sha(p) for p in (config_source, comments, *network_sources)},
        "files": {p.name: sha(p) for p in sorted(args.output.iterdir())},
        "changed_rule": "Only Allow-DHCP-Renew dest_port 68 -> 41001, in isolated ruleset",
        "unchanged_input": "Captured case-00 -> case-01 WAN6 update; all non-WAN6 interfaces unchanged",
        "scope": "One sample per external FIFO command; no sampling schedule or performance verdict here",
    }
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"files": len(manifest["files"]), "bytes": sum(p.stat().st_size for p in args.output.iterdir()),
                      "manifest_sha256": sha(args.output / "manifest.json")}))


if __name__ == "__main__":
    main()

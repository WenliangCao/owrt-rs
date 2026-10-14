#!/usr/bin/env python3
"""Second independent, deliberately narrow decoder for the original F2 fixture.

Consumes wire hex only, never driver canonical/checks or prior audit parsers.
Preserves every header field, label byte, ordered RR, TTL and unknown RDATA.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct


class BadName(Exception):
    pass


def parse_name(packet, start, route=()):
    """Return raw label hex and bytes consumed at the original position."""
    pos = start
    labels = []
    while True:
        if pos in route or pos >= len(packet):
            raise BadName({"reason": "loop-or-bounds", "offset": pos})
        size = packet[pos]
        if size == 0:
            return labels, pos + 1
        if size >= 192:
            if pos + 1 >= len(packet):
                raise BadName({"reason": "short-pointer", "offset": pos})
            dest = (size - 192) * 256 + packet[pos + 1]
            rest, _ = parse_name(packet, dest, route + tuple(range(start, pos + 1)))
            labels += rest
            if sum(len(x) // 2 + 1 for x in labels) + 1 > 255:
                raise BadName({"reason": "oversize-name", "offset": start})
            return labels, pos + 2
        if size > 63:
            raise BadName({"reason": "invalid-label-type", "offset": pos, "byte": size})
        if pos + size + 1 > len(packet):
            raise BadName({"reason": "short-label", "offset": pos})
        labels.append(packet[pos + 1:pos + size + 1].hex())
        if sum(len(x) // 2 + 1 for x in labels) + 1 > 255:
            raise BadName({"reason": "oversize-name", "offset": start})
        pos += size + 1


def packet(hex_value):
    wire = bytes.fromhex(hex_value)
    header = list(struct.unpack_from("!6H", wire))
    value = {"header": header, "question": [], "answer": [], "authority": [], "additional": []}
    position = 12
    offsets = []
    errors = []
    for _ in range(header[2]):
        name, position = parse_name(wire, position)
        kind, klass = struct.unpack_from("!HH", wire, position)
        value["question"].append([name, kind, klass])
        position += 4
    for section, number in zip(("answer", "authority", "additional"), header[3:]):
        for index in range(number):
            owner_start = position
            owner, position = parse_name(wire, position)
            fixed = position
            kind, klass, ttl, length = struct.unpack_from("!HHIH", wire, position)
            rstart = position + 10
            rend = rstart + length
            assert rend <= len(wire), "RDLENGTH exceeds packet"
            raw = wire[rstart:rend]
            if kind in (2, 5):
                try:
                    name, consumed = parse_name(wire, rstart)
                    assert consumed == rend, "RDATA name does not consume RDLENGTH"
                    data = {"name": name}
                except BadName as error:
                    data = {"invalid_name": error.args[0]}
                    errors.append({"section": section, "index": index, **error.args[0]})
            else:
                assert kind in (1, 41), "Unexpected fixture RR type"
                if kind == 1:
                    assert length == 4
                data = {"hex": raw.hex()}
            value[section].append([owner, kind, klass, ttl, data])
            offsets.append({"section": section, "index": index,
                            "owner_offset": owner_start, "owner_wire": wire[owner_start:fixed].hex(),
                            "rdata_offset": rstart, "rdata_hex": raw.hex()})
            position = rend
    assert position == len(wire), "Trailing bytes"
    return {"semantic": value, "layout": offsets, "errors": errors,
            "wire_hex": hex_value, "bytes": len(wire), "sha256": hashlib.sha256(wire).hexdigest()}


def no_transaction_id(parsed):
    value = copy.deepcopy(parsed["semantic"])
    value["header"][0] = 0
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads(args.input.read_text())
    expected = {"c": "097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87",
                "main": "ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863",
                "before": "7a56d4302dc8fbd3df8d5c441d2b910c0cf2222d9d3b105ef599ad4ca2150f7c",
                "fix": "a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66"}
    assert all(source["identities"][side] == sha for side, sha in expected.items())
    assert source["host_anchor"] is False and source["upstream_cnames"] is True
    assert len(source["cases"]) == 4
    assert {(r["debug"], r["protocol"]) for r in source["cases"]} == {
        (False, "udp"), (False, "tcp"), (True, "udp"), (True, "tcp")}
    result = {"input_private_path": "/home/ubuntu/dnsmasq-audit-fix6-20261014/private/recheck-f2-20261014/result.json",
              "input_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
              "decoder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "identities": source["identities"], "cases": []}
    alias = [b"alias".hex(), b"example".hex()]
    target = [b"target".hex(), b"example".hex()]
    other = [b"other".hex(), b"example".hex()]
    for case in source["cases"]:
        assert [line for line in case["config"].splitlines() if line.startswith("dns-rr=")] == [
            "dns-rr=target.example,5,c062",
            *["dns-rr=target.example,5,056f74686572076578616d706c6500"] * 3]
        assert "host-record=target.example" not in case["config"]
        sides = {}
        for side, runtime in case["sides"].items():
            assert runtime["alive"] is True and runtime["exit"] == 0
            parsed = {}
            for field in ("response", "warm", "health"):
                assert runtime[field]["status"] == "reply"
                parsed[field] = packet(runtime[field]["hex"])
            for field in ("warm_upstream", "upstream"):
                parsed[field] = []
                for flow in runtime[field]:
                    assert flow["protocol"] == case["protocol"]
                    q, r = packet(flow["query"]), packet(flow["reply"])
                    assert q["semantic"]["header"][0] == r["semantic"]["header"][0]
                    assert not q["errors"] and not r["errors"]
                    parsed[field].append({"query": q, "reply": r})
            assert len(parsed["warm_upstream"]) == 1
            assert len(parsed["upstream"]) == (1 if side == "main" else 0)
            parsed["alive"] = runtime["alive"]
            parsed["exit"] = runtime["exit"]
            sides[side] = parsed
        c = sides["c"]["response"]
        assert c["semantic"] == {
            "header": [0x1234, 0x8580, 1, 5, 0, 0],
            "question": [[alias, 255, 1]],
            "answer": [[alias, 5, 1, 300, {"name": target}]] + [[target, 5, 1, 60, {"name": other}]] * 4,
            "authority": [], "additional": []}
        assert sides["fix"]["response"]["wire_hex"] == c["wire_hex"]
        assert sides["main"]["response"]["semantic"] == c["semantic"]
        assert [sides[s]["response"]["bytes"] for s in ("c", "main", "before", "fix")] == [154, 223, 196, 154]
        before = sides["before"]["response"]
        assert before["errors"] == [{"section": "answer", "index": 4, "reason": "invalid-label-type", "offset": 98, "byte": 112}]
        repaired = copy.deepcopy(before["semantic"])
        repaired["answer"][4][4] = {"name": other}
        assert repaired == c["semantic"]
        assert [rr["owner_wire"] for rr in c["layout"]] == ["c00c"] + ["c02b"] * 4
        assert [rr["rdata_offset"] for rr in c["layout"]] == [43, 71, 98, 125, 152]
        assert c["layout"][-1]["rdata_hex"] == before["layout"][-1]["rdata_hex"] == "c062"
        assert parse_name(bytes.fromhex(c["wire_hex"]), 98)[0] == other
        for side in sides.values():
            for field in ("warm", "health"):
                assert not side[field]["errors"]
                assert side[field]["wire_hex"] == sides["c"][field]["wire_hex"]
            for field in ("query", "reply"):
                assert no_transaction_id(side["warm_upstream"][0][field]) == no_transaction_id(sides["c"]["warm_upstream"][0][field])
        assert no_transaction_id(sides["main"]["upstream"][0]["reply"]) == no_transaction_id(c)
        result["cases"].append({"label": case["label"], "debug": case["debug"], "protocol": case["protocol"],
                                "config": case["config"], "query_hex": case["query"], "warm_query_hex": case["warm_query"],
                                "sides": sides})
    result["summary"] = {"fresh_cases": 4, "fix_c_final_wire_identical": 4,
                         "main_c_full_semantics_equal": 4, "before_original_failure_reproduced": 4,
                         "warm_and_health_wire_identical_daemons": 16, "healthy_daemon_lifecycles": 16,
                         "ttl_tolerance_seconds": 0}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"]))


if __name__ == "__main__":
    main()

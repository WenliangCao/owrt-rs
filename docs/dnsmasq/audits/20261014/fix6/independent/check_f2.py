#!/usr/bin/env python3
"""Independently decode FIX6 F2 raw packets; no audit/product parser imports.

The small fixture uses A, CNAME and OPT. Client comparisons preserve every
semantic field, including TTL, case, sections and duplicate RR order. Wire
lengths/offsets are retained separately because name compression may differ.
Only upstream transaction IDs are normalized, after checking query/reply IDs.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct


class NameError(ValueError):
    def __init__(self, reason, offset, byte=None):
        self.detail = {"reason": reason, "offset": offset}
        if byte is not None:
            self.detail["byte"] = byte
        super().__init__(str(self.detail))


def read_name(packet, offset):
    labels, visited = [], set()
    wire_end = None
    expanded = 1
    while True:
        if offset >= len(packet):
            raise NameError("out-of-bounds", offset)
        if offset in visited:
            raise NameError("pointer-cycle", offset)
        visited.add(offset)
        size = packet[offset]
        if size == 0:
            return labels, offset + 1 if wire_end is None else wire_end
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise NameError("short-pointer", offset)
            if wire_end is None:
                wire_end = offset + 2
            offset = ((size & 0x3F) << 8) + packet[offset + 1]
        elif size & 0xC0:
            raise NameError("invalid-label-type", offset, size)
        else:
            end = offset + size + 1
            if end > len(packet):
                raise NameError("short-label", offset)
            expanded += size + 1
            if expanded > 255:
                raise NameError("expanded-name-over-255", offset)
            labels.append(packet[offset + 1:end].hex())
            offset = end


def decode(raw_hex):
    packet = bytes.fromhex(raw_hex)
    header = struct.unpack_from("!6H", packet)
    semantic = {"header": dict(zip(
        ("id", "flags", "qdcount", "ancount", "nscount", "arcount"), header)),
        "question": [], "answer": [], "authority": [], "additional": []}
    offset, layout, errors = 12, [], []
    for _ in range(header[2]):
        labels, offset = read_name(packet, offset)
        qtype, qclass = struct.unpack_from("!HH", packet, offset)
        offset += 4
        semantic["question"].append({"labels_hex": labels, "type": qtype, "class": qclass})
    for section, count in zip(("answer", "authority", "additional"), header[3:]):
        for index in range(count):
            start = offset
            owner, fixed = read_name(packet, start)
            rrtype, rrclass, ttl, length = struct.unpack_from("!HHIH", packet, fixed)
            rstart, offset = fixed + 10, fixed + 10 + length
            if offset > len(packet):
                raise ValueError("RDLENGTH extends beyond packet")
            data = packet[rstart:offset]
            if rrtype in (2, 5):
                try:
                    labels, consumed = read_name(packet, rstart)
                    if consumed != offset:
                        raise ValueError("RDATA name does not consume RDLENGTH")
                    value = {"labels_hex": labels}
                except NameError as error:
                    value = {"invalid_name": error.detail}
                    errors.append({"section": section, "index": index, **error.detail})
            else:
                if rrtype not in (1, 41):
                    raise ValueError(f"unexpected fixture type {rrtype}")
                if rrtype == 1 and length != 4:
                    raise ValueError("A RDATA must contain four bytes")
                value = {"bytes_hex": data.hex()}
            semantic[section].append({"owner_labels_hex": owner, "type": rrtype,
                                      "class": rrclass, "ttl": ttl, "rdata": value})
            layout.append({"section": section, "index": index, "owner_offset": start,
                           "owner_wire_hex": packet[start:fixed].hex(),
                           "fixed_offset": fixed, "rdata_offset": rstart,
                           "rdata_length": length, "rdata_hex": data.hex()})
    if offset != len(packet):
        raise ValueError("trailing packet bytes")
    return {"semantic": semantic, "layout": layout, "errors": errors,
            "length": len(packet), "hex": raw_hex,
            "sha256": hashlib.sha256(packet).hexdigest()}


def without_id(parsed):
    semantic = copy.deepcopy(parsed["semantic"])
    semantic["header"]["id"] = 0
    return semantic


def response(value):
    assert value["status"] == "reply", value
    parsed = decode(value["hex"])
    if "length" in value:
        assert parsed["length"] == value["length"]
    return parsed


def upstream(rows, protocol):
    parsed = []
    for row in rows:
        query, reply = decode(row["query"]), decode(row["reply"])
        assert row["protocol"] == protocol
        assert not query["errors"] and not reply["errors"]
        assert query["semantic"]["header"]["id"] == reply["semantic"]["header"]["id"]
        parsed.append({"protocol": protocol, "query": query, "reply": reply})
    return parsed


def check_file(path):
    data = json.loads(path.read_text())
    assert {key: data["identities"][key] for key in ("c", "main", "before", "fix")} == {
        "c": "097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87",
        "main": "ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863",
        "before": "7a56d4302dc8fbd3df8d5c441d2b910c0cf2222d9d3b105ef599ad4ca2150f7c",
        "fix": "a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66"}
    assert not data["host_anchor"] and data["upstream_cnames"]
    assert len(data["cases"]) == 4
    assert {(row["debug"], row["protocol"]) for row in data["cases"]} == {
        (False, "udp"), (False, "tcp"), (True, "udp"), (True, "tcp")}
    result = {"source_private_path": "/home/ubuntu/dnsmasq-audit-fix6-20261014/private/"
              + path.stem + "/result.json", "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
              "identities": data["identities"], "cases": []}
    for row in data["cases"]:
        assert [line for line in row["config"].splitlines() if line.startswith("dns-rr=")] == [
            "dns-rr=target.example,5,c062",
            *["dns-rr=target.example,5,056f74686572076578616d706c6500"] * 3]
        assert "host-record=target.example" not in row["config"]
        sides = {}
        for name in ("c", "main", "before", "fix"):
            side = row["sides"][name]
            assert side["alive"] is True and side["exit"] == 0
            assert len(side["warm_upstream"]) == 1
            assert len(side["upstream"]) == (1 if name == "main" else 0)
            sides[name] = {"response": response(side["response"]),
                           "warm": response(side["warm"]), "health": response(side["health"]),
                           "warm_upstream": upstream(side["warm_upstream"], row["protocol"]),
                           "upstream": upstream(side["upstream"], row["protocol"]),
                           "alive": side["alive"], "exit": side["exit"], "started": side["started"]}
        c = sides["c"]["response"]
        assert c["semantic"]["header"] == {"id": 0x1234, "flags": 0x8580,
            "qdcount": 1, "ancount": 5, "nscount": 0, "arcount": 0}
        assert [rr["ttl"] for rr in c["semantic"]["answer"]] == [300, 60, 60, 60, 60]
        alias = ["616c696173", "6578616d706c65"]
        target = ["746172676574", "6578616d706c65"]
        other = ["6f74686572", "6578616d706c65"]
        assert c["semantic"]["question"] == [{"labels_hex": alias, "type": 255, "class": 1}]
        assert [rr["owner_labels_hex"] for rr in c["semantic"]["answer"]] == [alias] + [target] * 4
        assert [rr["rdata"] for rr in c["semantic"]["answer"]] == [{"labels_hex": target}] + [{"labels_hex": other}] * 4
        assert all(rr["type"] == 5 and rr["class"] == 1 for rr in c["semantic"]["answer"])
        warm = sides["c"]["warm"]["semantic"]
        assert warm["question"] == [{"labels_hex": alias, "type": 1, "class": 1}]
        assert warm["answer"] == [
            {"owner_labels_hex": alias, "type": 5, "class": 1, "ttl": 300, "rdata": {"labels_hex": target}},
            {"owner_labels_hex": target, "type": 1, "class": 1, "ttl": 300, "rdata": {"bytes_hex": "c000024d"}}]
        for name in ("c", "main", "fix"):
            assert not sides[name]["response"]["errors"]
            assert sides[name]["response"]["semantic"] == c["semantic"]
        assert sides["fix"]["response"]["hex"] == c["hex"]
        assert c["length"] == 154
        assert sides["main"]["response"]["length"] == 223
        old = sides["before"]["response"]
        assert old["length"] == 196
        assert old["errors"] == [{"section": "answer", "index": 4,
            "reason": "invalid-label-type", "offset": 98, "byte": 0x70}]
        corrected = copy.deepcopy(old["semantic"])
        corrected["answer"][4]["rdata"] = c["semantic"]["answer"][4]["rdata"]
        assert corrected == c["semantic"]
        for name in ("c", "fix"):
            parsed = sides[name]["response"]
            assert parsed["layout"][-1]["rdata_hex"] == "c062"
            assert [rr["owner_wire_hex"] for rr in parsed["layout"]] == ["c00c"] + ["c02b"] * 4
            assert read_name(bytes.fromhex(parsed["hex"]), 98)[0] == ["6f74686572", "6578616d706c65"]
        assert old["layout"][-1]["rdata_hex"] == "c062"
        for name, side in sides.items():
            for field in ("warm", "health"):
                assert not side[field]["errors"]
                assert side[field]["semantic"] == sides["c"][field]["semantic"]
                assert side[field]["hex"] == sides["c"][field]["hex"]
            for direction in ("query", "reply"):
                assert without_id(side["warm_upstream"][0][direction]) == without_id(
                    sides["c"]["warm_upstream"][0][direction])
        forwarded = sides["main"]["upstream"][0]
        assert forwarded["query"]["semantic"]["question"] == decode(row["query"])["semantic"]["question"]
        assert without_id(forwarded["reply"]) == without_id(c)
        result["cases"].append({"label": row["label"], "protocol": row["protocol"],
            "debug": row["debug"], "config": row["config"], "query_hex": row["query"],
            "warm_query_hex": row["warm_query"], "sides": sides,
            "checks": {"fix_c_identical_final_bytes": True, "main_c_complete_semantics_equal": True,
                       "before_original_malformed_reproduced": True,
                       "fix_c_owner_layout_and_c062_target_equal": True,
                       "all_warm_and_health_client_bytes_equal": True,
                       "warm_upstream_queries_and_replies_equal_except_id": True,
                       "main_final_upstream_reply_equals_c_except_id": True,
                       "all_lifecycles_pass": True}})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, action="append", required=True)
    parser.add_argument("--c-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    c_bytes = args.c_source.read_bytes()
    assert hashlib.sha256(c_bytes).hexdigest() == "231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222"
    lines = c_bytes.decode().splitlines()
    assert "crec_ttl(crecp, now), &nameoffset," in "\n".join(lines[1794:1797])
    assert "daemon->local_ttl, NULL," in "\n".join(lines[1861:1872])
    assert 't->class, C_IN, "t", t->len, t->txt' in "\n".join(lines[1861:1872])
    assert "memcpy(p, sval, usval);" in "\n".join(lines[1609:1617])
    result = {"checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "comparison": "No driver canonical fields used. Full client bytes and full DNS semantics checked; only compression normalized for semantic comparison. Upstream transaction IDs are separately checked then normalized.",
              "c_source": {"sha256": hashlib.sha256(c_bytes).hexdigest(),
                           "cached_cname_cursor_lines": [1795, 1797],
                           "raw_null_cursor_lines": [1862, 1872],
                           "opaque_copy_lines": [1610, 1617]},
              "runs": [check_file(path) for path in args.result]}
    count = sum(len(run["cases"]) for run in result["runs"])
    result["summary"] = {"cases": count, "fix_c_final_byte_identical": count,
                         "main_c_complete_semantics_equal": count,
                         "before_original_malformed": count,
                         "warm_and_health_byte_identical_daemons": count * 4,
                         "healthy_lifecycles": count * 4}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"]))


if __name__ == "__main__":
    main()

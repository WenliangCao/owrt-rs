#!/usr/bin/env python3
"""Decode the retained F2 packets without importing either audit comparator.

Names lose only their compression representation. Header fields, label case,
RR order, sections, class, TTL and decoded RDATA remain exact. This deliberately
small parser handles the A/NS/CNAME records used by this synthetic fixture.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct


class InvalidName(ValueError):
    def __init__(self, code, offset, value=None):
        self.detail = {"code": code, "offset": offset}
        if value is not None:
            self.detail["byte"] = value
            self.detail["byte_hex"] = f"{value:02x}"
        super().__init__(str(self.detail))


def name(packet, offset):
    labels, seen, resume = [], set(), None
    expanded_length = 1
    while True:
        if offset >= len(packet):
            raise InvalidName("out-of-bounds", offset)
        if offset in seen:
            raise InvalidName("pointer-loop", offset)
        seen.add(offset)
        length = packet[offset]
        if length == 0:
            return labels, resume if resume is not None else offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise InvalidName("truncated-pointer", offset)
            if resume is None:
                resume = offset + 2
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
        elif length <= 63:
            end = offset + 1 + length
            if end > len(packet):
                raise InvalidName("truncated-label", offset)
            expanded_length += length + 1
            if expanded_length > 255:
                raise InvalidName("name-too-long", offset)
            labels.append(packet[offset + 1:end].hex())
            offset = end
        else:
            raise InvalidName("invalid-label-type", offset, length)


def decode(hex_packet):
    packet = bytes.fromhex(hex_packet)
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", packet)
    semantic = {
        "header": {"id": ident, "flags": flags, "qdcount": qd,
                   "ancount": an, "nscount": ns, "arcount": ar},
        "questions": [], "answer": [], "authority": [], "additional": [],
    }
    cursor, layouts, errors = 12, [], []
    for _ in range(qd):
        labels, cursor = name(packet, cursor)
        qtype, qclass = struct.unpack_from("!HH", packet, cursor)
        cursor += 4
        semantic["questions"].append({"labels_hex": labels, "type": qtype, "class": qclass})
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for index in range(count):
            start = cursor
            owner, fixed = name(packet, cursor)
            rrtype, rrclass, ttl, size = struct.unpack_from("!HHIH", packet, fixed)
            data_start, cursor = fixed + 10, fixed + 10 + size
            if cursor > len(packet):
                raise ValueError("RDLENGTH exceeds packet")
            data = packet[data_start:cursor]
            layout = {"section": section, "index": index, "owner_offset": start,
                      "rdata_offset": data_start, "rdata_length": size,
                      "rdata_hex": data.hex()}
            if rrtype in (2, 5):
                try:
                    labels, consumed = name(packet, data_start)
                    if consumed != cursor:
                        raise ValueError("name does not consume exactly RDLENGTH")
                    rdata = {"name_labels_hex": labels}
                except InvalidName as error:
                    rdata = {"invalid_name": error.detail}
                    errors.append({"section": section, "index": index, **error.detail})
            elif rrtype == 1:
                if size != 4:
                    raise ValueError("invalid A length")
                rdata = {"ipv4_bytes": list(data)}
            else:
                raise ValueError(f"unexpected fixture RR type {rrtype}")
            semantic[section].append({"owner_labels_hex": owner, "type": rrtype,
                                      "class": rrclass, "ttl": ttl, "rdata": rdata})
            layouts.append(layout)
    if cursor != len(packet):
        raise ValueError("unparsed trailing packet bytes")
    return {"semantic": semantic, "layout": layouts, "errors": errors,
            "length": len(packet), "sha256": hashlib.sha256(packet).hexdigest(),
            "hex": hex_packet}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--c-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads(args.result.read_text())
    assert source["host_anchor"] is False
    assert source["upstream_cnames"] is True
    assert len(source["cases"]) == 4
    assert {(row["debug"], row["protocol"]) for row in source["cases"]} == {
        (False, "udp"), (False, "tcp"), (True, "udp"), (True, "tcp")}
    evidence = {
        "source_private_path": "/home/ubuntu/dnsmasq-audit-fix5-20261014/private/cname-dynamic-01/result.json",
        "source_sha256": hashlib.sha256(args.result.read_bytes()).hexdigest(),
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "binary_identities": source["identities"],
        "comparison": "Only name compression is normalized; preserve every header, question, section, RR order, label byte/case, class, TTL and decoded RDATA field.",
        "cases": [],
    }
    for row in source["cases"]:
        parsed, warm = {}, {}
        for side in ("c", "main", "before", "fix"):
            runtime = row["sides"][side]
            assert runtime["response"]["status"] == "reply"
            assert runtime["warm"]["status"] == "reply"
            parsed[side] = decode(runtime["response"]["hex"])
            warm[side] = decode(runtime["warm"]["hex"])
            parsed[side]["upstream_count"] = len(runtime["upstream"])
            parsed[side]["alive"] = runtime["alive"]
            parsed[side]["exit"] = runtime["exit"]
            parsed[side]["health_status"] = runtime["health"]["status"]
            assert runtime["alive"] is True and runtime["exit"] == 0
        c = parsed["c"]["semantic"]
        for side in ("c", "main", "before"):
            assert not parsed[side]["errors"]
            assert parsed[side]["semantic"] == c
        assert all(item["semantic"] == warm["c"]["semantic"] for item in warm.values())
        assert c["header"] == {"id": 0x1234, "flags": 0x8580, "qdcount": 1,
                               "ancount": 5, "nscount": 0, "arcount": 0}
        assert [rr["ttl"] for rr in c["answer"]] == [300, 60, 60, 60, 60]
        fix = parsed["fix"]
        assert fix["semantic"]["header"] == c["header"]
        assert fix["semantic"]["questions"] == c["questions"]
        assert fix["semantic"]["answer"][:4] == c["answer"][:4]
        assert fix["errors"] == [{"section": "answer", "index": 4,
                                   "code": "invalid-label-type", "offset": 98,
                                   "byte": 112, "byte_hex": "70"}]
        assert parsed["c"]["layout"][-1]["rdata_hex"] == "c062"
        assert fix["layout"][-1]["rdata_hex"] == "c062"
        assert bytes.fromhex(fix["hex"])[98] == ord("p")
        assert name(bytes.fromhex(parsed["c"]["hex"]), 98)[0] == ["6f74686572", "6578616d706c65"]
        assert [parsed[side]["upstream_count"] for side in ("c", "main", "before", "fix")] == [0, 1, 0, 0]
        head_other_fields_match = (
            all(fix["semantic"][key] == c[key]
                for key in ("header", "questions", "authority", "additional"))
            and fix["semantic"]["answer"][:-1] == c["answer"][:-1]
            and {key: value for key, value in fix["semantic"]["answer"][-1].items()
                 if key != "rdata"}
            == {key: value for key, value in c["answer"][-1].items() if key != "rdata"}
        )
        assert head_other_fields_match
        evidence["cases"].append({
            "label": row["label"], "protocol": row["protocol"], "debug": row["debug"],
            "config": row["config"], "query_hex": row["query"], "sides": parsed,
            "checks": {"c_main_before_exact_semantics_including_ttl": True,
                       "warm_all_exact_semantics_including_ttl": True,
                       "head_last_cname_invalid_at_offset_98": True,
                       "head_other_fields_match_c": head_other_fields_match},
        })
    c_source = args.c_source.read_bytes()
    lines = c_source.decode().splitlines()
    raw_loop = "\n".join(lines[1861:1872])
    assert 'daemon->local_ttl, NULL,' in raw_loop
    assert 't->class, C_IN, "t", t->len, t->txt' in raw_loop
    assert 'crec_ttl(crecp, now), &nameoffset,' in "\n".join(lines[1794:1797])
    assert 'memcpy(p, sval, usval);' in "\n".join(lines[1609:1617])
    evidence["c_source_review"] = {
        "reference_path": "/home/ubuntu/dnsmasq-rewrite-20260929/reference/dnsmasq-2.93/src/rfc1035.c",
        "sha256": hashlib.sha256(c_source).hexdigest(),
        "cached_cname_lines": [1795, 1797], "cached_cname_updates_nameoffset": True,
        "raw_loop_lines": [1862, 1872], "raw_loop_updates_nameoffset": False,
        "raw_loop": raw_loop,
        "opaque_copy_lines": [1610, 1617],
        "conclusion": "Configured raw TYPE5 uses the same opaque 't' path and NULL output offset as every other dns-rr type. It does not advance C's owner cursor.",
    }
    evidence["summary"] = {"cases": 4, "c_main_before_match_including_ttl": 4,
                           "head_malformed_last_cname": 4, "all_daemons_alive_and_exit_zero": 16}
    args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence["summary"]))


if __name__ == "__main__":
    main()

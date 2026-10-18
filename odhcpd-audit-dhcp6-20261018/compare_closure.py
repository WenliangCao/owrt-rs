#!/usr/bin/env python3
"""Compare the five original targeted DHCPv6 replies to frozen C evidence."""
import hashlib
import json
from pathlib import Path
import sys

reference_path, candidate_path = map(Path, sys.argv[1:3])
expected_candidate_sha = sys.argv[3]
reference = json.loads(reference_path.read_text())
candidate = json.loads(candidate_path.read_text())
assert reference["events"]["complete"] is True
assert candidate["events"]["complete"] is True
assert reference["events"]["identity"]["sha256"] == "53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82"
assert candidate["events"]["identity"]["sha256"] == expected_candidate_sha
assert candidate["events"]["expected_elf_sha256"] == [expected_candidate_sha]
events = ["na_request_600", "na_renew_after_1200_reload", "na_rebind_after_1200_reload",
          "fresh_na_after_1200_reload", "pd_renew_old_128"]
output = {"candidate_elf_sha256": expected_candidate_sha,
          "reference_results_sha256": hashlib.sha256(reference_path.read_bytes()).hexdigest(),
          "candidate_results_sha256": hashlib.sha256(candidate_path.read_bytes()).hexdigest(),
          "matches": {}}
for event in events:
    left = [item for item in reference["events"][event]["decoded"]["options"] if item["code"] in (3, 25)]
    right = [item for item in candidate["events"][event]["decoded"]["options"] if item["code"] in (3, 25)]
    assert left and right
    assert left == right, (event, left, right)
    output["matches"][event] = True
output["complete"] = True
print(json.dumps(output, indent=2))

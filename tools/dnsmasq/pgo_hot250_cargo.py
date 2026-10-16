#!/usr/bin/env python3
"""One fixed backend change over the frozen training profile-use flags."""
import json
import os
from pathlib import Path
import sys

import pgo_train_cargo as original


def main():
    path = Path(os.environ['PGO_SMOKE_PLAN'])
    plan = json.loads(path.read_text())
    assert original.sha(__file__) == plan['wrapper_sha256']
    assert original.sha(original.__file__) == plan['base_wrapper_sha256']
    assert plan['hot_callsite_threshold'] == 250
    mode = os.environ['PGO_SMOKE_MODE']
    argv = sys.argv[1:]
    receipt = original.prepare(plan, mode, argv, os.environ)
    if receipt is not None:
        assert receipt['profile']['plan_sha256'] == plan['training_plan_sha256']
        assert original.sha(plan['profile_receipt']) == plan['profile_receipt_sha256']
        assert receipt['profile']['merged_profile']['sha256'] == plan['merged_profile_sha256']
        extra = ' -Cllvm-args=-hot-callsite-threshold=250'
        receipt.update(base_use_rustflags=receipt['effective_rustflags'],
                       added_rustflags=receipt['added_rustflags'] + extra,
                       effective_rustflags=receipt['effective_rustflags'] + extra,
                       scope=plan['scope'], plan_sha256=original.sha(path),
                       wrapper_sha256=original.sha(__file__),
                       base_wrapper_sha256=original.sha(original.__file__),
                       cargo_sha256=original.sha(plan['cargo']),
                       rustc_sha256=original.sha(plan['rustc']), rustc_environment=plan['rustc'])
        with Path(plan['invocation_receipts'][mode]).open('x') as stream:
            json.dump(receipt, stream, indent=2)
            stream.write('\n')
        os.environ['RUSTFLAGS'] = receipt['effective_rustflags']
    os.environ['RUSTC'] = plan['rustc']
    os.execv(plan['cargo'], [plan['cargo'], *argv])


if __name__ == '__main__':
    main()

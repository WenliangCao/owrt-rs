import json
from pathlib import Path
import tempfile
import unittest

import m5_interface_records as family


class RetainedProgress(unittest.TestCase):
    def exercise(self, samples, side='rust', alive=False):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);target=root/'hosts';body=b'# comment\n';target.write_bytes(body)
            states=[];error=None
            try: family.check_hosts_large_progress(root,target,body,samples,states,side,alive)
            except AssertionError as failed: error=str(failed)
            proof=json.loads((root/'hosts-large-progress.json').read_text())
            self.assertEqual(proof,states[0])
            self.assertEqual(proof['samples'],samples)
            self.assertEqual(proof['bytes'],len(body))
            return error,proof

    def sample(self, healthy=True, before=True, after=True):
        return dict(healthy=healthy,file_active=before,file_still_active=after,
                    started_ns=100,completed_ns=200)

    def test_missing_overlap_is_red_and_its_healthy_samples_are_retained(self):
        for before,after in [(False,False),(True,False),(False,True)]:
            error,proof=self.exercise([self.sample(before=before,after=after)])
            self.assertEqual(error,'no Rust DNS progress while hosts file stayed open')
            self.assertEqual(proof['healthy_while_open'],0)

    def test_unhealthy_empty_and_live_worker_evidence_is_retained(self):
        for samples,alive in [([self.sample(False)],False),([],False),([self.sample()],True)]:
            error,_=self.exercise(samples,alive=alive)
            self.assertEqual(error,'hosts large-file owner health failed')

    def test_actual_overlap_is_required_only_for_rust(self):
        error,proof=self.exercise([self.sample()]);self.assertIsNone(error)
        self.assertEqual(proof['healthy_while_open'],1)
        error,proof=self.exercise([self.sample(before=False,after=False)],side='c')
        self.assertIsNone(error);self.assertEqual(proof['healthy_while_open'],0)

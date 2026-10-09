import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import m5_interface_records as family


class RetainedProgress(unittest.TestCase):
    def test_same_path_log_does_not_finish_an_open_or_old_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary)
            with patch.object(family.files,'open_file_fds',return_value=[{'fd':7}]), \
                    patch.object(family.files,'exchange') as exchange:
                self.assertFalse(family.hosts_large_completed(1,15353,True,out))
                exchange.assert_not_called()
            for address,wanted in [('192.0.2.7',False),('192.0.2.8',True)]:
                reply={'response':{'records':[{'type':1,'data':address}]}}
                with patch.object(family.files,'open_file_fds',return_value=[]), \
                        patch.object(family.files,'exchange',return_value=reply):
                    self.assertEqual(family.hosts_large_completed(1,15353,True,out),wanted)
                    self.assertEqual(json.loads((out/'hosts-large-completion.json').read_text())['source_published'],wanted)
            reply={'response':{'records':[{'type':1,'data':'192.0.2.8'}]}}
            with patch.object(family.files,'open_file_fds',side_effect=[[],[{'fd':8}]]), \
                    patch.object(family.files,'exchange',return_value=reply):
                self.assertFalse(family.hosts_large_completed(1,15353,True,out))

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

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import m5_final_archive_gate as gate
from m2_rootfs import sha256


class LocalArchiveGateTests(unittest.TestCase):
    def test_missing_or_remote_only_verification_does_not_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); run = root / 'syntax'; run.mkdir()
            (run / 'result.json').write_text('{}\n')
            (root / 'syntax.tar.gz').write_bytes(b'archive fixture')
            manifest = root / 'syntax.manifest.json'
            manifest.write_text(json.dumps({'archive_sha256': sha256(root / 'syntax.tar.gz'),
                'entries': {'result.json': {'sha256': sha256(run / 'result.json')}}}))
            prune = {'archive_sha256': sha256(root / 'syntax.tar.gz')}
            (root / 'syntax.prune.json').write_text(json.dumps(prune))
            with self.assertRaises(FileNotFoundError): gate.verify(root, ['syntax'])
            receipt = {'verified': True, 'local_full_metadata_verified': True, 'verifier_host': 'local-mac',
                       'archive_sha256': prune['archive_sha256'], 'manifest_sha256': sha256(manifest)}
            path = root / 'syntax.local-verification.json'
            path.write_text(json.dumps(receipt))
            with patch.object(gate.socket, 'gethostname', return_value='oracle-host'):
                self.assertEqual(len(gate.verify(root, ['syntax'])), 1)
                receipt['verifier_host'] = 'oracle-host'; path.write_text(json.dumps(receipt))
                with self.assertRaises(ValueError): gate.verify(root, ['syntax'])
                receipt['verifier_host'] = 'local-mac'; path.write_text(json.dumps(receipt))
                (run / 'result.json').write_text('{"changed":true}')
                with self.assertRaises(ValueError): gate.verify(root, ['syntax'])


if __name__ == '__main__': unittest.main()

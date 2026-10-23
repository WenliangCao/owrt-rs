"""SDK adapter routing and toolchain pin checks; no product is compiled."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class MbxCargoTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "tools").mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls.jsonl"
        for name in ("mbx_cargo.sh", "toolchain_identity.sh"):
            shutil.copy2(ROOT / "tools" / name, self.root / "tools" / name)
        shutil.copy2(ROOT / "rust-toolchain.toml", self.root / "rust-toolchain.toml")
        self.pin = (ROOT / "rust-toolchain.toml").read_text().split('channel = "')[1].split('"')[0]
        for name in ("cargo", "rustc", "mbx"):
            tool = self.bin / name
            tool.write_text(f"#!{sys.executable}\n" + '''import json,os,pathlib,socket,sys,tempfile
name=pathlib.Path(sys.argv[0]).name
with open(os.environ['CALL_LOG'],'a') as log:
 log.write(json.dumps({'tool':name,'argv':sys.argv[1:],'flags':os.environ.get('RUSTFLAGS'),'tmpdir':os.environ.get('TMPDIR')})+'\\n')
if name=='mbx' and os.environ.get('CHECK_SESSION_SOCKET'):
 with tempfile.TemporaryDirectory(prefix='mbx-session-',dir=os.environ['TMPDIR']) as folder:
  with socket.socket(socket.AF_UNIX) as peer:peer.bind(folder+'/cache-agent.sock')
if name!='mbx':print(name+' '+os.environ[name.upper()+'_VERSION']+' (fixture)')
''')
            tool.chmod(0o755)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('CARGO', 'RUSTC', 'RUSTUP', 'OWRT_ALLOW_TOOLCHAIN'))}
        self.env.update(PATH=str(self.bin) + ":/usr/bin:/bin", CALL_LOG=str(self.log),
                        CARGO_HOME=str(self.root / ".cargo"), CARGO_VERSION=self.pin,
                        RUSTC_VERSION=self.pin, RUSTUP_TOOLCHAIN=self.pin)

    def run_adapter(self, *arguments):
        return subprocess.run(["sh", str(self.root / "tools/mbx_cargo.sh"), *arguments],
                              env=self.env, text=True, capture_output=True)

    def test_version_queries_use_cargo_but_compilation_uses_mbx_without_flag_changes(self):
        self.assertEqual(self.run_adapter("-V").stdout.strip(), f"cargo {self.pin} (fixture)")
        self.assertEqual(self.run_adapter("--version").returncode, 0)
        self.env["RUSTFLAGS"] = "-Dwarnings -Cprofile-use=/tmp/fixed.profdata"
        args = ["build", "--locked", "--manifest-path", "/tmp/source with space/Cargo.toml"]
        self.assertEqual(self.run_adapter(*args).returncode, 0)
        rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([row["tool"] for row in rows], ["cargo", "cargo", "mbx"])
        self.assertEqual(rows[-1]["argv"], args)
        self.assertEqual(rows[-1]["flags"], self.env["RUSTFLAGS"])

    def test_missing_mbx_never_falls_back_to_plain_cargo(self):
        (self.bin / "mbx").unlink()
        self.assertNotEqual(self.run_adapter("build", "--locked").returncode, 0)
        self.assertFalse(self.log.exists())

    def test_sdk_long_tmpdir_cannot_overflow_the_mbx_session_socket_path(self):
        sdk_tmp = self.root / ("sdk-" + "long" * 40) / "tmp"
        sdk_tmp.mkdir(parents=True)
        self.env.update(TMPDIR=str(sdk_tmp), CHECK_SESSION_SOCKET="1")
        control = subprocess.run([str(self.bin / "mbx"), "build"], env=self.env,
                                 text=True, capture_output=True)
        self.assertNotEqual(control.returncode, 0, "long-path control unexpectedly bound")
        self.assertIn("AF_UNIX path too long", control.stderr)
        self.assertEqual(self.run_adapter("build", "--locked").returncode, 0)
        rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(rows[-1]["tmpdir"], "/tmp")
        self.assertEqual(rows[-1]["argv"], ["build", "--locked"])

    def test_adapter_does_not_bypass_cargo_rustc_or_wrapper_pin_rejections(self):
        identity = self.root / "tools/toolchain_identity.sh"
        env = dict(self.env, CARGO=str(self.root / "tools/mbx_cargo.sh"))
        accepted = subprocess.run(["sh", str(identity)], env=env, text=True, capture_output=True)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("official=yes", accepted.stdout)
        for override in ({"CARGO_VERSION": "0.0.0"}, {"RUSTC_VERSION": "0.0.0"},
                         {"RUSTC_WRAPPER": "/usr/bin/true"}):
            with self.subTest(override=override):
                rejected = subprocess.run(["sh", str(identity)], env={**env, **override},
                                          text=True, capture_output=True)
                self.assertNotEqual(rejected.returncode, 0)


if __name__ == "__main__":
    unittest.main()

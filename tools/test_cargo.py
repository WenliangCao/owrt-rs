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


class CargoTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "tools").mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls.jsonl"
        for name in ("cargo.sh", "toolchain_identity.sh"):
            shutil.copy2(ROOT / "tools" / name, self.root / "tools" / name)
        shutil.copy2(ROOT / "rust-toolchain.toml", self.root / "rust-toolchain.toml")
        self.pin = (ROOT / "rust-toolchain.toml").read_text().split('channel = "')[1].split('"')[0]
        for name in ("cargo", "rustc"):
            tool = self.bin / name
            tool.write_text(f"#!{sys.executable}\n" + '''import json,os,pathlib,socket,sys,tempfile
name=pathlib.Path(sys.argv[0]).name
with open(os.environ['CALL_LOG'],'a') as log:
 log.write(json.dumps({'tool':name,'argv':sys.argv[1:],'flags':os.environ.get('RUSTFLAGS'),'tmpdir':os.environ.get('TMPDIR')})+'\\n')
if name=='cargo':print('cargo '+os.environ['CARGO_VERSION'])
else:print(name+' '+os.environ[name.upper()+'_VERSION']+' (fixture)')
''')
            tool.chmod(0o755)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('CARGO', 'RUSTC', 'RUSTUP', 'OWRT_ALLOW_TOOLCHAIN'))}
        self.env.update(PATH=str(self.bin) + ":/usr/bin:/bin", CALL_LOG=str(self.log),
                        CARGO_HOME=str(self.root / ".cargo"), CARGO_VERSION="1.102.0 (huacnlee/cargo 0.103.0-1)",
                        RUSTC_VERSION=self.pin, RUSTUP_TOOLCHAIN=self.pin, RUSTC=str(self.bin / "rustc"))

    def run_adapter(self, *arguments):
        return subprocess.run(["sh", str(self.root / "tools/cargo.sh"), *arguments],
                              env=self.env, text=True, capture_output=True)

    def test_build_preserves_arguments_and_flags(self):
        self.assertIn("huacnlee/cargo", self.run_adapter("-V").stdout)
        self.assertEqual(self.run_adapter("--version").returncode, 0)
        self.env["RUSTFLAGS"] = "-Dwarnings -Cprofile-use=/tmp/fixed.profdata"
        args = ["build", "--locked", "--manifest-path", "/tmp/source with space/Cargo.toml"]
        result = self.run_adapter(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([row["tool"] for row in rows], ["cargo"] * 4)
        self.assertEqual(rows[-2]["argv"], ["-V"])
        self.assertEqual(rows[-1]["argv"], args)
        self.assertEqual(rows[-1]["flags"], self.env["RUSTFLAGS"])

    def test_stock_cargo_is_rejected_before_build(self):
        self.env["CARGO_VERSION"] = self.pin
        result = self.run_adapter("build", "--locked")
        self.assertNotEqual(result.returncode, 0)
        rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([row["argv"] for row in rows], [["-V"]])

    def test_adapter_does_not_bypass_cargo_rustc_or_wrapper_pin_rejections(self):
        identity = self.root / "tools/toolchain_identity.sh"
        env = dict(self.env, CARGO=str(self.root / "tools/cargo.sh"))
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

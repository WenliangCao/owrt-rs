//! Shell recipes owrt-tools drives: the mbx SDK adapter and the core release
//! recipe, run with recording stubs. Nothing is compiled.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_exec(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn pin() -> String {
    let text = fs::read_to_string(repo().join("rust-toolchain.toml")).unwrap();
    text.split("channel = \"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}

/// One record per call: tool, RUSTFLAGS, TMPDIR, then the arguments.
const RECORDER: &str = r#"#!/bin/sh
name=${0##*/}
{ printf '%s\t%s\t%s' "$name" "${RUSTFLAGS-}" "${TMPDIR-}"; for arg; do printf '\t%s' "$arg"; done; printf '\n'; } >> "$CALL_LOG"
case $name in
cargo) printf 'cargo %s (fixture)\n' "$CARGO_VERSION" ;;
rustc) printf 'rustc %s (fixture)\n' "$RUSTC_VERSION" ;;
esac
"#;

struct Adapter {
    dir: TempDir,
    pin: String,
    env: Vec<(String, String)>,
}

struct Call {
    tool: String,
    flags: String,
    tmpdir: String,
    argv: Vec<String>,
}

impl Adapter {
    fn new() -> Self {
        let dir = TempDir::new("owrt-mbx-cargo");
        let root = &dir.0;
        fs::create_dir_all(root.join("tools")).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        for name in ["mbx_cargo.sh", "toolchain_identity.sh"] {
            fs::copy(
                repo().join("tools").join(name),
                root.join("tools").join(name),
            )
            .unwrap();
        }
        fs::copy(
            repo().join("rust-toolchain.toml"),
            root.join("rust-toolchain.toml"),
        )
        .unwrap();
        for name in ["cargo", "rustc", "mbx"] {
            write_exec(&root.join("bin").join(name), RECORDER);
        }
        let pin = pin();
        let mut env: Vec<(String, String)> = std::env::vars()
            .filter(|(key, _)| {
                ![
                    "CARGO",
                    "RUSTC",
                    "RUSTUP",
                    "OWRT_ALLOW_TOOLCHAIN",
                    "RUSTFLAGS",
                    "TMPDIR",
                ]
                .iter()
                .any(|prefix| key.starts_with(prefix))
                    && key != "PATH"
            })
            .collect();
        for (key, value) in [
            (
                "PATH",
                format!("{}:/usr/bin:/bin", root.join("bin").display()),
            ),
            ("CALL_LOG", root.join("calls.log").display().to_string()),
            ("CARGO_HOME", root.join(".cargo").display().to_string()),
            ("CARGO_VERSION", pin.clone()),
            ("RUSTC_VERSION", pin.clone()),
            ("RUSTUP_TOOLCHAIN", pin.clone()),
        ] {
            env.push((key.to_owned(), value));
        }
        Self { dir, pin, env }
    }

    fn set(&mut self, key: &str, value: &str) {
        self.env.retain(|(name, _)| name != key);
        self.env.push((key.to_owned(), value.to_owned()));
    }

    fn run(&self, program: &str, args: &[&str], extra: &[(&str, &str)]) -> Output {
        let mut command = Command::new(program);
        command
            .args(args)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)));
        command.envs(extra.iter().copied());
        command.output().unwrap()
    }

    fn adapter(&self, args: &[&str]) -> Output {
        let script = self.dir.0.join("tools/mbx_cargo.sh");
        let mut full = vec![script.to_str().unwrap()];
        full.extend(args);
        self.run("sh", &full, &[])
    }

    fn calls(&self) -> Vec<Call> {
        let Ok(text) = fs::read_to_string(self.dir.0.join("calls.log")) else {
            return Vec::new();
        };
        text.lines()
            .map(|line| {
                let mut fields = line.split('\t').map(str::to_owned);
                Call {
                    tool: fields.next().unwrap(),
                    flags: fields.next().unwrap(),
                    tmpdir: fields.next().unwrap(),
                    argv: fields.collect(),
                }
            })
            .collect()
    }
}

#[test]
fn version_queries_use_cargo_but_compilation_uses_mbx_without_flag_changes() {
    let mut fixture = Adapter::new();
    let version = fixture.adapter(&["-V"]);
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        format!("cargo {} (fixture)", fixture.pin)
    );
    assert!(fixture.adapter(&["--version"]).status.success());
    let flags = "-Dwarnings -Cprofile-use=/tmp/fixed.profdata";
    fixture.set("RUSTFLAGS", flags);
    let args = [
        "build",
        "--locked",
        "--manifest-path",
        "/tmp/source with space/Cargo.toml",
    ];
    assert!(fixture.adapter(&args).status.success());
    let calls = fixture.calls();
    assert_eq!(
        calls
            .iter()
            .map(|call| call.tool.as_str())
            .collect::<Vec<_>>(),
        ["cargo", "cargo", "mbx"]
    );
    assert_eq!(calls[2].argv, args);
    assert_eq!(calls[2].flags, flags);
}

#[test]
fn missing_mbx_never_falls_back_to_plain_cargo() {
    let fixture = Adapter::new();
    fs::remove_file(fixture.dir.0.join("bin/mbx")).unwrap();
    assert!(!fixture.adapter(&["build", "--locked"]).status.success());
    assert!(fixture.calls().is_empty());
}

#[test]
fn sdk_long_tmpdir_cannot_overflow_the_mbx_session_socket_path() {
    let mut fixture = Adapter::new();
    let sdk_tmp = fixture
        .dir
        .0
        .join(format!("sdk-{}", "long".repeat(40)))
        .join("tmp");
    fs::create_dir_all(&sdk_tmp).unwrap();
    // Control: mbx's session socket below the SDK TMPDIR cannot be bound.
    let socket = sdk_tmp.join("mbx-session-XXXXXXXX/cache-agent.sock");
    let error = std::os::unix::net::UnixListener::bind(&socket).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
    fixture.set("TMPDIR", sdk_tmp.to_str().unwrap());
    assert!(fixture.adapter(&["build", "--locked"]).status.success());
    let calls = fixture.calls();
    let last = calls.last().unwrap();
    assert_eq!(last.tmpdir, "/tmp");
    assert_eq!(last.argv, ["build", "--locked"]);
}

#[test]
fn adapter_does_not_bypass_cargo_rustc_or_wrapper_pin_rejections() {
    let mut fixture = Adapter::new();
    let identity = fixture.dir.0.join("tools/toolchain_identity.sh");
    let identity = identity.to_str().unwrap();
    let adapter = fixture.dir.0.join("tools/mbx_cargo.sh");
    fixture.set("CARGO", adapter.to_str().unwrap());
    let accepted = fixture.run("sh", &[identity], &[]);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert!(String::from_utf8_lossy(&accepted.stdout).contains("official=yes"));
    for (key, value) in [
        ("CARGO_VERSION", "0.0.0"),
        ("RUSTC_VERSION", "0.0.0"),
        ("RUSTC_WRAPPER", "/usr/bin/true"),
    ] {
        let rejected = fixture.run("sh", &[identity], &[(key, value)]);
        assert!(!rejected.status.success(), "{key}={value} accepted");
    }
}

/// `ci_build_core.sh` with recording git/rsync/mbx and the real owrt-tools
/// for the warning gate and the manifest. Needs GNU tar (`--sort=name`).
#[cfg(target_os = "linux")]
#[test]
fn core_recipe_default_stays_three_and_opt_in_copies_netifd_dependency() {
    const GIT: &str = "#!/bin/sh\ncase \" $* \" in *--format=%ct*) echo 1 ;; *) echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;; esac\n";
    const RSYNC: &str = "#!/bin/sh\nfor arg; do src=${dst-}; dst=$arg; done\nmkdir -p \"$dst\"\ncp -R \"$src.\" \"$dst\"\n";
    const MBX: &str = r#"#!/bin/sh
while [ $# -gt 0 ]; do
    case $1 in --manifest-path) manifest=$2; shift ;; --target-dir) target=$2; shift ;; esac
    shift
done
dir=$(dirname "$manifest")
component=${dir##*/}
[ "$component" != odhcpd ] || [ -f "$dir/../netifd/Cargo.toml" ] || exit 1
mkdir -p "$target/aarch64-unknown-linux-musl/release"
printf 'fixture %s' "$component" > "$target/aarch64-unknown-linux-musl/release/$component-rs"
echo "$component" >> "$TEST_CARGO_LOG"
"#;
    for include in [None, Some("1")] {
        let dir = TempDir::new("owrt-core-recipe");
        let root = &dir.0;
        let tools = root.join("tools");
        fs::create_dir_all(&tools).unwrap();
        let script = fs::read_to_string(repo().join("tools/ci_build_core.sh")).unwrap();
        // Relocate only this fixture's canonical source slot.
        assert_eq!(script.matches("/tmp/owrt-core-release/").count(), 1);
        let slot = format!("{}/", root.join("source-slot").display());
        fs::write(
            tools.join("ci_build_core.sh"),
            script.replace("/tmp/owrt-core-release/", &slot),
        )
        .unwrap();
        fs::write(root.join("rust-toolchain.toml"), "channel = \"1.98.1\"\n").unwrap();
        fs::write(
            tools.join("toolchain_identity.sh"),
            "printf '%s\\n' 'official=yes'\n",
        )
        .unwrap();
        fs::copy(
            repo().join("tools/mbx_cargo.sh"),
            tools.join("mbx_cargo.sh"),
        )
        .unwrap();
        fs::write(tools.join("check_abi.sh"), "exit 0\n").unwrap();
        fs::write(
            tools.join("owrt-tools.sh"),
            format!("exec '{}' \"$@\"\n", env!("CARGO_BIN_EXE_owrt-tools")),
        )
        .unwrap();
        for name in [
            "procd", "ubusd", "netifd", "odhcpd", "ubus", "uci", "platform",
        ] {
            let crate_dir = root.join("components").join(name);
            fs::create_dir_all(&crate_dir).unwrap();
            fs::write(
                crate_dir.join("Cargo.toml"),
                format!("[package]\nname = \"{name}\"\n"),
            )
            .unwrap();
        }
        let work = root.join("work");
        let out = work.join("out");
        fs::create_dir_all(&out).unwrap();
        fs::write(
            out.join("manifest.json"),
            format!(
                "{{\"source_commit\": \"{}\", \"openwrt\": \"25.12.5\"}}",
                "a".repeat(40)
            ),
        )
        .unwrap();
        let linker = work.join(
            "openwrt-sdk-25.12.5-fixture/staging_dir/toolchain-aarch64_fixture/bin/aarch64-openwrt-linux-musl-gcc",
        );
        fs::create_dir_all(linker.parent().unwrap()).unwrap();
        write_exec(&linker, "#!/bin/sh\nexit 0\n");
        let commands = root.join("commands");
        fs::create_dir_all(&commands).unwrap();
        for (name, body) in [("git", GIT), ("rsync", RSYNC), ("mbx", MBX)] {
            write_exec(&commands.join(name), body);
        }
        let mut command = Command::new("sh");
        command
            .arg(tools.join("ci_build_core.sh"))
            .arg(&work)
            .env("OPENWRT_VERSION", "25.12.5")
            .env(
                "PATH",
                format!("{}:{}", commands.display(), std::env::var("PATH").unwrap()),
            )
            .env("TEST_CARGO_LOG", root.join("cargo.log"))
            .env_remove("OWRT_CORE_INCLUDE_ODHCPD");
        if let Some(value) = include {
            command.env("OWRT_CORE_INCLUDE_ODHCPD", value);
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let mut expected = vec!["procd", "ubusd", "netifd"];
        if include.is_some() {
            expected.push("odhcpd");
        }
        assert_eq!(
            fs::read_to_string(root.join("cargo.log"))
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            expected
        );
        let names: BTreeSet<String> = expected.iter().map(|name| format!("{name}-rs")).collect();
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("core-manifest.json")).unwrap())
                .unwrap();
        let hashed: BTreeSet<String> = manifest["binary_sha256"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(hashed, names);
        let archive = fs::File::open(out.join("core-binaries.tar.gz")).unwrap();
        let members: BTreeSet<String> = tar::Archive::new(flate2::read::GzDecoder::new(archive))
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().display().to_string())
            .collect();
        assert_eq!(members, names);
    }
}

use std::fs;

use serde_json::{json, Value};

use super::*;
use crate::device::NATIVE_PATHS;
use crate::util::{strings, TempDir};

fn args(extra: &[&str]) -> Vec<String> {
    let mut raw = strings(["candidate", "out", "--interface", "en0"]);
    raw.extend(strings(extra.iter().copied()));
    raw
}

#[test]
fn native_runner_rejects_missing_guard_and_rom_before_ssh() {
    for extra in [
        &[][..],
        &["--native-manifest", "unused", "--reference-root", "/stock"][..],
        &[
            "--native-manifest",
            "unused",
            "--guard",
            "guard",
            "--reference-root",
            "/stock",
        ][..],
        &[
            "--native-manifest",
            "unused",
            "--guard",
            "guard",
            "--reference-root",
            "/rom/",
            "--health-guard-root",
            "/tmp/dnsmasq-perf-core",
        ][..],
    ] {
        let mut raw = vec!["--stack", "native"];
        raw.extend(extra);
        assert!(Options::parse(&args(&raw)).is_err(), "{extra:?}");
    }
    assert!(Options::parse(&args(&["--bogus"])).is_err());
    assert!(
        Options::parse(&args(&["--schedule", "random-blocks", "--guard", "g"])).is_err(),
        "random-blocks needs a seed"
    );
}

#[test]
fn schedules_match_the_python_orders() {
    let order = |extra: &[&str]| schedule_order(&Options::parse(&args(extra)).unwrap());
    assert_eq!(
        order(&[
            "--schedule",
            "random-blocks",
            "--seed",
            "7",
            "--guard",
            "g",
            "--repeats",
            "3"
        ]),
        [
            "r84",
            "stock",
            "candidate",
            "candidate",
            "stock",
            "r84",
            "candidate",
            "stock",
            "r84"
        ]
    );
    assert_eq!(
        order(&[
            "--sides",
            "stock",
            "candidate",
            "--repeats",
            "2",
            "--baseline-label",
            "r89"
        ]),
        ["stock", "candidate", "candidate", "stock"]
    );
    assert_eq!(
        order(&["--repeats", "2", "--baseline-label", "r89"]),
        ["stock", "r89", "candidate", "candidate", "r89", "stock"]
    );
    assert_eq!(
        order(&[
            "--schedule",
            "three-side-sequential",
            "--repeats",
            "2",
            "--baseline-label",
            "v021"
        ]),
        ["stock", "stock", "v021", "v021", "candidate", "candidate"]
    );
    assert_eq!(
        order(&[
            "--schedule",
            "two-side-balanced",
            "--sides",
            "stock",
            "candidate",
            "--repeats",
            "2"
        ]),
        [
            "stock",
            "candidate",
            "candidate",
            "stock",
            "stock",
            "candidate",
            "candidate",
            "stock"
        ]
    );
}

struct FakeDevice {
    health: Value,
    identity: String,
    comparison: Value,
    digests: BTreeMap<String, String>,
    commands: Vec<String>,
    windows: usize,
}

const PARTIAL: &[u8] = b"failed window retained\n";

impl Device for FakeDevice {
    fn ssh(&mut self, command: &str, _timeout: f64) -> Result<Vec<u8>> {
        self.commands.push(command.to_owned());
        assert!(
            !command.contains("stack-switch") && !command.contains("/root/r84"),
            "{command}"
        );
        let value = if command.starts_with("set -eu\ntest ! -L /tmp/dnsmasq-perf-core") {
            "55 66\n".to_owned()
        } else if command.starts_with("cd ") && command.contains("find . -type f") {
            format!("{}  ./partial.txt\n", util::sha256_bytes(PARTIAL))
        } else if command.starts_with("cat ") && command.ends_with(".identity") {
            "77 88\n".to_owned()
        } else if command.starts_with("cat ") && command.ends_with("/manifest.json") {
            assert!(
                ["cat /host-tools/manifest.json", "cat /v021/manifest.json"].contains(&command),
                "{command}"
            );
            self.comparison.to_string()
        } else if command == "readlink -f /stock-root" {
            "/stock-root".to_owned()
        } else if command == "sha256sum /etc/config/*" {
            "same config".to_owned()
        } else if let Some(paths) = command.strip_prefix("sha256sum ") {
            let mut values = Vec::new();
            for path in paths.split_whitespace().map(|path| path.trim_matches('\'')) {
                let name = Path::new(path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let digest = if path.starts_with("/stock-root/") {
                    "b".repeat(64)
                } else {
                    self.digests[&name].clone()
                };
                values.push(format!("{digest}  {path}"));
            }
            values.join("\n")
        } else if command.starts_with("/host-tools/bins/owrt-benchmark snapshot ") {
            "{}".to_owned()
        } else if ["test ! -e ", "cp ", "cat /proc/"]
            .iter()
            .any(|prefix| command.starts_with(prefix))
        {
            String::new()
        } else {
            panic!("unexpected collector operation: {command}");
        };
        Ok(value.into_bytes())
    }

    fn ssh_into(
        &mut self,
        command: &str,
        output: &File,
        _merge: bool,
        _timeout: f64,
    ) -> Result<i32> {
        self.commands.push(command.to_owned());
        assert!(command.starts_with("tar -czf - -C "), "{command}");
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            output.try_clone()?,
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(PARTIAL.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, "partial.txt", PARTIAL)?;
        archive.into_inner()?.finish()?.flush()?;
        Ok(0)
    }

    fn scp(&mut self, _local: &Path, _target: &str) -> Result<()> {
        Ok(())
    }

    fn probe(&mut self, _options: &ProbeOptions) -> Result<Value> {
        Ok(self.health.clone())
    }

    fn native_identity(&mut self, _host: &str, _manifest: &Value) -> Result<String> {
        Ok(self.identity.clone())
    }

    fn guarded_window(
        &mut self,
        command: &str,
        _root: &str,
        guard: (u64, u64),
        _helper: &str,
        _receipt: &str,
        _log: &File,
    ) -> Result<i32> {
        assert!(
            command.starts_with("OWRT_BENCH_GUARD=")
                && command.contains("/isolated.sh /stock-root "),
            "{command}"
        );
        assert_eq!(guard, (55, 66));
        self.windows += 1;
        bail!("fixture guard died")
    }
}

#[test]
fn native_guard_failure_archives_before_raising_and_never_prunes() {
    let dir = TempDir::new("owrt-run-candidate");
    let base = dir.path();
    let (candidate, guard, manifest_path) = (
        base.join("candidate"),
        base.join("guard"),
        base.join("manifest.json"),
    );
    fs::write(&candidate, b"candidate").unwrap();
    fs::write(&guard, b"guard").unwrap();
    let components: Map<String, Value> = NATIVE_PATHS
        .iter()
        .enumerate()
        .map(|(number, (name, path))| ((*name).to_owned(), json!({"path": path, "rust_sha256": format!("{:064x}", number + 1), "stock_sha256": "b".repeat(64)})))
        .collect();
    let manifest = json!({"deployment_layout": "native-ten", "source_commit": "a".repeat(40), "components": components});
    fs::write(&manifest_path, manifest.to_string()).unwrap();
    let manifest_sha = util::sha256_file(&manifest_path).unwrap();
    let identity: String = NATIVE_PATHS
        .iter()
        .enumerate()
        .map(|(number, (name, _))| match *name {
            "uci" | "fw4" | "reload-config" => format!("{name} - - {:064x}\n", number + 1),
            "procd" => format!("{name} 1 101 {:064x}\n", number + 1),
            _ => format!(
                "{name} {} {} {:064x}\n",
                10 + number,
                100 + number,
                number + 1
            ),
        })
        .collect();
    let tools = [
        ("ns-exec", "c".repeat(64)),
        ("owrt-benchmark", "d".repeat(64)),
    ];
    let comparison_components: Map<String, Value> = components
        .iter()
        .filter(|(name, _)| *name != "dnsmasq")
        .map(|(name, item)| (name.clone(), json!({"original": {"sha256": item["stock_sha256"]}, "rust": {"sha256": item["rust_sha256"]}})))
        .collect();
    let comparison = json!({"components": comparison_components,
                            "tools": tools.iter().map(|(name, digest)| ((*name).to_owned(), json!({"sha256": digest}))).collect::<Map<_, _>>()});
    let benchmark = util::repo().join("tools/benchmark");
    let mut digests: BTreeMap<String, String> = tools
        .iter()
        .map(|(name, digest)| ((*name).to_owned(), digest.clone()))
        .collect();
    digests.insert("guard".into(), util::sha256_file(&guard).unwrap());
    digests.insert(
        "isolated.sh".into(),
        util::sha256_file(&benchmark.join("isolated.sh")).unwrap(),
    );
    digests.insert(
        "owned_group.sh".into(),
        util::sha256_file(&benchmark.join("owned_group.sh")).unwrap(),
    );
    digests.insert("procd-rs".into(), util::sha256_file(&candidate).unwrap());
    let mut device = FakeDevice {
        health: json!({"boot_id": "boot", "mode": "native", "native_identity": identity, "native_manifest_sha256": manifest_sha}),
        identity,
        comparison,
        digests,
        commands: Vec::new(),
        windows: 0,
    };
    let out = base.join("out");
    let options = Options::parse(&strings([
        &util::display(&candidate),
        &util::display(&out),
        "--component",
        "procd",
        "--interface",
        "en0",
        "--stack",
        "native",
        "--native-manifest",
        &util::display(&manifest_path),
        "--host-bundle",
        "/host-tools",
        "--baseline-bundle",
        "/v021",
        "--baseline-label",
        "v021",
        "--reference-root",
        "/stock-root",
        "--guard",
        &util::display(&guard),
        "--sides",
        "stock",
        "candidate",
        "--schedule",
        "two-side-balanced",
        "--repeats",
        "2",
        "--health-guard-root",
        "/tmp/dnsmasq-perf-core",
    ]))
    .unwrap();
    let error = run(&options, &mut device).unwrap_err().to_string();
    assert!(
        error.contains("window failed") && error.contains("fixture guard died"),
        "{error}"
    );
    assert_eq!(device.windows, 1);
    let plan = util::read_json(&out.join("settings.json")).unwrap();
    assert_eq!(plan["reference_root"], json!("/stock-root"));
    assert_eq!(plan["host_bundle"], json!("/host-tools"));
    assert_eq!(plan["native_manifest_sha256"], json!(manifest_sha));
    assert_eq!(
        util::read_json(&out.join("reference-identities.json"))
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        10
    );
    let window = out.join("01-stock");
    assert_eq!(fs::read(window.join("raw/partial.txt")).unwrap(), PARTIAL);
    let result = util::read_json(&window.join("result.json")).unwrap();
    assert!(result["remote_evidence_retained"].is_string());
    assert!(result["failures"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f.as_str().unwrap().contains("fixture guard died")));
    assert!(!device
        .commands
        .iter()
        .any(|command| command.starts_with("rm -rf")));
    assert!(!window.join("COMPLETE").exists());
}

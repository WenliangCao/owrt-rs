//! Device tooling regressions with synthetic hosts; never a router.

use super::*;
use crate::util::TempDir;
use std::cell::RefCell;
use std::rc::Rc;

// ------------------------------------------------------- observe-only window

#[derive(Default, Clone)]
struct Scenario {
    odhcpd: bool,
    migration: bool,
    migrated: bool,
    phase: &'static str,
    fault: Option<&'static str>,
    success: bool,
    omit_system: bool,
    receipt_changed: bool,
    no_remote: bool,
    gate_override: Option<Value>,
}

fn scenario() -> Scenario {
    Scenario { phase: "observe", success: true, ..Default::default() }
}

struct FakeWindow {
    s: Scenario,
    manifest: Value,
    image_hash: String,
    commands: Rc<RefCell<Vec<String>>>,
    config_reads: usize,
    clock: f64,
}

const OLD_BOOT: &str = "11111111-1111-1111-1111-111111111111";
const NEW_BOOT: &str = "22222222-2222-2222-2222-222222222222";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn migration_info() -> Value {
    json!({"system_sha256": "e".repeat(64), "marker_sha256": "f".repeat(64)})
}

impl Window for FakeWindow {
    fn run(&mut self, argv: &[String], _: f64) -> Result<Output> {
        let ok = |text: String| Ok(Output { code: 0, stdout: text.into_bytes(), stderr: Vec::new() });
        if argv[0] == "scp" {
            assert_eq!(self.s.phase, "stage");
            self.commands.borrow_mut().push("scp".into());
            return ok(String::new());
        }
        assert_eq!(argv[0], "ssh");
        let command = argv.last().unwrap().clone();
        self.commands.borrow_mut().push(command.clone());
        assert!(!command.contains("sysupgrade -f") && !command.contains("reboot"), "{command}");
        let output = if command == "cat /proc/sys/kernel/random/boot_id" {
            (if self.s.phase == "observe" { NEW_BOOT } else { OLD_BOOT }).to_owned()
        } else if command == "cat /usr/share/owrt-control-plane/release.json" {
            self.manifest.to_string()
        } else if command.starts_with("set -eu\nsha256sum") {
            let mut names = vec!["procd", "ubusd", "netifd", "rpcd", "logd", "uhttpd", "dnsmasq"];
            if self.s.odhcpd {
                assert!(command.contains("uhttpd odhcpd;"));
                names.push("odhcpd");
            }
            names.iter().map(|name| format!("{name} {DIGEST}")).collect::<Vec<_>>().join("\n")
        } else if let Some(rest) = command.strip_prefix("sha256sum ") {
            let names: Vec<&str> = rest.split_whitespace().collect();
            if names.contains(&"/etc/config/network") {
                self.config_reads += 1;
            }
            let active = self.s.fault.and_then(|fault| match fault.strip_prefix("late-") {
                Some(late) => (self.config_reads >= 2).then_some(late),
                None => Some(fault),
            });
            let mut values: Vec<(String, String)> = names.iter().map(|name| ((*name).to_owned(), DIGEST.to_owned())).collect();
            for (name, value) in &mut values {
                match name.as_str() {
                    "/etc/config/system" => {
                        *value = if self.s.migrated { "e".repeat(64) } else { DIGEST.to_owned() };
                    }
                    "/etc/owrt-log-settings-v1" => {
                        *value = "f".repeat(64);
                        if active == Some("missing-marker") {
                            return Ok(Output { code: 1, stdout: Vec::new(), stderr: b"missing marker".to_vec() });
                        }
                    }
                    "/tmp/owrt-native-image.bin" | "/tmp/owrt-native-config.tar.gz" => *value = self.image_hash.clone(),
                    _ => {}
                }
                let target = match active {
                    Some("network") => "/etc/config/network",
                    Some("system") => "/etc/config/system",
                    Some("protected") => "/etc/shadow",
                    Some("marker") => "/etc/owrt-log-settings-v1",
                    _ => "",
                };
                if name == target {
                    *value = "0".repeat(64);
                }
            }
            values.iter().map(|(name, value)| format!("{value}  {name}")).collect::<Vec<_>>().join("\n")
        } else if command.starts_with("/sbin/sysupgrade -T ") {
            assert_eq!(self.s.phase, "stage");
            "Image check passed".into()
        } else if command == "ubus -S -t 3 call luci getMountPoints" {
            "{\"result\": []}".into()
        } else if command.starts_with("set -eu\nfor s") || command.starts_with("printf %s ")
            || command.starts_with("/bin/sh /root/owrt-native-trial/native_trial_guard.sh confirm ") {
            String::new()
        } else {
            panic!("unhandled SSH command: {command}");
        };
        ok(output)
    }

    fn probe(&mut self, _: &str, _: &str) -> Result<Value> {
        Ok(json!({"boot_id": if self.s.phase == "observe" { NEW_BOOT } else { OLD_BOOT }}))
    }

    fn dnsmasq_runtime(&mut self, _: &[String], _: &str, _: &str, _: &Path) -> Result<Vec<Value>> {
        Ok(vec![json!({"sha256": DIGEST})])
    }

    fn monotonic(&mut self) -> f64 {
        let now = self.clock;
        self.clock += 100.0;
        now
    }

    fn sleep(&mut self, _: f64) {}

    fn spawn_upgrade(&mut self, _: &[String], _: &Path) -> Result<std::process::Child> {
        panic!("fixture attempted to launch an upgrade");
    }

    fn driver_sha256(&self) -> Result<String> {
        Ok("d".repeat(64))
    }
}

fn exercise(s: Scenario) {
    let temp = TempDir::new("window");
    let base = fs::canonicalize(temp.path()).unwrap();
    let mut paths: Vec<(String, String)> = ["procd", "ubusd", "netifd", "rpcd", "logd", "uci", "fw4"]
        .iter().map(|name| ((*name).to_owned(), format!("/sbin/{name}"))).collect();
    paths.extend([("httpd".into(), "/usr/sbin/uhttpd".into()), ("dnsmasq".into(), "/usr/sbin/dnsmasq".into()),
                  ("reload-config".into(), "/sbin/reload_config".into())]);
    if s.odhcpd {
        paths.push(("odhcpd".into(), "/usr/sbin/odhcpd".into()));
    }
    let components: Map<String, Value> = paths.iter()
        .map(|(name, path)| (name.clone(), json!({"path": path, "rust_sha256": DIGEST, "stock_sha256": "b".repeat(64)}))).collect();
    let integration: Map<String, Value> = ["/etc/init.d/dnsmasq", "/usr/share/acl.d/dnsmasq_acl.json"].iter()
        .map(|path| ((*path).to_owned(), json!({"path": path, "replacement_sha256": DIGEST}))).collect();
    let manifest = json!({"deployment_layout": if s.odhcpd { "native-eleven" } else { "native-ten" }, "source_commit": "a".repeat(40),
                          "components": components, "integration_files": integration});
    for name in ["image.bin", "trial-config.tar.gz", "guard-evidence.tar.gz"] {
        fs::write(base.join(name), "fixture").unwrap();
    }
    let image_hash = sha(&base.join("image.bin")).unwrap();
    fs::write(base.join("manifest.json"), manifest.to_string()).unwrap();
    let mut gate = json!({"ready_for_staging": true, "rollback_source_commit": "b".repeat(40), "ujail_sha256": "c".repeat(64),
                          "previous_boot_id": OLD_BOOT, "image_path": util::display(&base.join("image.bin")),
                          "manifest_path": util::display(&base.join("manifest.json")), "guard_evidence_sha256": image_hash,
                          "backup_sha256": {}});
    if s.migration {
        gate["log_settings_migration"] = s.gate_override.clone().unwrap_or_else(migration_info);
    }
    fs::write(base.join("recovery-gate.json"), gate.to_string()).unwrap();
    fs::write(base.join("trial-config.tar.json"), json!({"image": {"sha256": image_hash}, "archive_sha256": image_hash,
                                                         "token": "private-token", "payload_sha256": {"root/fixture": DIGEST}}).to_string()).unwrap();
    let mut ready = json!({"sysupgrade_test_passed": true, "driver_sha256": "d".repeat(64), "image_sha256": image_hash, "config_sha256": image_hash});
    if s.migration {
        ready["log_settings_migration"] = migration_info();
        if s.receipt_changed {
            ready["log_settings_migration"]["marker_sha256"] = json!("0".repeat(64));
        }
    }
    fs::write(base.join("stage-ready.json"), ready.to_string()).unwrap();
    let mut configurations: Vec<String> = vec!["/etc/config/network".into(), "/etc/config/system".into()];
    configurations.extend((0..17).map(|i| format!("/etc/config/fixture{i}")));
    if s.omit_system {
        configurations.retain(|path| path != "/etc/config/system");
    }
    let mut protected = vec!["/etc/shadow".to_owned()];
    protected.extend((0..11).map(|i| format!("/etc/protected-fixture{i}")));
    for (name, entries) in [("config-before.sha256", &configurations), ("protected-before.sha256", &protected)] {
        fs::write(base.join(name), entries.iter().map(|path| format!("{DIGEST}  {path}\n")).collect::<String>()).unwrap();
    }
    let commands = Rc::new(RefCell::new(Vec::new()));
    let mut window = FakeWindow { s: s.clone(), manifest, image_hash, commands: commands.clone(), config_reads: 0, clock: 0.0 };
    let args = WindowArgs { phase: s.phase.into(), directory: base.clone(), host: "openwrt".into(), interface: "en0".into(),
                            previous_boot_id: Some(OLD_BOOT.into()), label: "normal-reboot".into() };
    let outcome = deploy_window(&args, &mut window);
    let succeeded = matches!(outcome, Ok(0));
    assert_eq!(succeeded, s.success, "{:?}", outcome.as_ref().err().map(ToString::to_string));
    let commands = commands.borrow();
    let confirms = commands.iter().filter(|c| c.contains(" confirm private-token ")).count();
    if s.no_remote {
        assert!(commands.is_empty());
    }
    let result_path = base.join("result-normal-reboot.json");
    if s.success && s.phase == "observe" {
        let result = util::read_json(&result_path).unwrap();
        assert_eq!(result["boot_id"], NEW_BOOT);
        assert!(result["continuous_client_health_s"].as_f64().unwrap() >= 180.0);
        assert_eq!(confirms, 1);
        assert_eq!(window.config_reads, 2);
        if s.migration {
            assert_eq!(result["log_settings_migration"], migration_info());
            assert_eq!(commands.iter().filter(|c| c.contains("/etc/owrt-log-settings-v1")).count(), 2);
        }
    } else if s.success && s.phase == "stage" {
        let staged = util::read_json(&base.join("stage-ready.json")).unwrap();
        assert_eq!(staged["log_settings_migration"], migration_info());
        assert_eq!(window.config_reads, 1);
        assert!(!commands.iter().any(|c| c.contains("/etc/owrt-log-settings-v1")));
    } else {
        assert_eq!(confirms, 0);
        assert!(!result_path.exists());
        if s.phase != "observe" {
            assert!(!commands.iter().any(|c| c == "scp"));
        }
    }
    if s.fault.is_some_and(|f| f.starts_with("late-")) {
        let events = util::read_text(&base.join("window-normal-reboot.jsonl")).unwrap();
        assert!(events.lines().any(|line| serde_json::from_str::<Value>(line).unwrap()["event"] == "health_pass"),
                "never reached the healthy initial snapshot");
    }
    assert!(!base.join("ACTIVATION_STARTED").exists());
}

#[test]
fn observe_confirms_new_boot_without_flash_or_reboot() {
    exercise(scenario());
}

#[test]
fn eleven_observation_also_checks_live_odhcpd() {
    exercise(Scenario { odhcpd: true, ..scenario() });
}

#[test]
fn migrated_system_and_marker_confirm_only_after_boot() {
    exercise(Scenario { migration: true, migrated: true, ..scenario() });
}

#[test]
fn migration_does_not_accept_old_system_after_boot() {
    exercise(Scenario { migration: true, success: false, ..scenario() });
}

#[test]
fn without_migration_new_system_is_still_rejected() {
    exercise(Scenario { migrated: true, success: false, ..scenario() });
}

#[test]
fn migration_keeps_other_configurations_and_protected_files_strict() {
    for fault in ["network", "protected", "system", "marker", "missing-marker"] {
        exercise(Scenario { migration: true, migrated: true, fault: Some(fault), success: false, ..scenario() });
    }
}

#[test]
fn final_confirmation_rechecks_both_migration_fingerprints() {
    for fault in ["late-system", "late-marker", "late-network", "late-protected"] {
        exercise(Scenario { migration: true, migrated: true, fault: Some(fault), success: false, ..scenario() });
    }
}

#[test]
fn stage_and_activate_never_accept_postboot_configurations() {
    for phase in ["stage", "activate"] {
        exercise(Scenario { migration: true, migrated: true, phase, success: false, ..scenario() });
    }
    exercise(Scenario { migration: true, phase: "stage", ..scenario() });
}

#[test]
fn migration_schema_is_fixed_and_checked_before_remote_access() {
    let valid = migration_info();
    let with = |key: &str, value: Value| { let mut v = valid.clone(); v[key] = value; v };
    for value in [Value::Null, json!({}), json!([]), json!({"system_sha256": "e".repeat(64)}), with("path", json!("/etc/config/network")),
                  with("system_sha256", json!("E".repeat(64))), with("marker_sha256", json!("short")), with("marker_sha256", json!(1))] {
        exercise(Scenario { migration: true, gate_override: Some(value), success: false, no_remote: true, ..scenario() });
    }
}

#[test]
fn migration_requires_system_in_original_configuration_inventory() {
    exercise(Scenario { migration: true, migrated: true, omit_system: true, success: false, ..scenario() });
}

#[test]
fn stage_receipt_binds_migration_expectations() {
    for phase in ["activate", "observe"] {
        exercise(Scenario { migration: true, migrated: phase == "observe", phase, receipt_changed: true, success: false, ..scenario() });
    }
}

// ------------------------------------------------------ dnsmasq runtime proof

fn collect(count: u64, fault: Option<&str>) -> Result<Vec<Value>> {
    let (digest, ujail) = ("a".repeat(64), "b".repeat(64));
    let instances: Map<String, Value> = (1..=count).map(|n| (n.to_string(), json!({"running": true, "jail": {"name": "dnsmasq"},
        "pid": 40 + n, "command": ["/usr/sbin/dnsmasq", "-C", format!("/var/etc/dnsmasq.{n}")]}))).collect();
    let stat = |pid: u64, parent: u64, start: u64| {
        let mut fields = vec!["S".to_owned(), parent.to_string()];
        fields.extend(std::iter::repeat_n("0".to_owned(), 17));
        fields.push(start.to_string());
        format!("{pid} (process name) {}\n", fields.join(" "))
    };
    let pid_re = Regex::new(r"(?m)^pid=(\d+)$").unwrap();
    let mut remote = |command: &str, _: f64| -> Result<String> {
        if command.starts_with("ubus ") {
            return Ok(json!({"dnsmasq": {"instances": instances}}).to_string());
        }
        if command.contains("for process in /proc/") {
            let total = if fault == Some("missing-instance") { count - 1 } else { count };
            return Ok((1..=total).map(|n| format!("{} {digest}", 100 + n)).collect::<Vec<_>>().join("\n"));
        }
        let pid: u64 = pid_re.captures(command).unwrap()[1].parse().unwrap();
        let (number, parent) = (pid - 100, pid - 60);
        let mut argv: Vec<String> = string_list(&instances[&number.to_string()]["command"]).unwrap();
        if fault == Some("wrong-argv") {
            *argv.last_mut().unwrap() = "/unrelated.conf".into();
        }
        let fields = [stat(pid, parent, 900), "/host/fixture/usr/sbin/dnsmasq\n".into(), format!("{digest} /proc/{pid}/exe\n"),
                      argv.join("\0") + "\0", format!("Name:\tdnsmasq\nPPid:\t{parent}\n"), stat(parent, 1, 800), "/sbin/ujail\n".into(),
                      format!("{} /proc/{parent}/exe\n", if fault == Some("wrong-parent") { "c".repeat(64) } else { ujail.clone() }),
                      "/sbin/ujail\0".into(), stat(parent, 1, 800), stat(pid, parent, if fault == Some("reused-pid") { 901 } else { 900 }),
                      format!("{digest} /proc/{pid}/exe\n")];
        Ok(fields.join("\x1c"))
    };
    let temp = TempDir::new("runtime");
    let path = temp.path().join("runtime.jsonl");
    let result = dnsmasq_runtime(&mut remote, &digest, &ujail, &path);
    let passed = serde_json::from_str::<Value>(&util::read_text(&path).unwrap()).unwrap()["passed"].clone();
    assert_eq!(passed, json!(result.is_ok()));
    result
}

#[test]
fn jail_path_does_not_replace_executable_identity() {
    let rows = collect(1, None).unwrap();
    assert_eq!(rows[0]["exe"], "/host/fixture/usr/sbin/dnsmasq");
    assert_eq!(rows[0]["parent_pid"], 41);
}

#[test]
fn every_dnsmasq_instance_is_verified() {
    let rows = collect(2, None).unwrap();
    assert_eq!(rows.iter().map(|r| r["instance"].as_str().unwrap()).collect::<BTreeSet<_>>(), ["1", "2"].into());
    assert!(collect(2, Some("missing-instance")).is_err());
}

#[test]
fn wrong_parent_argv_and_reused_pid_fail_closed() {
    for fault in ["wrong-parent", "wrong-argv", "reused-pid"] {
        assert!(collect(1, Some(fault)).is_err(), "{fault}");
    }
}

// ----------------------------------------------------- production probe

struct FakeProbe {
    manifest: Value,
    release: Value,
    instances: Value,
    rows: Vec<[u64; 3]>,
    digests: Vec<String>,
    snapshots: usize,
    fault: Option<&'static str>,
    answers: Vec<String>,
    https: Vec<Vec<String>>,
    https_result: (i32, &'static [u8]),
}

fn fake_probe() -> FakeProbe {
    let components: Map<String, Value> = NATIVE_PATHS.iter().enumerate().map(|(index, (name, path))| ((*name).to_owned(),
        json!({"path": path, "rust_sha256": format!("{:064x}", index + 1), "stock_sha256": "b".repeat(64)}))).collect();
    let manifest = json!({"deployment_layout": "native-ten", "source_commit": "a".repeat(40), "components": components});
    let mut release = manifest.clone();
    release["layout"] = json!("native-ten");
    let mut fake = FakeProbe { manifest, release, instances: json!({"cfg": {"running": true, "jail": {"name": "dnsmasq"}, "pid": 40,
                                                                             "command": ["/usr/sbin/dnsmasq", "-C", "/private/config"]}}),
                               rows: Vec::new(), digests: Vec::new(), snapshots: 0, fault: None, answers: Vec::new(), https: Vec::new(),
                               https_result: (0, b"<title>Example Domain</title>") };
    for (number, name) in ["procd", "ubusd", "netifd", "rpcd", "logd", "httpd"].iter().enumerate() {
        let number = number as u64 + 1;
        let pid = if *name == "procd" { 1 } else { 10 + number };
        fake.push(pid, if pid == 1 { 0 } else { 1 }, 100 + number, fake.digest(name));
    }
    fake.push(40, 1, 400, STOCK_UJAIL_SHA256.into());
    let dns = fake.digest("dnsmasq");
    fake.push(41, 40, 410, dns);
    fake
}

impl FakeProbe {
    fn digest(&self, name: &str) -> String {
        self.manifest["components"][name]["rust_sha256"].as_str().unwrap().to_owned()
    }

    fn push(&mut self, pid: u64, parent: u64, start: u64, digest: String) {
        self.rows.push([pid, parent, start]);
        self.digests.push(digest);
    }
}

fn shell_words(command: &str) -> Vec<String> {
    command.split_whitespace().map(|word| word.trim_matches('\'').to_owned()).collect()
}

impl ProbeHost for FakeProbe {
    fn ssh(&mut self, host: &str, command: &str, _: f64) -> Result<String> {
        assert_eq!(host, "fixture-host");
        assert!(!command.contains("stack-switch") && !command.contains("native_trial_guard"));
        if command.starts_with("sha256sum ") {
            let mut hashes = BTreeMap::new();
            for item in self.manifest["components"].as_object().unwrap().values() {
                for prefix in ["", "/rom"] {
                    hashes.insert(format!("{prefix}{}", item["path"].as_str().unwrap()), item["rust_sha256"].as_str().unwrap().to_owned());
                }
            }
            for prefix in ["", "/rom"] {
                hashes.insert(format!("{prefix}/sbin/ujail"), STOCK_UJAIL_SHA256.to_owned());
            }
            if self.fault == Some("installed") {
                hashes.insert("/sbin/procd".into(), "f".repeat(64));
            }
            return Ok(shell_words(command)[1..].iter().map(|path| format!("{}  {path}", hashes[path])).collect::<Vec<_>>().join("\n"));
        }
        if command.starts_with("cat /usr/share/") {
            return Ok(self.release.to_string());
        }
        if command.starts_with("ubus ") {
            return Ok(json!({"dnsmasq": {"instances": self.instances}}).to_string());
        }
        if command.starts_with("set -eu\nfor process") {
            self.snapshots += 1;
            let mut rows = self.rows.clone();
            if self.fault == Some("reused") && self.snapshots == 2 {
                rows.last_mut().unwrap()[2] += 1;
            }
            return Ok(rows.iter().zip(&self.digests).map(|(r, d)| format!("{} {} {} {d}", r[0], r[1], r[2])).collect::<Vec<_>>().join("\n"));
        }
        if command == "cat /proc/41/cmdline" {
            return Ok(if self.fault == Some("argv") { "wrong\0".into() } else {
                string_list(&self.instances["cfg"]["command"]).unwrap().join("\0") + "\0"
            });
        }
        panic!("unexpected native read: {command}");
    }

    fn run(&mut self, argv: &[String], _: f64) -> Result<String> {
        assert_eq!(argv[0], "dig");
        assert!(argv.contains(&"+tcp".to_owned()));
        Ok(if self.answers.is_empty() { String::new() } else { self.answers.remove(0) })
    }

    fn fetch(&mut self, argv: &[String], _: f64) -> Result<Output> {
        self.https.push(argv.to_vec());
        Ok(Output { code: self.https_result.0, stdout: self.https_result.1.to_vec(), stderr: Vec::new() })
    }
}

fn identity(fake: &mut FakeProbe) -> Result<String> {
    let manifest = fake.manifest.clone();
    native_identity(fake, "fixture-host", &manifest)
}

#[test]
fn eleven_manifest_requires_exact_odhcpd_path_and_complete_set() {
    let mut manifest = fake_probe().manifest;
    manifest["deployment_layout"] = json!("native-eleven");
    manifest["components"]["odhcpd"] = json!({"path": "/usr/sbin/odhcpd", "rust_sha256": "c".repeat(64), "stock_sha256": "d".repeat(64)});
    let temp = TempDir::new("manifest");
    let path = temp.path().join("manifest.json");
    fs::write(&path, manifest.to_string()).unwrap();
    assert_eq!(load_native_manifest(&path).unwrap().0["components"].as_object().unwrap().len(), 11);
    for bad in ["wrong-path", "missing", "old-layout", "unknown-layout"] {
        let mut changed = manifest.clone();
        match bad {
            "wrong-path" => changed["components"]["odhcpd"]["path"] = json!("/sbin/odhcpd"),
            "missing" => { changed["components"].as_object_mut().unwrap().shift_remove("odhcpd"); }
            "old-layout" => changed["deployment_layout"] = json!("native-ten"),
            _ => changed["deployment_layout"] = json!("native-twelve"),
        }
        fs::write(&path, changed.to_string()).unwrap();
        assert!(load_native_manifest(&path).is_err(), "{bad}");
    }
}

#[test]
fn client_egress_requires_both_families_on_the_lan() {
    let mut fake = fake_probe();
    fake.answers = vec!["example.com. 60 IN A 192.0.2.1".into(), "example.com. 60 IN AAAA 2001:db8::1".into()];
    let result = client_egress(&mut fake, "en0", "192.168.1.100", true).unwrap();
    assert!(result.values().all(|v| v != &json!(false)));
    assert_eq!(result.len(), 5);
    assert_eq!(result["client_dns_transport"], "tcp");
    for (family, argv) in ["-4", "-6"].iter().zip(&fake.https) {
        assert!(argv.contains(&(*family).to_owned()));
        let at = |flag: &str| argv[argv.iter().position(|a| a == flag).unwrap() + 1].clone();
        assert_eq!((at("--interface"), at("--noproxy")), ("en0".into(), "*".into()));
        assert!(!argv.contains(&"-k".to_owned()));
    }
}

#[test]
fn client_egress_rejects_missing_dns_and_false_https_success() {
    let mut fake = fake_probe();
    assert!(client_egress(&mut fake, "en0", "192.168.1.100", false).unwrap_err().to_string().contains("DNS answer"));
    for result in [(7, &b"Example Domain"[..]), (0, &b"captive portal"[..])] {
        let mut fake = fake_probe();
        fake.answers = vec!["example.com. 60 IN A 192.0.2.1".into()];
        fake.https_result = result;
        assert!(client_egress(&mut fake, "en0", "192.168.1.100", false).unwrap_err().to_string().contains("HTTPS"));
    }
}

#[test]
fn native_rows_bind_ten_components_and_ignore_isolated_names() {
    let mut fake = fake_probe();
    // Same executable bytes in isolated siblings are not production.
    let (rpcd, dns) = (fake.digest("rpcd"), fake.digest("dnsmasq"));
    fake.push(99, 98, 900, rpcd);
    fake.push(101, 100, 1000, dns);
    let text = identity(&mut fake).unwrap();
    let rows: Vec<Vec<&str>> = text.lines().map(|line| line.split_whitespace().collect()).collect();
    assert_eq!(rows.iter().map(|r| r[0]).collect::<BTreeSet<_>>(), NATIVE_PATHS.iter().map(|(n, _)| *n).collect());
    assert_eq!(rows.len(), 10);
    assert_eq!(rows.iter().find(|r| r[0] == "procd").unwrap()[1..3], ["1", "101"]);
    assert_eq!(rows.iter().find(|r| r[0] == "dnsmasq").unwrap()[1..3], ["41", "410"]);
    for row in &rows {
        if matches!(row[0], "uci" | "fw4" | "reload-config") {
            assert_eq!(row[1..3], ["-", "-"]);
        }
    }
    assert_eq!(fake.snapshots, 2);
}

#[test]
fn wrong_installed_release_argv_and_reused_pid_fail() {
    for fault in ["installed", "argv", "reused"] {
        let mut fake = fake_probe();
        fake.fault = Some(fault);
        assert!(identity(&mut fake).is_err(), "{fault}");
    }
    let mut fake = fake_probe();
    fake.release["source_commit"] = json!("c".repeat(40));
    assert!(identity(&mut fake).unwrap_err().to_string().contains("release"));
}

#[test]
fn duplicate_production_daemon_and_wrong_dns_parent_fail() {
    let mut fake = fake_probe();
    let rpcd = fake.digest("rpcd");
    fake.push(22, 1, 222, rpcd);
    assert!(identity(&mut fake).unwrap_err().to_string().contains("one production process"));
    let mut fake = fake_probe();
    let index = fake.digests.len() - 2;
    fake.digests[index] = "f".repeat(64);
    assert!(identity(&mut fake).unwrap_err().to_string().contains("production ujail"));
}

#[test]
fn two_dns_children_are_not_silently_picked() {
    let mut fake = fake_probe();
    let dns = fake.digest("dnsmasq");
    fake.push(42, 40, 420, dns);
    assert!(identity(&mut fake).unwrap_err().to_string().contains("one DNS child"));
}

#[test]
fn local_native_manifest_requires_exact_paths_and_components() {
    let mut manifest = fake_probe().manifest;
    let temp = TempDir::new("manifest");
    let path = temp.path().join("manifest.json");
    fs::write(&path, manifest.to_string()).unwrap();
    let (loaded, digest) = load_native_manifest(&path).unwrap();
    assert_eq!(loaded, manifest);
    assert_eq!(digest, sha(&path).unwrap());
    manifest["components"].as_object_mut().unwrap().shift_remove("dnsmasq");
    fs::write(&path, manifest.to_string()).unwrap();
    assert!(load_native_manifest(&path).unwrap_err().to_string().contains("component set differs"));
}

// --------------------------------------------------------- trial backups

fn member(name: &str, kind: tar::EntryType) -> MemberInfo {
    MemberInfo { name: name.into(), kind }
}

fn reserved() -> Vec<String> {
    strings(["root/owrt-native-trial", "etc/init.d/owrt-native-trial", "etc/rc.d/S01owrt-native-trial", "root/owrt-native-rollback-receipt"])
}

fn reject(entries: &[MemberInfo]) {
    assert!(validate_members(entries, &reserved()).is_err());
}

use tar::EntryType::{Char, Directory, Link, Regular, Symlink};

#[test]
fn regular_config_and_unrelated_symlink() {
    validate_members(&[member("etc/config/network", Regular), member("etc/localtime", Symlink)], &reserved()).unwrap();
}

#[test]
fn reserved_directory_and_descendant() {
    reject(&[member("root/owrt-native-trial", Directory)]);
    reject(&[member("root/owrt-native-trial/armed", Regular)]);
}

#[test]
fn payload_ancestor_symlink() {
    reject(&[member("root", Symlink)]);
    reject(&[member("etc/init.d", Symlink)]);
}

#[test]
fn original_member_ancestor_symlink() {
    reject(&[member("etc/config", Symlink), member("etc/config/network", Regular)]);
}

#[test]
fn hardlink_and_device_rejected() {
    reject(&[member("etc/config/a", Link)]);
    reject(&[member("dev/unsafe", Char)]);
}

#[test]
fn duplicate_and_traversal() {
    reject(&[member("etc/config/a", Regular), member("/etc/config/a", Regular)]);
    reject(&[member("etc/../root/a", Regular)]);
    reject(&[member("etc/./config/a", Regular)]);
}

#[test]
fn member_list_injection() {
    reject(&[member("etc/config/a\nroot/other", Regular)]);
    reject(&[member("--checkpoint-action=exec=sh", Regular)]);
}

#[test]
fn old_layered_flag_rejected() {
    reject(&[member("etc/owrt-dnsmasq.boot-enable", Regular)]);
}

#[test]
fn backup_cannot_override_candidate_integration() {
    assert!(validate_members(&[member("etc/init.d/dnsmasq", Regular)], &strings(["etc/init.d/dnsmasq"])).is_err());
}

#[test]
fn trial_archive_preserves_backup_and_adds_exact_guard_payload() {
    let temp = TempDir::new("trial");
    let root = temp.path();
    // Synthetic release, recovery files and rollback image.
    let rootfs = root.join("rootfs");
    let mut components = Map::new();
    for (name, path) in NATIVE_PATHS {
        let recovery = format!("/usr/libexec/owrt-stock{path}");
        let file = rootfs.join(recovery.trim_start_matches('/'));
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, format!("stock {name}")).unwrap();
        components.insert(name.into(), json!({"path": path, "recovery_path": recovery, "stock_sha256": sha(&file).unwrap()}));
    }
    let mut integration = Map::new();
    for path in ["/etc/init.d/dnsmasq", "/usr/share/acl.d/dnsmasq_acl.json"] {
        let recovery = format!("/usr/libexec/owrt-stock{path}");
        let file = rootfs.join(recovery.trim_start_matches('/'));
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, format!("stock {path}")).unwrap();
        integration.insert(path.trim_start_matches('/').into(), json!({"path": path, "recovery_path": recovery, "stock_sha256": sha(&file).unwrap()}));
    }
    let manifest = json!({"deployment_layout": "native-ten", "source_commit": "a".repeat(40), "image": {"sha256": "i".repeat(64)},
                          "components": components, "integration_files": integration});
    let metadata = rootfs.join("usr/share/owrt-control-plane");
    fs::create_dir_all(&metadata).unwrap();
    util::write_json(&metadata.join("release.json"), &manifest).unwrap();
    let stock: String = components.values().chain(integration.values())
        .map(|c| format!("{}  {}\n", c["stock_sha256"].as_str().unwrap(), c["recovery_path"].as_str().unwrap())).collect();
    fs::write(metadata.join("stock.sha256"), stock).unwrap();
    fs::create_dir_all(rootfs.join("usr/sbin")).unwrap();
    fs::write(rootfs.join("usr/sbin/owrt-recover-c"), "recover").unwrap();
    util::write_json(&root.join("manifest.json"), &manifest).unwrap();
    fs::write(root.join("bounded"), "#!/bin/sh\n").unwrap();
    fs::write(root.join("rollback.bin"), "rollback image").unwrap();
    // A backup with a file, a directory and a symlink, owned by root.
    let config = root.join("config.tar.gz");
    {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(fs::File::create(&config).unwrap(), flate2::Compression::default()));
        let new_header = || { let mut h = tar::Header::new_gnu(); h.set_uid(0); h.set_gid(0); h.set_mtime(1_700_000_000); h };
        let mut header = new_header();
        header.set_entry_type(Directory);
        header.set_mode(0o755);
        header.set_size(0);
        builder.append_data(&mut header, "etc/config/", std::io::empty()).unwrap();
        let mut header = new_header();
        header.set_mode(0o600);
        header.set_uid(0);
        header.set_size(9);
        builder.append_data(&mut header, "etc/config/network", &b"lan conf\n"[..]).unwrap();
        let mut header = new_header();
        header.set_entry_type(Symlink);
        header.set_mode(0o777);
        header.set_size(0);
        builder.append_link(&mut header, "etc/localtime", "/tmp/localtime").unwrap();
        builder.into_inner().unwrap().finish().unwrap();
    }
    let output = root.join("trial-config.tar.gz");
    let args = TrialArgs { config: config.clone(), manifest: root.join("manifest.json"), bounded: root.join("bounded"), output: output.clone(),
                           rootfs, rollback_image: root.join("rollback.bin"), rollback_sha256: util::sha256_bytes(b"rollback image"),
                           rollback_version: "v0.2.1".into() };
    let result = trial_prepare(&args).unwrap();
    assert_eq!(result["original_members_preserved"], 3);
    let written: BTreeMap<String, Original> = read_members(&output).unwrap().into_iter().map(|m| (m.name.clone(), m)).collect();
    assert_eq!(written["etc/config/network"].data, b"lan conf\n");
    assert_eq!(written["etc/localtime"].link.as_deref(), Some(Path::new("/tmp/localtime")));
    assert_eq!(written["root/owrt-native-trial/rollback-config.tar.gz"].data, fs::read(&config).unwrap());
    assert_eq!(written["root/owrt-native-trial/armed"].data, format!("{}\n", result["token"].as_str().unwrap()).into_bytes());
    assert_eq!(written["etc/rc.d/S01owrt-native-trial"].link.as_deref(), Some(Path::new("../init.d/owrt-native-trial")));
    let record = util::read_json(&root.join("trial-config.tar.json")).unwrap();
    assert_eq!(record, result);
    assert!(trial_prepare(&args).is_err(), "existing output must not be replaced");
}

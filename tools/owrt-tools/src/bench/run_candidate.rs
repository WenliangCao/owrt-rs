//! `run-candidate`: component experiment with the exact image, frozen
//! baselines and a candidate.
//!
//! Physical use requires the already-authorized recovery gate. The production
//! stack stays active; each subject runs in the existing isolated harness.
//! Every download is checksummed before deleting its exact owned temporary
//! directory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{json, Map, Value};

use super::json::{at, first_word, first_words, key, ks, lines, obj, read};
use super::mt::Random;
use super::stats::py_eq;
use crate::device::{self, quote, ProbeOptions, RealHost};
use crate::util::{self, bail, ensure, Error, Result};

const ORDER: [&str; 12] = [
    "stock",
    "r84",
    "candidate",
    "candidate",
    "r84",
    "stock",
    "r84",
    "stock",
    "candidate",
    "candidate",
    "stock",
    "r84",
];
const TWO_SIDE_BALANCED: [&str; 4] = ["stock", "candidate", "candidate", "stock"];
const COMPONENTS: [&str; 9] = [
    "httpd",
    "rpcd",
    "procd",
    "ubusd",
    "netifd",
    "uci",
    "reload-config",
    "logd",
    "fw4",
];
const SCHEDULES: [&str; 5] = [
    "default",
    "two-side-balanced",
    "three-side-sequential",
    "calibration",
    "random-blocks",
];
const RELOAD_WORKLOADS: [&str; 5] = [
    "first_baseline",
    "unchanged_config",
    "single_change",
    "multi_change",
    "comment_only",
];
const STATIC: [&str; 6] = [
    "static_512_dat",
    "static_16k_dat",
    "static_16k_css",
    "static_image_css",
    "static_64k_dat",
    "static_1m_dat",
];
const ENVIRONMENT: &str = "cat /proc/uptime /proc/loadavg; for f in /sys/class/thermal/thermal_zone*/temp; do test ! -f \"$f\" || cat \"$f\"; done";
const SSH: [&str; 9] = [
    "ssh",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=4",
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=3",
];

fn join(words: &[&str]) -> String {
    words
        .iter()
        .map(|word| quote(word))
        .collect::<Vec<_>>()
        .join(" ")
}

fn sha(path: &Path) -> Result<String> {
    util::sha256_file(path)
}

fn hex12() -> Result<String> {
    Ok(util::uuid4()?.replace('-', "")[..12].to_owned())
}

/// The router, its SSH transport and the local probes; a seam for tests.
pub trait Device {
    /// Remote stdout; fails on a nonzero exit.
    fn ssh(&mut self, command: &str, timeout: f64) -> Result<Vec<u8>>;
    /// Remote stdout (and stderr when `merge`) into `output`; returns the exit code.
    fn ssh_into(&mut self, command: &str, output: &File, merge: bool, timeout: f64) -> Result<i32>;
    fn scp(&mut self, local: &Path, target: &str) -> Result<()>;
    fn probe(&mut self, options: &ProbeOptions) -> Result<Value>;
    fn native_identity(&mut self, host: &str, manifest: &Value) -> Result<String>;
    /// Runs one namespace window under the native health guard.
    fn guarded_window(
        &mut self,
        command: &str,
        root: &str,
        guard: (u64, u64),
        helper: &str,
        receipt: &str,
        log: &File,
    ) -> Result<i32>;
}

fn text(bytes: Vec<u8>) -> Result<String> {
    Ok(String::from_utf8(bytes)?)
}

fn remote_sha(device: &mut dyn Device, path: &str) -> Result<String> {
    let output = text(device.ssh(&format!("sha256sum {path}"), 30.0)?)?;
    output
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| Error::new(format!("no checksum for {path}")))
}

/// Checks only the already-running guard, not all production ELFs per poll.
pub fn health_guard_identity(
    device: &mut dyn Device,
    root: &str,
    expected: Option<(u64, u64)>,
    idle: bool,
) -> Result<(u64, u64)> {
    ensure!(
        Regex::new("^/tmp/dnsmasq-perf-[A-Za-z0-9_-]+$")?.is_match(root),
        "unsafe health guard root"
    );
    let mut command = format!(
        "set -eu
test ! -L {root}
test -d {root}
test \"$(stat -c %u {root})\" = \"$(id -u)\"
test ! -e {root}/STOP
test ! -L {root}/guard.identity
read guard start extra < {root}/guard.identity
case \"$guard:$start\" in *[!0-9:]*|:*|*:) exit 2;; esac
test -z \"$extra\"
test \"$guard\" -gt 1
test \"$start\" -gt 0
test \"$(readlink /proc/$guard/exe)\" = {root}/device_perf_guard
test \"$(awk '{{print $22}}' /proc/$guard/stat)\" = \"$start\"
kill -0 \"$guard\"
"
    );
    if idle {
        command += &format!("test ! -e {root}/active.group\ntest ! -L {root}/active.group\n");
    }
    command += "printf \"%s %s\\n\" \"$guard\" \"$start\"\n";
    let output = text(device.ssh(&command, 30.0)?)?;
    let fields: Vec<&str> = output.split_whitespace().collect();
    let parsed: Vec<u64> = fields
        .iter()
        .filter_map(|value| {
            value
                .parse()
                .ok()
                .filter(|_| value.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect();
    ensure!(
        fields.len() == 2 && parsed.len() == 2 && parsed.iter().all(|&value| value > 0),
        "invalid health guard identity"
    );
    let identity = (parsed[0], parsed[1]);
    ensure!(
        identity.0 > 1 && expected.is_none_or(|expected| expected == identity),
        "health guard PID/start changed"
    );
    Ok(identity)
}

/// The production [`Device`]: OpenSSH, scp and the read-only probes.
pub struct RealDevice {
    host: String,
}

impl RealDevice {
    fn argv(&self, command: &str) -> Vec<String> {
        let mut argv = util::strings(SSH);
        argv.extend([self.host.clone(), command.to_owned()]);
        argv
    }

    fn spawn(&self, command: &str, output: &File, merge: bool) -> Result<Child> {
        let argv = self.argv(command);
        let stderr = if merge {
            Stdio::from(output.try_clone()?)
        } else {
            Stdio::inherit()
        };
        Ok(util::command(&argv, None, None)
            .stdout(output.try_clone()?)
            .stderr(stderr)
            .spawn()?)
    }
}

fn wait_for(child: &mut Child, timeout: Duration) -> Result<Option<i32>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(util::exit_code(status)));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

impl Device for RealDevice {
    fn ssh(&mut self, command: &str, timeout: f64) -> Result<Vec<u8>> {
        let output = util::run_timeout(&self.argv(command), None, util::seconds(timeout))?;
        ensure!(
            output.code == 0,
            "ssh command failed with exit {}: {}",
            output.code,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output.stdout)
    }

    fn ssh_into(&mut self, command: &str, output: &File, merge: bool, timeout: f64) -> Result<i32> {
        let mut child = self.spawn(command, output, merge)?;
        match wait_for(&mut child, util::seconds(timeout))? {
            Some(code) => Ok(code),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("ssh command timed out after {timeout} seconds")
            }
        }
    }

    fn scp(&mut self, local: &Path, target: &str) -> Result<()> {
        util::run_checked(
            &util::strings([
                "scp",
                "-O",
                &util::display(local),
                &format!("{}:{target}", self.host),
            ]),
            None,
            None,
        )
    }

    fn probe(&mut self, options: &ProbeOptions) -> Result<Value> {
        device::probe(&mut RealHost, options)
    }

    fn native_identity(&mut self, host: &str, manifest: &Value) -> Result<String> {
        device::native_identity(&mut RealHost, host, manifest)
    }

    /// Keeps the old harness command intact; stops only this window's owned
    /// group.
    fn guarded_window(
        &mut self,
        command: &str,
        root: &str,
        guard: (u64, u64),
        helper: &str,
        receipt: &str,
        log: &File,
    ) -> Result<i32> {
        health_guard_identity(self, root, Some(guard), true)?;
        let remote = format!(
            "setsid /bin/sh {}",
            join(&[
                helper,
                root,
                "run",
                &guard.0.to_string(),
                &guard.1.to_string(),
                receipt,
                command
            ])
        );
        let mut process: Option<Child> = None;
        let outcome = (|| -> Result<i32> {
            let child = process.insert(self.spawn(&remote, log, true)?);
            let deadline = Instant::now() + Duration::from_secs(660); // Existing 600s lifetime guard plus setup/cleanup.
            loop {
                if let Some(code) = wait_for(child, Duration::from_secs(5))? {
                    health_guard_identity(self, root, Some(guard), false)?;
                    return Ok(code);
                }
                health_guard_identity(self, root, Some(guard), false)?;
                ensure!(
                    Instant::now() < deadline,
                    "native namespace host deadline exceeded"
                );
            }
        })();
        let error = match outcome {
            Ok(code) => return Ok(code),
            Err(error) => error,
        };
        let stop = self
            .ssh(
                &format!("/bin/sh {}", join(&[helper, root, "stop", receipt])),
                30.0,
            )
            .err();
        if let Some(child) = process.as_mut() {
            if matches!(child.try_wait(), Ok(None))
                && wait_for(child, Duration::from_secs(15))?.is_none()
            {
                let _ = child.kill(); // Host SSH only; validated remote stop above owns cleanup.
                let _ = wait_for(child, Duration::from_secs(5));
            }
        }
        let detail = stop
            .map(|stop| format!("; owned stop failed: {stop}"))
            .unwrap_or_default();
        bail!("native health/group failure: {error}{detail}")
    }
}

/// One `--extra-baseline` ELF with its provenance.
fn extra_baseline_records(
    elf_args: &[String],
    evidence_args: &[String],
    baseline_label: &str,
) -> Result<Map<String, Value>> {
    let label_re = Regex::new("^[a-z][a-z0-9_-]*$")?;
    let paths = |items: &[String]| -> Result<Vec<(String, PathBuf)>> {
        let mut result: Vec<(String, PathBuf)> = Vec::new();
        for item in items {
            let (label, path) = item.split_once('=').unwrap_or((item.as_str(), ""));
            ensure!(
                item.contains('=')
                    && label_re.is_match(label)
                    && !["stock", "candidate", "r84", baseline_label].contains(&label),
                "invalid extra baseline label: {label}"
            );
            ensure!(
                !result.iter().any(|entry| entry.0 == label),
                "duplicate extra baseline label: {label}"
            );
            result.push((
                label.to_owned(),
                fs::canonicalize(path).map_err(|error| Error::new(format!("{path}: {error}")))?,
            ));
        }
        Ok(result)
    };
    let (elfs, evidence) = (paths(elf_args)?, paths(evidence_args)?);
    let labels = |entries: &[(String, PathBuf)]| {
        entries
            .iter()
            .map(|entry| entry.0.clone())
            .collect::<BTreeSet<_>>()
    };
    ensure!(
        labels(&elfs) == labels(&evidence),
        "each extra baseline requires exactly one ELF and provenance JSON"
    );
    let mut records = Map::new();
    for (label, path) in &elfs {
        let subject = sha(path)?;
        let evidence_path = &evidence
            .iter()
            .find(|entry| entry.0 == *label)
            .expect("labels match")
            .1;
        let raw = fs::read(evidence_path)?;
        let provenance: Value = serde_json::from_slice(&raw)?;
        ensure!(
            provenance.is_object()
                && provenance.get("subject_sha256").and_then(Value::as_str)
                    == Some(subject.as_str()),
            "extra baseline provenance subject_sha256 mismatch: {label}"
        );
        records.insert(label.clone(), json!({"subject_sha256": subject, "elf_path": util::display(path),
                                             "evidence_path": util::display(evidence_path),
                                             "evidence_sha256": util::sha256_bytes(&raw), "provenance": provenance}));
    }
    Ok(records)
}

// ------------------------------------------------------------ arguments

const VALUE_OPTIONS: [&str; 34] = [
    "--component",
    "--interface",
    "--access",
    "--host",
    "--stack",
    "--native-manifest",
    "--host-bundle",
    "--reference-root",
    "--baseline-bundle",
    "--baseline-label",
    "--cpus",
    "--repeats",
    "--schedule",
    "--seed",
    "--guard",
    "--health-guard-root",
    "--iterations",
    "--exec-resource-probe",
    "--exec-task-probe",
    "--reload-packages",
    "--reload-warmup",
    "--procd-warmup",
    "--fw4-count",
    "--fw4-warmup",
    "--fw4-fixture",
    "--netifd-scale",
    "--netifd-fixture",
    "--netifd-event-contracts",
    "--netifd-warmup",
    "--memory-probe",
    "--rpc-client-probe",
    "--bench",
    "--extra-baseline",
    "--extra-baseline-evidence",
];
const LIST_OPTIONS: [&str; 7] = [
    "--reload-workloads",
    "--httpd-workloads",
    "--rpcd-workloads",
    "--procd-workloads",
    "--fw4-workloads",
    "--netifd-workloads",
    "--sides",
];
const FLAGS: [&str; 3] = ["--resume", "--matrix", "--extended"];

/// argparse-style parsing: value options, `nargs="+"` lists, repeatable
/// `--extra-baseline*` options and flags.
#[derive(Default)]
struct Cli {
    positional: Vec<String>,
    values: BTreeMap<String, Vec<String>>,
    flags: BTreeSet<String>,
}

impl Cli {
    fn parse(raw: &[String]) -> Result<Self> {
        let mut cli = Cli::default();
        let mut index = 0;
        while index < raw.len() {
            let item = &raw[index];
            index += 1;
            if item == "--" {
                cli.positional.extend(raw[index..].iter().cloned());
                break;
            }
            if !item.starts_with("--") {
                cli.positional.push(item.clone());
                continue;
            }
            let (name, inline) = match item.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (item.as_str(), None),
            };
            if FLAGS.contains(&name) && inline.is_none() {
                cli.flags.insert(name.to_owned());
            } else if LIST_OPTIONS.contains(&name) {
                let mut values: Vec<String> = inline.into_iter().collect();
                while index < raw.len() && !raw[index].starts_with('-') {
                    values.push(raw[index].clone());
                    index += 1;
                }
                ensure!(!values.is_empty(), "{name}: expected at least one argument");
                cli.values.insert(name.to_owned(), values);
            } else if VALUE_OPTIONS.contains(&name) {
                let value = match inline {
                    Some(value) => value,
                    None => {
                        ensure!(index < raw.len(), "{name}: expected one argument");
                        index += 1;
                        raw[index - 1].clone()
                    }
                };
                let entry = cli.values.entry(name.to_owned()).or_default();
                if !name.starts_with("--extra-baseline") {
                    entry.clear();
                }
                entry.push(value);
            } else {
                bail!("unrecognized arguments: {item}");
            }
        }
        Ok(cli)
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|values| values.last())
            .map(String::as_str)
    }

    fn list(&self, name: &str) -> Option<Vec<String>> {
        self.values.get(name).cloned()
    }

    fn int(&self, name: &str, default: i64) -> Result<i64> {
        match self.value(name) {
            Some(value) => value
                .trim()
                .parse()
                .map_err(|_| Error::new(format!("{name}: invalid int value: {value:?}"))),
            None => Ok(default),
        }
    }

    fn choice<'a>(&'a self, name: &str, choices: &[&str], default: &'a str) -> Result<&'a str> {
        let value = self.value(name).unwrap_or(default);
        ensure!(
            choices.contains(&value),
            "{name}: invalid choice: {value:?}"
        );
        Ok(value)
    }

    fn path(&self, name: &str) -> Option<PathBuf> {
        self.value(name).map(PathBuf::from)
    }
}

/// Validated run plan; every check here happens before any SSH.
pub struct Options {
    candidate: PathBuf,
    output: PathBuf,
    component: String,
    interface: String,
    access: String,
    host: String,
    stack: String,
    native_manifest_path: Option<PathBuf>,
    native_manifest: Option<(Value, String)>,
    host_bundle: String,
    reference_root: String,
    baseline_bundle: String,
    baseline_label: String,
    extra_baselines: Map<String, Value>,
    cpus: Option<String>,
    repeats: i64,
    schedule: String,
    seed: Option<i64>,
    guard: Option<PathBuf>,
    health_guard_root: Option<String>,
    iterations: i64,
    resume: bool,
    matrix: bool,
    exec_resource_probe: Option<PathBuf>,
    exec_task_probe: Option<PathBuf>,
    reload_packages: i64,
    reload_workloads: Option<Vec<String>>,
    reload_warmup: i64,
    httpd_workloads: Option<Vec<String>>,
    rpcd_workloads: Option<Vec<String>>,
    procd_workloads: Option<Vec<String>>,
    procd_warmup: i64,
    fw4_workloads: Option<Vec<String>>,
    fw4_count: Option<i64>,
    fw4_warmup: i64,
    fw4_fixture: Option<PathBuf>,
    fw4_fixture_hash: Option<String>,
    netifd_scale: i64,
    netifd_fixture: Option<PathBuf>,
    fixture_hashes: Vec<(String, String)>,
    netifd_event_contracts: Option<PathBuf>,
    event_contracts: Vec<(String, Value)>,
    netifd_workloads: Option<Vec<String>>,
    netifd_warmup: i64,
    memory_probe: Option<PathBuf>,
    rpc_client_probe: Option<PathBuf>,
    sides: Vec<String>,
    bench: Option<PathBuf>,
    extended: bool,
}

fn unique(items: &[String]) -> bool {
    items.iter().collect::<BTreeSet<_>>().len() == items.len()
}

fn within(items: &[String], allowed: &BTreeSet<String>) -> bool {
    items.iter().all(|item| allowed.contains(item))
}

fn suffixed(names: &[String], suffixes: &[&str]) -> BTreeSet<String> {
    names
        .iter()
        .flat_map(|name| suffixes.iter().map(move |suffix| format!("{name}{suffix}")))
        .collect()
}

fn owned(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

impl Options {
    pub fn parse(raw: &[String]) -> Result<Self> {
        let cli = Cli::parse(raw)?;
        let [candidate, output] = &cli.positional[..] else {
            bail!("usage: run-candidate CANDIDATE OUTPUT --interface IF [options]")
        };
        let stack = cli
            .choice("--stack", &["rust", "stock", "native"], "rust")?
            .to_owned();
        let interface = cli
            .value("--interface")
            .ok_or_else(|| Error::new("--interface is required"))?
            .to_owned();
        let health_guard_root = cli.value("--health-guard-root").map(str::to_owned);
        let mut reference_root = cli.value("--reference-root").map(str::to_owned);
        let native_manifest_path = cli.path("--native-manifest");
        let guard = cli.path("--guard");
        let mut native_manifest = None;
        if stack == "native" {
            ensure!(native_manifest_path.is_some() && guard.is_some() && reference_root.is_some() && health_guard_root.is_some(),
                    "native requires --native-manifest, --guard, --health-guard-root and an explicit --reference-root");
            ensure!(
                Regex::new("^/tmp/dnsmasq-perf-[A-Za-z0-9_-]+$")?
                    .is_match(health_guard_root.as_deref().unwrap_or_default()),
                "unsafe health guard root"
            );
            ensure!(
                reference_root
                    .as_deref()
                    .unwrap_or_default()
                    .trim_end_matches('/')
                    != "/rom",
                "native /rom contains Rust; --reference-root must be the exact stock rootfs"
            );
            native_manifest = Some(device::load_native_manifest(
                native_manifest_path.as_deref().unwrap_or(Path::new("")),
            )?);
        } else {
            ensure!(
                native_manifest_path.is_none(),
                "--native-manifest requires --stack native"
            );
            ensure!(
                health_guard_root.is_none(),
                "--health-guard-root requires --stack native"
            );
        }
        let reference_root = reference_root.take().unwrap_or_else(|| "/rom".into());
        let host_bundle = cli.value("--host-bundle").unwrap_or("/root/r84").to_owned();
        for path in [&host_bundle, &reference_root] {
            ensure!(
                path.starts_with('/') && !path.contains(['\0', '\n', '\r']),
                "host bundle and reference root must be absolute paths"
            );
        }
        let repeats = cli.int("--repeats", 4)?;
        let schedule = cli.choice("--schedule", &SCHEDULES, "default")?.to_owned();
        let seed = cli
            .value("--seed")
            .map(|_| cli.int("--seed", 0))
            .transpose()?;
        ensure!((1..=64).contains(&repeats), "repeats must be in 1..64");
        ensure!(
            !matches!(schedule.as_str(), "default" | "two-side-balanced")
                || matches!(repeats, 2 | 4),
            "legacy schedules require 2 or 4 repeats"
        );
        ensure!(
            !matches!(schedule.as_str(), "calibration" | "random-blocks") || guard.is_some(),
            "new experiments require a router-side lifetime guard"
        );
        ensure!(
            (schedule == "random-blocks") == seed.is_some(),
            "--seed is required only for random-blocks"
        );
        let baseline_label = cli.value("--baseline-label").unwrap_or("r84").to_owned();
        ensure!(
            Regex::new("^[a-z][a-z0-9_-]*$")?.is_match(&baseline_label)
                && !["stock", "candidate"].contains(&baseline_label.as_str()),
            "invalid baseline label"
        );
        let baseline_bundle = cli
            .value("--baseline-bundle")
            .unwrap_or("/root/r84")
            .to_owned();
        let cpus = cli.value("--cpus").map(str::to_owned);
        ensure!(
            baseline_bundle.starts_with('/')
                && cpus
                    .as_deref()
                    .is_none_or(|cpus| Regex::new("^[0-9,-]+$").is_ok_and(|re| re.is_match(cpus))),
            "baseline path must be absolute; CPU list must be numeric"
        );
        let empty = Vec::new();
        let extra_baselines = extra_baseline_records(
            cli.values.get("--extra-baseline").unwrap_or(&empty),
            cli.values
                .get("--extra-baseline-evidence")
                .unwrap_or(&empty),
            &baseline_label,
        )?;
        let bench = cli.path("--bench");
        let netifd_event_contracts = cli.path("--netifd-event-contracts");
        ensure!(extra_baselines.is_empty() || (schedule == "random-blocks" && bench.is_some() && netifd_event_contracts.is_none()),
                "extra baselines require random-blocks and --bench; netifd event contracts are not supported");
        let iterations = cli.int("--iterations", 10000)?;
        ensure!(iterations > 0, "iterations must be positive");
        let sides = cli
            .list("--sides")
            .unwrap_or_else(|| owned(&["stock", "r84", "candidate"]));
        ensure!(
            sides
                .iter()
                .all(|side| ["stock", "r84", "candidate"].contains(&side.as_str())),
            "--sides: invalid choice"
        );
        if schedule == "calibration" {
            ensure!(
                sides == ["candidate"],
                "calibration requires exactly --sides candidate"
            );
        } else {
            ensure!(
                unique(&sides)
                    && sides.iter().any(|s| s == "stock")
                    && sides.iter().any(|s| s == "candidate"),
                "sides must include stock and candidate, without duplicates"
            );
        }
        let component = cli.choice("--component", &COMPONENTS, "httpd")?.to_owned();
        let memory_probe = cli.path("--memory-probe");
        let matrix = cli.flags.contains("--matrix");
        ensure!(
            component == "httpd" || memory_probe.is_none(),
            "held-connection memory currently requires HTTPD"
        );
        ensure!(
            !matrix
                || [
                    "httpd",
                    "rpcd",
                    "procd",
                    "ubusd",
                    "netifd",
                    "uci",
                    "reload-config"
                ]
                .contains(&component.as_str()),
            "expanded matrix is not defined for this component"
        );
        let exec_resource_probe = cli.path("--exec-resource-probe");
        let exec_task_probe = cli.path("--exec-task-probe");
        ensure!(
            exec_resource_probe.is_none()
                || (["uci", "reload-config"].contains(&component.as_str()) && bench.is_some()),
            "exec resource probe requires UCI/reload-config and --bench"
        );
        ensure!(
            exec_task_probe.is_none() || (component == "reload-config" && bench.is_some()),
            "exec task probe requires reload-config and --bench"
        );
        let reload_workloads = cli.list("--reload-workloads");
        let reload_warmup = cli.int("--reload-warmup", 5)?;
        let reload_packages = cli.int("--reload-packages", 4)?;
        ensure!(
            [4, 24, 64, 128].contains(&reload_packages),
            "--reload-packages: invalid choice"
        );
        if let Some(workloads) = &reload_workloads {
            ensure!(
                workloads
                    .iter()
                    .all(|w| RELOAD_WORKLOADS.contains(&w.as_str())),
                "--reload-workloads: invalid choice"
            );
        }
        if reload_workloads.is_some() || reload_warmup != 5 || reload_packages != 4 {
            ensure!(
                component == "reload-config" && matrix,
                "reload workload/warmup controls require its matrix"
            );
        }
        ensure!(
            (0..=100_000).contains(&reload_warmup),
            "reload warmup must be in 0..100000"
        );
        ensure!(
            reload_workloads.as_deref().is_none_or(unique),
            "duplicate reload workload"
        );
        let netifd_scale = cli.int("--netifd-scale", 32)?;
        ensure!(
            [32, 64, 128].contains(&netifd_scale),
            "--netifd-scale: invalid choice"
        );
        ensure!(
            netifd_scale == 32 || (component == "netifd" && matrix),
            "--netifd-scale requires a netifd matrix"
        );
        let httpd_workloads = cli.list("--httpd-workloads");
        if let Some(workloads) = &httpd_workloads {
            let mut allowed: BTreeSet<String> = owned(&[
                "jsonrpc",
                "jsonrpc_c4",
                "jsonrpc_large",
                "jsonrpc_large_c4",
                "cgi",
                "cgi_c4",
            ])
            .into_iter()
            .collect();
            allowed.extend(suffixed(&owned(&STATIC), &["_c1", "_c4"]));
            ensure!(
                component == "httpd" && matrix && unique(workloads) && within(workloads, &allowed),
                "invalid HTTP matrix workload subset"
            );
        }
        let rpcd_workloads = cli.list("--rpcd-workloads");
        if let Some(workloads) = &rpcd_workloads {
            let lanes = owned(&[
                "uci_configs",
                "uci_get_network",
                "file_stat",
                "session_access",
                "uci_get_64",
                "uci_get_authorized",
                "session_access_granted",
                "file_list",
                "session_access_64",
                "uci_state_network",
                "uci_get_delta",
                "session_access_acl256",
                "luci_version",
                "luci_features",
                "luci_devices",
            ]);
            ensure!(
                component == "rpcd"
                    && matrix
                    && unique(workloads)
                    && within(workloads, &suffixed(&lanes, &["", "_c4"])),
                "invalid RPCD matrix workload subset"
            );
        }
        let procd_workloads = cli.list("--procd-workloads");
        let procd_warmup = cli.int("--procd-warmup", 20)?;
        if procd_workloads.is_some() || procd_warmup != 20 {
            ensure!(
                component == "procd" && matrix,
                "procd workload/warmup controls require its matrix"
            );
        }
        ensure!(
            (0..=100_000).contains(&procd_warmup),
            "procd warmup must be in 0..100000"
        );
        if let Some(workloads) = &procd_workloads {
            let mut allowed = suffixed(
                &owned(&[
                    "system_info",
                    "service_list_32",
                    "service_list_128",
                    "service_list_named_128",
                ]),
                &["", "_c4"],
            );
            allowed.insert("service_list_instance_fields".into());
            ensure!(
                unique(workloads) && within(workloads, &allowed),
                "invalid or duplicate procd workload"
            );
        }
        let fw4_workloads = cli.list("--fw4-workloads");
        if let Some(workloads) = &fw4_workloads {
            ensure!(
                workloads.iter().all(|w| w == "print" || w == "check"),
                "--fw4-workloads: invalid choice"
            );
        }
        let fw4_count = cli
            .value("--fw4-count")
            .map(|_| cli.int("--fw4-count", 0))
            .transpose()?;
        let fw4_warmup = cli.int("--fw4-warmup", 3)?;
        let fw4_fixture = cli.path("--fw4-fixture");
        if fw4_workloads.is_some()
            || fw4_count.is_some()
            || fw4_warmup != 3
            || fw4_fixture.is_some()
        {
            ensure!(component == "fw4", "fw4 controls require --component fw4");
        }
        ensure!(
            fw4_workloads.as_deref().is_none_or(unique),
            "duplicate fw4 workload"
        );
        ensure!(
            fw4_count.is_none_or(|count| count > 0),
            "fw4 count must be positive"
        );
        ensure!(
            (0..=100_000).contains(&fw4_warmup),
            "fw4 warmup must be in 0..100000"
        );
        let mut fw4_fixture_hash = None;
        if let Some(fixture) = &fw4_fixture {
            ensure!(
                bench.is_some(),
                "--fw4-fixture requires --bench for private bundles"
            );
            ensure!(fixture.is_file(), "fw4 fixture must be a regular file");
            fw4_fixture_hash = Some(sha(fixture)?);
        }
        let netifd_workloads = cli.list("--netifd-workloads");
        let netifd_warmup = cli.int("--netifd-warmup", 20)?;
        if netifd_workloads.is_some() || netifd_warmup != 20 {
            ensure!(
                component == "netifd" && matrix,
                "netifd workload/warmup controls require its matrix"
            );
        }
        ensure!(
            (0..=100_000).contains(&netifd_warmup),
            "netifd warmup must be in 0..100000"
        );
        if let Some(workloads) = &netifd_workloads {
            let lanes = vec![
                "interface_dump".into(),
                "lan_status".into(),
                "device_status".into(),
                "wireless_status".into(),
                "device_status_all".into(),
                format!("interface_dump_{netifd_scale}"),
                format!("interface_named_{netifd_scale}"),
            ];
            let mut allowed = suffixed(&lanes, &["", "_c4"]);
            allowed.extend(owned(&["events_static2", "reload_unchanged"]));
            ensure!(
                unique(workloads) && within(workloads, &allowed),
                "invalid or duplicate netifd workload"
            );
        }
        let events = netifd_workloads.as_deref() == Some(&["events_static2".to_owned()][..]);
        ensure!(
            events
                || !netifd_workloads
                    .as_ref()
                    .is_some_and(|w| w.iter().any(|name| name == "events_static2")),
            "events_static2 requires its own fixture and separate run"
        );
        let netifd_fixture = cli.path("--netifd-fixture");
        ensure!(
            events == netifd_event_contracts.is_some()
                && (!events || (bench.is_some() && netifd_fixture.is_none())),
            "event lane requires --bench and --netifd-event-contracts, with no wireless fixture"
        );
        let mut event_contracts = Vec::new();
        if events {
            let directory = netifd_event_contracts.as_deref().unwrap_or(Path::new(""));
            for side in ["stock", baseline_label.as_str(), "candidate"] {
                let path = directory.join(format!("{side}.json"));
                let contract = read(&path)?;
                let steps: BTreeSet<&str> = contract
                    .get("steps")
                    .and_then(Value::as_object)
                    .map(|s| s.keys().map(String::as_str).collect())
                    .unwrap_or_default();
                ensure!(
                    contract.get("schema") == Some(&json!(1))
                        && steps
                            == BTreeSet::from(["lan-down", "lan-up", "wired-down", "wired-up"]),
                    "invalid event contract: {}",
                    util::display(&path)
                );
                let record = json!({"sha256": sha(&path)?, "reference_subject_sha256": key(&contract, "reference_subject_sha256")?});
                match event_contracts
                    .iter_mut()
                    .find(|entry: &&mut (String, Value)| entry.0 == side)
                {
                    Some(entry) => entry.1 = record,
                    None => event_contracts.push((side.to_owned(), record)),
                }
            }
        }
        let mut fixture_hashes = Vec::new();
        if let Some(fixture) = &netifd_fixture {
            ensure!(
                component == "netifd" && matrix && bench.is_some(),
                "--netifd-fixture requires a netifd matrix and --bench for private bundles"
            );
            for name in [
                "wireless",
                "handler-schema.json",
                "mac80211.sh",
                "expected-wireless.json",
            ] {
                fixture_hashes.push((name.to_owned(), sha(&fixture.join(name))?));
            }
        }
        let rpc_client_probe = cli.path("--rpc-client-probe");
        let has_r84 = sides.iter().any(|side| side == "r84");
        ensure!(
            memory_probe.is_none() || !(matrix || has_r84),
            "held-connection memory uses --sides stock candidate without --matrix"
        );
        ensure!(rpc_client_probe.is_none() || !(component != "rpcd" || matrix || memory_probe.is_some() || has_r84),
                "RPC client diagnostics require rpcd, --sides stock candidate, and no other experiment mode");
        ensure!(
            bench.is_none() || (memory_probe.is_none() && rpc_client_probe.is_none()),
            "--bench is not used with diagnostic probes"
        );
        ensure!(
            bench.is_none()
                || !has_r84
                || ["three-side-sequential", "random-blocks"].contains(&schedule.as_str()),
            "--bench with a frozen baseline requires three-side-sequential"
        );
        let extended = cli.flags.contains("--extended");
        ensure!(
            !extended || component == "ubusd",
            "--extended is a ubusd mode"
        );
        ensure!(
            schedule != "two-side-balanced" || sides == ["stock", "candidate"],
            "two-side-balanced requires exactly --sides stock candidate"
        );
        ensure!(
            schedule != "three-side-sequential" || sides == ["stock", "r84", "candidate"],
            "three-side-sequential requires exactly --sides stock r84 candidate"
        );
        ensure!(schedule != "random-blocks" || sides == ["stock", "r84", "candidate"],
                "random-blocks requires base --sides stock r84 candidate; extra baselines are added automatically");
        let resume = cli.flags.contains("--resume");
        let output = PathBuf::from(output);
        ensure!(
            !resume || (output.join("STARTED").exists() && !output.join("COMPLETE").exists()),
            "resume requires an existing, incomplete collection"
        );
        Ok(Options {
            candidate: PathBuf::from(candidate),
            output,
            component,
            interface,
            access: cli
                .choice("--access", &["wired", "wifi"], "wifi")?
                .to_owned(),
            host: cli.value("--host").unwrap_or("openwrt").to_owned(),
            stack,
            native_manifest_path,
            native_manifest,
            host_bundle,
            reference_root,
            baseline_bundle,
            baseline_label,
            extra_baselines,
            cpus,
            repeats,
            schedule,
            seed,
            guard,
            health_guard_root,
            iterations,
            resume,
            matrix,
            exec_resource_probe,
            exec_task_probe,
            reload_packages,
            reload_workloads,
            reload_warmup,
            httpd_workloads,
            rpcd_workloads,
            procd_workloads,
            procd_warmup,
            fw4_workloads,
            fw4_count,
            fw4_warmup,
            fw4_fixture,
            fw4_fixture_hash,
            netifd_scale,
            netifd_fixture,
            fixture_hashes,
            netifd_event_contracts,
            event_contracts,
            netifd_workloads,
            netifd_warmup,
            memory_probe,
            rpc_client_probe,
            sides,
            bench,
            extended,
        })
    }
}

/// The comparison order of every schedule.
fn schedule_order(options: &Options) -> Vec<String> {
    let label = |side: &str| {
        if side == "r84" {
            options.baseline_label.clone()
        } else {
            side.to_owned()
        }
    };
    let repeats = options.repeats as usize;
    match options.schedule.as_str() {
        "calibration" => vec!["candidate".to_owned(); repeats],
        "random-blocks" => {
            let mut rng = Random::new(options.seed.unwrap_or_default());
            let mut population = vec!["stock".to_owned(), options.baseline_label.clone()];
            population.extend(options.extra_baselines.keys().cloned());
            population.push("candidate".to_owned());
            (0..repeats)
                .flat_map(|_| rng.sample(&population, 3 + options.extra_baselines.len()))
                .collect()
        }
        "two-side-balanced" => TWO_SIDE_BALANCED
            .iter()
            .cycle()
            .take(4 * repeats)
            .map(|side| (*side).to_owned())
            .collect(),
        "three-side-sequential" => ["stock", "r84", "candidate"]
            .iter()
            .flat_map(|side| vec![label(side); repeats])
            .collect(),
        _ => ORDER[..(repeats * 3).min(ORDER.len())]
            .iter()
            .filter(|side| options.sides.iter().any(|s| s == *side))
            .map(|side| label(side))
            .collect(),
    }
}

/// Python `tarfile.extractall(filter="data")` for regular files and
/// directories; links, devices and escaping names are refused.
fn extract_data(archive: &Path, target: &Path) -> Result<()> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(File::open(archive)?));
    for entry in tar.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.into_owned();
        ensure!(
            name.components()
                .all(|part| matches!(part, Component::Normal(_) | Component::CurDir)),
            "unsafe archive member {}",
            name.display()
        );
        let destination = target.join(&name);
        match entry.header().entry_type() {
            tar::EntryType::Directory => fs::create_dir_all(&destination)?,
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mode = entry.header().mode()?;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination)?;
                std::io::copy(&mut entry, &mut file)?;
                util::set_mode(&destination, (mode & 0o755) | 0o600)?;
            }
            other => bail!(
                "refused archive member {} of type {other:?}",
                name.display()
            ),
        }
    }
    Ok(())
}

fn split_pair(line: &str) -> Result<(&str, &str)> {
    let (first, rest) = line
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or_else(|| Error::new(format!("invalid checksum row: {line}")))?;
    Ok((first, rest.trim_start()))
}

fn print_event(value: Value) {
    println!("{}", util::line_json(&value));
    let _ = std::io::stdout().flush();
}

struct Run<'a> {
    options: &'a Options,
    device: &'a mut dyn Device,
    out: PathBuf,
}

impl Run<'_> {
    fn ssh(&mut self, command: &str) -> Result<Vec<u8>> {
        self.device.ssh(command, 30.0)
    }

    fn save(&self, name: &str, value: &Value) -> Result<()> {
        fs::write(self.out.join(name), util::pretty_json(value) + "\n")?;
        Ok(())
    }

    fn initial(&self, name: &str, value: &Value) -> Result<()> {
        if self.options.resume {
            ensure!(
                py_eq(&read(&self.out.join(name))?, value),
                "resume settings changed: {name}"
            );
            Ok(())
        } else {
            self.save(name, value)
        }
    }

    fn device_probe(&mut self) -> Result<Value> {
        let options = self.options;
        let health = self.device.probe(&ProbeOptions {
            host: &options.host,
            mode: &options.stack,
            interface: Some(&options.interface),
            native_manifest: options.native_manifest_path.as_deref(),
            host_bundle: &options.host_bundle,
            ..Default::default()
        })?;
        if let Some((_, digest)) = &options.native_manifest {
            ensure!(
                health.get("native_manifest_sha256").and_then(Value::as_str)
                    == Some(digest.as_str()),
                "local native manifest changed"
            );
        }
        Ok(health)
    }

    fn production_identity(&mut self) -> Result<Vec<u8>> {
        match &self.options.native_manifest {
            Some((manifest, _)) => Ok(self
                .device
                .native_identity(&self.options.host, manifest)?
                .into_bytes()),
            None => self.ssh(&format!(
                "/bin/sh {} verify {}",
                quote(&format!("{}/stack-switch.sh", self.options.host_bundle)),
                self.options.stack
            )),
        }
    }

    fn remote_sha(&mut self, path: &str) -> Result<String> {
        remote_sha(self.device, path)
    }
}

fn manifest_sha<'a>(manifest: &'a Value, component: &str, role: &str) -> Result<&'a str> {
    at(manifest, &["components", component, role, "sha256"])?
        .as_str()
        .ok_or_else(|| Error::new("manifest hash is not a string"))
}

fn tool_sha<'a>(manifest: &'a Value, name: &str) -> Result<&'a str> {
    at(manifest, &["tools", name, "sha256"])?
        .as_str()
        .ok_or_else(|| Error::new("tool hash is not a string"))
}

pub fn run(options: &Options, device: &mut dyn Device) -> Result<()> {
    let component = options.component.as_str();
    let binary = if component == "reload-config" {
        "reload_config_rs".to_owned()
    } else {
        format!("{component}-rs")
    };
    if let Some(parent) = options
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    match util::create_private_dir(&options.output) {
        Err(error) if !(options.resume && options.output.is_dir()) => return Err(error),
        _ => {}
    }
    let out = fs::canonicalize(&options.output)?;
    fs::write(out.join("STARTED"), b"")?;
    let mut run = Run {
        options,
        device,
        out: out.clone(),
    };
    let benchmark = util::repo().join("tools/benchmark");
    let script = benchmark.join("isolated.sh");
    let group_script = benchmark.join("owned_group.sh");
    let mut guard_identity = None;
    if let Some(root) = &options.health_guard_root {
        let identity = health_guard_identity(run.device, root, None, true)?;
        guard_identity = Some(identity);
        run.save(&format!("health-guard-binding-{}.json", hex12()?),
                 &json!({"root": root, "pid_start": [identity.0, identity.1], "owned_group_sha256": sha(&group_script)?}))?;
    }
    let current = run.device_probe()?;
    let pre = if options.resume {
        let pre = read(&out.join("health-before.json"))?;
        ensure!(
            py_eq(key(&current, "boot_id")?, key(&pre, "boot_id")?),
            "host rebooted before resume"
        );
        run.save(&format!("resume-health-{}.json", hex12()?), &current)?;
        pre
    } else {
        run.save("health-before.json", &current)?;
        current.clone()
    };
    let boot_id = ks(&pre, "boot_id")?.to_owned();
    let identity = run.production_identity()?;
    if let (Some((_, digest)), Some(path)) =
        (&options.native_manifest, &options.native_manifest_path)
    {
        ensure!(
            ks(&current, "native_identity")?.as_bytes() == identity.as_slice(),
            "native process changed after health probe"
        );
        let raw_manifest = fs::read(path)?;
        ensure!(
            util::sha256_bytes(&raw_manifest) == *digest,
            "native manifest changed"
        );
        if options.resume {
            ensure!(
                fs::read(out.join("native-manifest.json"))? == raw_manifest,
                "native manifest changed before resume"
            );
        } else {
            fs::write(out.join("native-manifest.json"), &raw_manifest)?;
        }
    }
    let config = run.ssh("sha256sum /etc/config/*")?;
    for (name, value) in [
        ("host-running-hashes.txt", &identity),
        ("config-before.sha256", &config),
    ] {
        if options.resume {
            ensure!(
                fs::read(out.join(name))? == *value,
                "host state changed before resume"
            );
        } else {
            fs::write(out.join(name), value)?;
        }
    }
    let manifest: Value = serde_json::from_slice(&run.ssh(&format!(
        "cat {}",
        quote(&format!("{}/manifest.json", options.host_bundle))
    ))?)?;
    let baseline: Value = serde_json::from_slice(&run.ssh(&format!(
        "cat {}",
        quote(&format!("{}/manifest.json", options.baseline_bundle))
    ))?)?;
    if let Some((native, _)) = &options.native_manifest {
        let reference = text(run.ssh(&format!("readlink -f {}", quote(&options.reference_root)))?)?;
        let reference = reference.trim();
        ensure!(
            reference.starts_with('/') && reference != "/rom",
            "native reference resolves to /rom or is missing"
        );
        let mut expected_reference = Map::new();
        for (name, item) in obj(native, "components")? {
            let expected = ks(item, "stock_sha256")?;
            if name != "dnsmasq" {
                ensure!(
                    manifest_sha(&manifest, name, "original")? == expected,
                    "comparison C identity differs from native stock reference"
                );
            }
            expected_reference.insert(
                format!(
                    "{}{}",
                    options.reference_root.trim_end_matches('/'),
                    ks(item, "path")?
                ),
                json!(expected),
            );
        }
        let paths: Vec<String> = expected_reference.keys().map(|path| quote(path)).collect();
        let observed_text = text(run.ssh(&format!("sha256sum {}", paths.join(" ")))?)?;
        let mut observed = Map::new();
        for line in util::splitlines(&observed_text) {
            let (digest, path) = split_pair(line)?;
            observed.insert(path.to_owned(), json!(digest));
        }
        ensure!(
            py_eq(
                &Value::Object(observed),
                &Value::Object(expected_reference.clone())
            ),
            "reference root does not contain exact stock components"
        );
        run.initial(
            "reference-identities.json",
            &Value::Object(expected_reference),
        )?;
    }
    let mut hashes = Map::new();
    hashes.insert(
        "stock".into(),
        json!(manifest_sha(&manifest, component, "original")?),
    );
    hashes.insert(
        options.baseline_label.clone(),
        json!(manifest_sha(&baseline, component, "rust")?),
    );
    hashes.insert("candidate".into(), json!(sha(&options.candidate)?));
    for (label, record) in &options.extra_baselines {
        hashes.insert(label.clone(), key(record, "subject_sha256")?.clone());
    }
    let hash = |side: &str| {
        hashes
            .get(side)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::new(format!("no subject for {side}")))
    };
    for name in ["ns-exec", "owrt-benchmark"] {
        ensure!(
            tool_sha(&baseline, name)? == tool_sha(&manifest, name)?,
            "frozen baseline and host benchmark tools differ"
        );
    }
    let mut tool_hashes = Map::new();
    for name in ["ns-exec", "owrt-benchmark"] {
        tool_hashes.insert(name.into(), json!(tool_sha(&manifest, name)?));
    }
    if let Some(bench) = &options.bench {
        tool_hashes.insert("owrt-benchmark".into(), json!(sha(bench)?));
    }
    run.initial("subjects.json", &Value::Object(hashes.clone()))?;
    run.initial("host-manifest.json", &manifest)?;
    run.initial("baseline-manifest.json", &baseline)?;
    let mut identities = tool_hashes.clone();
    identities.insert("driver".into(), json!(sha(&std::env::current_exe()?)?));
    run.initial("tool-identities.json", &Value::Object(identities))?;
    let order = schedule_order(options);
    run.initial("order.json", &json!(order))?;
    let settings = settings(options, &hashes, &tool_hashes, &group_script)?;
    run.initial("settings.json", &settings)?;
    let harness_sha = sha(&script)?;
    let remote;
    if options.resume {
        let collector = read(&out.join("collector.json"))?;
        remote = ks(&collector, "remote")?.to_owned();
        ensure!(
            Regex::new(&format!(
                "^/tmp/r85-{}-[a-f0-9]{{12}}$",
                regex::escape(component)
            ))?
            .is_match(&remote),
            "invalid resume remote"
        );
        ensure!(
            ks(&collector, "harness_sha256")? == harness_sha,
            "harness changed before resume"
        );
        ensure!(
            run.remote_sha(&format!("{remote}/isolated.sh"))? == harness_sha,
            "remote harness changed before resume"
        );
    } else {
        remote = format!("/tmp/r85-{component}-{}", hex12()?);
        run.ssh(&format!("test ! -e {remote} && mkdir -p {remote}/bundle"))?;
        run.save(
            "collector.json",
            &json!({"remote": remote, "harness_sha256": harness_sha}),
        )?;
    }
    let bundle = format!("{remote}/bundle");
    let group_helper = format!("{remote}/owned_group.sh");
    if options.health_guard_root.is_some() {
        if !options.resume {
            run.device.scp(&group_script, &group_helper)?;
        }
        ensure!(
            Some(run.remote_sha(&group_helper)?.as_str())
                == settings["owned_group_sha256"].as_str(),
            "owned group helper identity mismatch"
        );
    }
    if let Some(guard) = &options.guard {
        if !options.resume {
            run.device
                .scp(&fs::canonicalize(guard)?, &format!("{remote}/guard"))?;
        }
        ensure!(
            Some(run.remote_sha(&format!("{remote}/guard"))?.as_str())
                == settings["guard_sha256"].as_str(),
            "guard identity mismatch"
        );
    }
    // With --bench, use the same uploaded client in every selected bundle.
    // Every historical side gets its own temporary bundle containing its
    // original ELF; historical source bundles remain untouched.
    let has_r84 = options.sides.iter().any(|side| side == "r84");
    let stock_bundle = if options.bench.is_some() {
        format!("{remote}/stock-bundle")
    } else {
        format!("{}/bins", options.baseline_bundle)
    };
    let baseline_bundle =
        (options.bench.is_some() && has_r84).then(|| format!("{remote}/baseline-bundle"));
    let extra_bundles: Vec<(String, String)> = options
        .extra_baselines
        .keys()
        .map(|label| (label.clone(), format!("{remote}/baseline-{label}")))
        .collect();
    if !options.resume {
        if let Some(bench) = &options.bench {
            let mut targets = vec![bundle.clone(), stock_bundle.clone()];
            targets.extend(extra_bundles.iter().map(|entry| entry.1.clone()));
            targets.extend(baseline_bundle.clone());
            let ns_exec = quote(&format!("{}/bins/ns-exec", options.host_bundle));
            let copies: Vec<String> = targets
                .iter()
                .map(|target| format!("cp {ns_exec} {}/", quote(target)))
                .collect();
            let quoted: Vec<String> = targets.iter().map(|target| quote(target)).collect();
            run.ssh(&format!(
                "mkdir -p {} && {}",
                quoted.join(" "),
                copies.join(" && ")
            ))?;
            let bench = fs::canonicalize(bench)?;
            for target in &targets {
                run.device
                    .scp(&bench, &format!("{target}/owrt-benchmark"))?;
            }
            if let Some(baseline_bundle) = &baseline_bundle {
                run.ssh(&format!(
                    "cp {} {}",
                    quote(&format!("{}/bins/{binary}", options.baseline_bundle)),
                    quote(&format!("{baseline_bundle}/{binary}"))
                ))?;
            }
        } else {
            let tools: Vec<String> = ["ns-exec", "owrt-benchmark"]
                .iter()
                .map(|name| quote(&format!("{}/bins/{name}", options.host_bundle)))
                .collect();
            run.ssh(&format!("cp {} {bundle}/", tools.join(" ")))?;
        }
        for (label, target) in &extra_bundles {
            let elf = ks(&options.extra_baselines[label.as_str()], "elf_path")?;
            run.device
                .scp(Path::new(elf), &format!("{target}/{binary}"))?;
        }
        run.device.scp(
            &fs::canonicalize(&options.candidate)?,
            &format!("{bundle}/{binary}"),
        )?;
        run.device.scp(
            &fs::canonicalize(&script)?,
            &format!("{remote}/isolated.sh"),
        )?;
    }
    let mut bundle_targets = vec![bundle.clone(), stock_bundle.clone()];
    bundle_targets.extend(baseline_bundle.clone());
    bundle_targets.extend(extra_bundles.iter().map(|entry| entry.1.clone()));
    for (probe, file, setting) in [
        (
            &options.exec_resource_probe,
            "exec-resource",
            "exec_resource_probe_sha256",
        ),
        (
            &options.exec_task_probe,
            "exec-task-counts",
            "exec_task_probe_sha256",
        ),
    ] {
        let Some(probe) = probe else { continue };
        for target in &bundle_targets {
            if !options.resume {
                run.device
                    .scp(&fs::canonicalize(probe)?, &format!("{target}/{file}"))?;
            }
            ensure!(
                Some(run.remote_sha(&format!("{target}/{file}"))?.as_str())
                    == settings[setting].as_str(),
                "{file} identity mismatch"
            );
        }
    }
    for (probe, file, record, label) in [
        (
            &options.memory_probe,
            "memory-probe",
            "memory-probe.json",
            "memory probe",
        ),
        (
            &options.rpc_client_probe,
            "rpc-client-probe",
            "client-probe.json",
            "RPC client probe",
        ),
    ] {
        let Some(probe) = probe else { continue };
        let digest = sha(probe)?;
        if !options.resume {
            run.device
                .scp(&fs::canonicalize(probe)?, &format!("{bundle}/{file}"))?;
        }
        ensure!(
            run.remote_sha(&format!("{bundle}/{file}"))? == digest,
            "{label} upload checksum mismatch"
        );
        let value = if file == "memory-probe" {
            json!({"sha256": digest})
        } else {
            json!({"sha256": digest, "diagnostic_only": true})
        };
        run.initial(record, &value)?;
    }
    ensure!(
        run.remote_sha(&format!("{remote}/isolated.sh"))? == harness_sha,
        "remote harness identity mismatch"
    );
    if let (Some(fixture), Some(digest)) = (&options.fw4_fixture, &options.fw4_fixture_hash) {
        for target in &bundle_targets {
            let destination = format!("{target}/fw4-firewall");
            if !options.resume {
                run.device.scp(&fs::canonicalize(fixture)?, &destination)?;
            }
            ensure!(
                run.remote_sha(&quote(&destination))? == *digest,
                "fw4 fixture identity mismatch"
            );
        }
    }
    if let Some(fixture) = &options.netifd_fixture {
        for target in &bundle_targets {
            let directory = format!("{target}/netifd-fixture");
            if !options.resume {
                run.ssh(&format!("mkdir {}", quote(&directory)))?;
                for (name, _) in &options.fixture_hashes {
                    run.device.scp(
                        &fs::canonicalize(fixture.join(name))?,
                        &format!("{directory}/{name}"),
                    )?;
                }
                run.ssh(&format!(
                    "chmod 755 {}",
                    quote(&format!("{directory}/mac80211.sh"))
                ))?;
            }
            for (name, digest) in &options.fixture_hashes {
                ensure!(
                    run.remote_sha(&quote(&format!("{directory}/{name}")))? == *digest,
                    "netifd fixture identity mismatch"
                );
            }
        }
    }
    if let Some(contracts) = &options.netifd_event_contracts {
        let mut selections = vec![
            (bundle.clone(), "candidate".to_owned()),
            (stock_bundle.clone(), "stock".to_owned()),
        ];
        if let Some(baseline_bundle) = &baseline_bundle {
            selections.push((baseline_bundle.clone(), options.baseline_label.clone()));
        }
        for (target, side) in selections {
            let destination = format!("{target}/event-contract.json");
            if !options.resume {
                run.device.scp(
                    &fs::canonicalize(contracts.join(format!("{side}.json")))?,
                    &destination,
                )?;
            }
            let expected = options
                .event_contracts
                .iter()
                .find(|entry| entry.0 == side)
                .map(|entry| &entry.1["sha256"]);
            ensure!(
                expected.and_then(Value::as_str)
                    == Some(run.remote_sha(&quote(&destination))?.as_str()),
                "event contract identity mismatch"
            );
        }
    }
    for name in ["ns-exec", "owrt-benchmark"] {
        for target in &bundle_targets {
            ensure!(
                tool_hashes[name].as_str()
                    == Some(run.remote_sha(&format!("{target}/{name}"))?.as_str()),
                "benchmark identity mismatch: {name}"
            );
        }
    }
    ensure!(
        run.remote_sha(&format!("{bundle}/{binary}"))? == hash("candidate")?,
        "candidate upload checksum mismatch"
    );
    if has_r84 {
        let target = baseline_bundle
            .clone()
            .unwrap_or_else(|| stock_bundle.clone());
        ensure!(
            run.remote_sha(&format!("{target}/{binary}"))? == hash(&options.baseline_label)?,
            "baseline upload checksum mismatch"
        );
    }
    for (label, target) in &extra_bundles {
        ensure!(
            run.remote_sha(&format!("{target}/{binary}"))? == hash(label)?,
            "extra baseline upload checksum mismatch: {label}"
        );
    }
    let identity_text = String::from_utf8(identity.clone())?;
    let mut monitors = Vec::new();
    for line in util::splitlines(&identity_text) {
        let field = line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| Error::new("invalid production identity row"))?;
        if field != "-" {
            monitors.push(field);
        }
    }
    let snapshot = format!(
        "{} snapshot {}",
        quote(&format!("{}/bins/owrt-benchmark", options.host_bundle)),
        monitors.join(",")
    );
    for (index, side) in order.iter().enumerate() {
        let index = index + 1;
        let local = out.join(format!("{index:02}-{side}"));
        let raw = local.join("raw");
        if options.resume && local.exists() {
            ensure!(
                local.join("COMPLETE").exists() && raw.join("COMPLETE").exists(),
                "incomplete sample requires explicit recovery or archival before resume: {}",
                util::display(&local)
            );
            ensure!(
                first_word(&raw.join("binary-sha256.txt"))? == hash(side)?,
                "preserved subject identity differs"
            );
            ensure!(
                super::json::text(&raw.join("boot-id.txt"))?.trim() == boot_id,
                "preserved boot differs"
            );
            ensure!(
                first_word(&raw.join("harness-sha256.txt"))? == harness_sha,
                "preserved harness differs"
            );
            let raw_root = fs::canonicalize(&raw)?;
            for line in lines(&local.join("raw.sha256"))? {
                let (expected, name) = split_pair(&line)?;
                let path = fs::canonicalize(raw.join(name))?;
                ensure!(
                    path.starts_with(&raw_root) && sha(&path)? == expected,
                    "preserved evidence changed: {name}"
                );
            }
            print_event(json!({"event": "preserved", "side": side, "index": index}));
            continue;
        }
        util::create_private_dir(&local)?;
        let run_out = format!("{remote}/run-{index:02}");
        let selected = if side == "candidate"
            || options.memory_probe.is_some()
            || options.rpc_client_probe.is_some()
        {
            bundle.clone()
        } else if let Some((_, target)) = extra_bundles.iter().find(|entry| entry.0 == *side) {
            target.clone()
        } else if *side == options.baseline_label && baseline_bundle.is_some() {
            baseline_bundle.clone().unwrap_or_default()
        } else {
            stock_bundle.clone()
        };
        let implementation = if side == "stock" { "c" } else { "rs" };
        fs::write(local.join("host-before.json"), run.ssh(&snapshot)?)?;
        let mounts = run.ssh("cat /proc/self/mountinfo")?;
        fs::write(local.join("mounts-before.txt"), &mounts)?;
        let before_config = run.ssh("sha256sum /etc/config/*")?;
        fs::write(local.join("config-before.sha256"), &before_config)?;
        ensure!(before_config == config, "production state changed");
        let before_identity = run.production_identity()?;
        fs::write(local.join("production-before.txt"), &before_identity)?;
        ensure!(before_identity == identity, "production state changed");
        fs::write(local.join("environment-before.txt"), run.ssh(ENVIRONMENT)?)?;
        print_event(
            json!({"event": "started", "side": side, "index": index, "at": util::utc_now_iso()}),
        );
        let command = window_command(
            options,
            &settings,
            &remote,
            &selected,
            implementation,
            &run_out,
            index,
        );
        let mut failures: Vec<String> = Vec::new();
        let mut run_exit: Option<i32> = None;
        let group_receipt = format!("{remote}/group-{index:02}.identity");
        let launched = (|| -> Result<i32> {
            let log = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(local.join("run.log"))?;
            match (&options.health_guard_root, guard_identity) {
                (Some(root), Some(guard)) => {
                    run.save(&format!("{index:02}-{side}/health-guard.json"),
                             &json!({"root": root, "guard_pid_start": [guard.0, guard.1], "group_receipt": group_receipt,
                                     "owned_group_sha256": settings["owned_group_sha256"]}))?;
                    run.device.guarded_window(
                        &command,
                        root,
                        guard,
                        &group_helper,
                        &group_receipt,
                        &log,
                    )
                }
                _ => run.device.ssh_into(&command, &log, true, 1800.0),
            }
        })();
        match launched {
            Ok(code) => {
                run_exit = Some(code);
                if code != 0 {
                    failures.push(format!("namespace exited {code}"));
                }
            }
            Err(error) => failures.push(format!("launch: {error}")),
        }
        // Preserve a failed window before raising, including collection
        // errors. The router-side guard remains responsible for bounded
        // termination.
        if let Err(error) = collect_window(
            &mut run,
            &local,
            &run_out,
            &hash(side)?,
            &boot_id,
            &harness_sha,
            &tool_hashes,
            &manifest,
        ) {
            failures.push(format!("raw evidence: {error}"));
        }
        if let (Some(root), Some(guard)) = (&options.health_guard_root, guard_identity) {
            let postflight = (|| -> Result<()> {
                fs::write(
                    local.join("owned-group.identity"),
                    run.ssh(&format!("cat {}", quote(&group_receipt)))?,
                )?;
                health_guard_identity(run.device, root, Some(guard), true)?;
                Ok(())
            })();
            if let Err(error) = postflight {
                failures.push(format!("health guard postflight: {error}"));
            }
        }
        for (filename, command, expected) in [
            ("host-after.json", Some(snapshot.as_str()), None),
            ("environment-after.txt", Some(ENVIRONMENT), None),
            (
                "mounts-after.txt",
                Some("cat /proc/self/mountinfo"),
                Some(&mounts),
            ),
            (
                "config-after.sha256",
                Some("sha256sum /etc/config/*"),
                Some(&config),
            ),
            ("production-after.txt", None, Some(&identity)),
        ] {
            let checked = (|| -> Result<()> {
                let value = match command {
                    Some(command) => run.ssh(command)?,
                    None => run.production_identity()?,
                };
                fs::write(local.join(filename), &value)?;
                ensure!(
                    expected.is_none_or(|expected| *expected == value),
                    "{filename} changed"
                );
                Ok(())
            })();
            if let Err(error) = checked {
                failures.push(format!("{filename}: {error}"));
            }
        }
        if !failures.is_empty() {
            match run.device_probe() {
                Ok(health) => run.save(
                    &format!("{index:02}-{side}/health-after-failure.json"),
                    &health,
                )?,
                Err(error) => failures.push(format!("health: {error}")),
            }
        }
        run.save(&format!("{index:02}-{side}/result.json"),
                 &json!({"command": command, "exit": run_exit, "failures": failures,
                         "remote_evidence_retained": if failures.is_empty() { Value::Null } else { json!(run_out) }}))?;
        ensure!(
            failures.is_empty(),
            "window failed; evidence preserved: {}",
            failures.join("; ")
        );
        run.ssh(&format!("rm -rf -- {}", quote(&run_out)))?;
        fs::write(local.join("COMPLETE"), b"")?;
        print_event(json!({"event": "complete", "side": side, "index": index}));
    }
    let post = run.device_probe()?;
    run.save("health-after.json", &post)?;
    let after = run.ssh("sha256sum /etc/config/*")?;
    fs::write(out.join("config-after.sha256"), &after)?;
    ensure!(
        py_eq(key(&pre, "boot_id")?, key(&post, "boot_id")?) && config == after,
        "host boot/configuration changed"
    );
    ensure!(
        run.production_identity()? == identity,
        "host process identities changed"
    );
    run.ssh(&format!("rm -rf -- {remote}"))?;
    fs::write(out.join("COMPLETE"), b"")?;
    println!("{component} comparison complete");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_window(
    run: &mut Run,
    local: &Path,
    run_out: &str,
    subject: &str,
    boot_id: &str,
    harness_sha: &str,
    tool_hashes: &Map<String, Value>,
    manifest: &Value,
) -> Result<()> {
    let archive = local.join("raw.tar.gz");
    let raw = local.join("raw");
    {
        let target = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&archive)?;
        let code = run.device.ssh_into(
            &format!("tar -czf - -C {} .", quote(run_out)),
            &target,
            false,
            180.0,
        )?;
        ensure!(code == 0, "remote tar exited {code}");
    }
    let checksums = run.ssh(&format!(
        "cd {} && find . -type f -exec sha256sum '{{}}' ';'",
        quote(run_out)
    ))?;
    fs::write(local.join("raw.sha256"), &checksums)?;
    util::create_private_dir(&raw)?;
    extract_data(&archive, &raw)?;
    let raw_root = fs::canonicalize(&raw)?;
    for line in util::splitlines(&String::from_utf8(checksums)?) {
        let (digest, name) = split_pair(line)?;
        let path = fs::canonicalize(raw.join(name))?;
        ensure!(
            path.starts_with(&raw_root) && sha(&path)? == digest,
            "download checksum mismatch"
        );
    }
    ensure!(raw.join("COMPLETE").exists(), "incomplete isolated run");
    ensure!(
        first_word(&raw.join("binary-sha256.txt"))? == subject,
        "subject identity mismatch"
    );
    if raw.join("subject-sha256.txt").exists() {
        ensure!(
            first_word(&raw.join("subject-sha256.txt"))? == subject,
            "live subject identity mismatch"
        );
    }
    ensure!(
        super::json::text(&raw.join("boot-id.txt"))?.trim() == boot_id,
        "host boot changed"
    );
    ensure!(
        first_word(&raw.join("harness-sha256.txt"))? == harness_sha,
        "harness identity mismatch"
    );
    let mut observed = Map::new();
    for line in lines(&raw.join("benchmark-sha256.txt"))? {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [digest, path] = fields[..] else {
            bail!("invalid benchmark identity row")
        };
        let name = Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        observed.insert(name, json!(digest));
    }
    ensure!(
        py_eq(
            &Value::Object(observed),
            &Value::Object(tool_hashes.clone())
        ),
        "measured tool identities differ"
    );
    let component = run.options.component.as_str();
    let dependencies: &[&str] = match component {
        "httpd" => &["rpcd", "ubusd"],
        "procd" => &["ubusd"],
        _ => &[],
    };
    if !dependencies.is_empty() {
        let observed = first_words(&raw.join("dependencies-sha256.txt"))?;
        let expected = dependencies
            .iter()
            .map(|name| Ok(manifest_sha(manifest, name, "original")?.to_owned()))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            observed == expected,
            "{}",
            if component == "httpd" {
                "HTTP dependencies are not the exact image C binaries"
            } else {
                "procd dependency is not the exact image C ubusd"
            }
        );
    }
    Ok(())
}

fn settings(
    options: &Options,
    hashes: &Map<String, Value>,
    tool_hashes: &Map<String, Value>,
    group_script: &Path,
) -> Result<Value> {
    let component = options.component.as_str();
    let mut settings = Map::new();
    let mut put = |name: &str, value: Value| {
        settings.insert(name.to_owned(), value);
    };
    put("component", json!(component));
    put("iterations", json!(options.iterations));
    put("matrix", json!(options.matrix));
    put("stack", json!(options.stack));
    put("host_bundle", json!(options.host_bundle));
    put("reference_root", json!(options.reference_root));
    put(
        "held_connections",
        if options.memory_probe.is_some() {
            json!(64)
        } else {
            Value::Null
        },
    );
    put(
        "rpc_client_diagnostic",
        json!(options.rpc_client_probe.is_some()),
    );
    put("baseline_label", json!(options.baseline_label));
    put("baseline_bundle", json!(options.baseline_bundle));
    put("cpu_affinity", json!(options.cpus));
    put("management_access", json!(options.access));
    put("workload_transport", json!("namespace loopback"));
    if let Some((_, digest)) = &options.native_manifest {
        put("native_manifest_sha256", json!(digest));
    }
    if options.schedule != "default" {
        put("schedule", json!(options.schedule));
    }
    if let Some(seed) = options.seed {
        put("seed", json!(seed));
    }
    if !options.extra_baselines.is_empty() {
        put(
            "extra_baselines",
            Value::Object(options.extra_baselines.clone()),
        );
    }
    if component == "procd" {
        put("procd_warmup", json!(options.procd_warmup));
        if let Some(workloads) = &options.procd_workloads {
            put("procd_workloads", json!(workloads));
        }
    }
    if let Some(workloads) = &options.httpd_workloads {
        put("httpd_workloads", json!(workloads));
    }
    if let Some(workloads) = &options.rpcd_workloads {
        put("rpcd_workloads", json!(workloads));
    }
    if component == "reload-config" {
        let default = if options.matrix {
            owned(&RELOAD_WORKLOADS)
        } else {
            owned(&["unchanged_config"])
        };
        put(
            "reload_workloads",
            json!(options.reload_workloads.clone().unwrap_or(default)),
        );
        put("reload_warmup", json!(options.reload_warmup));
        put("reload_packages", json!(options.reload_packages));
        put("reload_prepared_exec", json!(true));
    }
    if component == "fw4" {
        put(
            "fw4_workloads",
            json!(options
                .fw4_workloads
                .clone()
                .unwrap_or_else(|| owned(&["print", "check"]))),
        );
        put(
            "fw4_count",
            json!(options
                .fw4_count
                .unwrap_or((options.iterations / 100).max(1))),
        );
        put("fw4_warmup", json!(options.fw4_warmup));
        if let Some(digest) = &options.fw4_fixture_hash {
            put("fw4_fixture_sha256", json!(digest));
        }
    }
    if component == "netifd" {
        put("netifd_scale", json!(options.netifd_scale));
        put("netifd_warmup", json!(options.netifd_warmup));
        if let Some(workloads) = &options.netifd_workloads {
            put("netifd_workloads", json!(workloads));
        }
        if !options.event_contracts.is_empty() {
            // Candidate must match C. Formal R89 retains its actual baseline
            // contract; source/output differences are reviewed before calibration.
            for (side, contract) in &options.event_contracts {
                let source = if *side == options.baseline_label {
                    &hashes[options.baseline_label.as_str()]
                } else {
                    &hashes["stock"]
                };
                ensure!(
                    py_eq(&contract["reference_subject_sha256"], source),
                    "event contract source identity mismatch"
                );
            }
            let directory = options
                .netifd_event_contracts
                .as_deref()
                .unwrap_or(Path::new(""));
            ensure!(
                fs::read(directory.join("candidate.json"))?
                    == fs::read(directory.join("stock.json"))?,
                "candidate contract must match the frozen C contract"
            );
            put(
                "netifd_event_contracts",
                Value::Object(options.event_contracts.iter().cloned().collect()),
            );
        }
        if !options.fixture_hashes.is_empty() {
            put(
                "netifd_fixture_sha256",
                Value::Object(
                    options
                        .fixture_hashes
                        .iter()
                        .map(|(n, d)| (n.clone(), json!(d)))
                        .collect(),
                ),
            );
        }
    }
    if let Some(guard) = &options.guard {
        put("guard_sha256", json!(sha(guard)?));
        put("namespace_timeout_seconds", json!(600));
    }
    if let Some(root) = &options.health_guard_root {
        put("health_guard_root", json!(root));
        put("owned_group_sha256", json!(sha(group_script)?));
        put("health_guard_poll_seconds", json!(5));
        put("native_host_deadline_seconds", json!(660));
    }
    if options.bench.is_some() {
        put("bench_sha256", tool_hashes["owrt-benchmark"].clone());
    }
    if let Some(probe) = &options.exec_resource_probe {
        put("exec_resource_probe_sha256", json!(sha(probe)?));
    }
    if let Some(probe) = &options.exec_task_probe {
        put("exec_task_probe_sha256", json!(sha(probe)?));
    }
    if options.extended {
        put("extended", json!(true));
    }
    Ok(Value::Object(settings))
}

fn window_command(
    options: &Options,
    settings: &Value,
    remote: &str,
    selected: &str,
    implementation: &str,
    run_out: &str,
    index: usize,
) -> String {
    let component = options.component.as_str();
    let mut command = format!(
        "/bin/sh {remote}/isolated.sh {} {} {component} {implementation} {run_out} {}",
        quote(&options.reference_root),
        quote(selected),
        options.iterations
    );
    let words = |values: &[String]| quote(&values.join(" "));
    if let Some(cpus) = &options.cpus {
        command = format!("taskset -c {} {command}", quote(cpus));
    }
    if options.matrix {
        command = format!(
            "OWRT_{}_MATRIX=1 {command}",
            component.to_uppercase().replace('-', "_")
        );
        if component == "netifd" {
            command = format!(
                "OWRT_NETIFD_SCALE={} OWRT_NETIFD_WARMUP={} {command}",
                options.netifd_scale, options.netifd_warmup
            );
            if let Some(workloads) = &options.netifd_workloads {
                command = format!("OWRT_NETIFD_WORKLOADS={} {command}", words(workloads));
            }
        }
    }
    let strings = |name: &str| {
        settings[name]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    if component == "reload-config" {
        command = format!("OWRT_RELOAD_CONFIG_WORKLOADS={} OWRT_RELOAD_CONFIG_WARMUP={} OWRT_RELOAD_CONFIG_PACKAGES={} {command}",
                          words(&strings("reload_workloads")), options.reload_warmup, options.reload_packages);
    }
    if component == "fw4" {
        command = format!(
            "OWRT_FW4_WORKLOADS={} OWRT_FW4_COUNT={} OWRT_FW4_WARMUP={} {command}",
            words(&strings("fw4_workloads")),
            settings["fw4_count"],
            options.fw4_warmup
        );
        if let Some(digest) = &options.fw4_fixture_hash {
            command = format!("OWRT_FW4_FIXTURE_SHA256={digest} {command}");
        }
    }
    if let Some(workloads) = &options.httpd_workloads {
        command = format!("OWRT_HTTPD_WORKLOADS={} {command}", words(workloads));
    }
    if let Some(workloads) = &options.rpcd_workloads {
        command = format!("OWRT_RPCD_WORKLOADS={} {command}", words(workloads));
    }
    if component == "procd" {
        command = format!("OWRT_PROCD_WARMUP={} {command}", options.procd_warmup);
        if let Some(workloads) = &options.procd_workloads {
            command = format!("OWRT_PROCD_WORKLOADS={} {command}", words(workloads));
        }
    }
    if options.guard.is_some() {
        command = format!("OWRT_BENCH_GUARD={remote}/guard {command}");
    }
    if options.extended {
        command = format!("OWRT_UBUSD_EXTENDED=1 OWRT_UBUSD_NORMALIZED=1 {command}");
    }
    if options.memory_probe.is_some() {
        command = format!("OWRT_HTTPD_MEMORY=1 {command}");
    }
    if options.rpc_client_probe.is_some() {
        let order = if index % 2 == 1 {
            "tree-first"
        } else {
            "wire-first"
        };
        command = format!("OWRT_RPCD_CLIENT_DIAGNOSTIC=1 OWRT_RPCD_CLIENT_ORDER={order} {command}");
    }
    command
}

pub fn main(raw: &[String]) -> Result<i32> {
    let options = match Options::parse(raw) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("run-candidate: error: {error}");
            return Ok(2);
        }
    };
    let mut device = RealDevice {
        host: options.host.clone(),
    };
    run(&options, &mut device)?;
    Ok(0)
}

#[cfg(test)]
#[path = "run_candidate_tests.rs"]
mod tests;

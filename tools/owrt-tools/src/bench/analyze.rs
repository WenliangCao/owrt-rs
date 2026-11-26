//! `analyze`: derive an allowlisted, publishable summary from private R84
//! measurements.
//!
//! No response bodies, configuration hashes, addresses, tokens or device logs
//! are copied to the output. By default all four boots and all 72 component
//! runs must be complete. `--partial` is for private progress inspection only.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use regex::Regex;
use serde_json::{json, Map, Value};

use super::json::{
    at, bytes, first_word, json_lines, key, kf, ki, kn, lines, list, merge, need_pid, pick, read,
    text,
};
use super::stats::{isclose, mean, num, py_eq, stats, sum_nums, value_stats, Num};
use crate::util::{self, bail, ensure, Error, Result};

pub const COMPONENT_WORK: &[(&str, &[&str])] = &[
    ("uci", &["export_network", "export_64", "set_commit_get"]),
    ("reload-config", &["unchanged_config"]),
    ("fw4", &["print", "check"]),
    ("logd", &["syslog_128", "log_read_100"]),
    ("httpd", &["static_16k", "cgi", "jsonrpc"]),
    (
        "rpcd",
        &[
            "uci_configs",
            "uci_get_network",
            "file_stat",
            "session_access",
        ],
    ),
    ("procd", &["service_list_32", "system_info"]),
    ("ubusd", &["lookup", "lookup_all_64", "invoke"]),
    (
        "netifd",
        &[
            "interface_dump",
            "lan_status",
            "device_status",
            "wireless_status",
        ],
    ),
];
const ORDER: [&str; 8] = ["c", "rs", "rs", "c", "rs", "c", "c", "rs"];
const WINDOWS: [&str; 4] = ["rust-1", "stock-1", "stock-2", "rust-2"];
const SERIAL: [&str; 8] = [
    "network",
    "rpcd",
    "procd",
    "log",
    "uci",
    "fw4",
    "http-static",
    "http-jsonrpc",
];
const MEMORY_KEYS: [&str; 8] = [
    "VmRSS", "RssAnon", "RssFile", "RssShmem", "VmHWM", "VmPTE", "Threads", "fds",
];
const SYSTEM_MEMORY_KEYS: [&str; 10] = [
    "MemFree",
    "MemAvailable",
    "Cached",
    "AnonPages",
    "Mapped",
    "Shmem",
    "SReclaimable",
    "SUnreclaim",
    "KernelStack",
    "PageTables",
];
const TIMING_KEYS: [&str; 7] = [
    "successful",
    "wall_s",
    "ops_per_s",
    "mean_us",
    "p50_us",
    "p95_us",
    "p99_us",
];

pub fn component_work(component: &str) -> Option<&'static [&'static str]> {
    COMPONENT_WORK
        .iter()
        .find(|(name, _)| *name == component)
        .map(|(_, work)| *work)
}

fn digest(path: &Path) -> Result<String> {
    util::sha256_file(path)
}

/// The native client's nonnegative `.round()` index over sorted samples.
pub fn rounded_quantile(ordered: &[i64], quantile: f64) -> f64 {
    let index = ((ordered.len() - 1) as f64 * quantile + 0.5).floor() as usize;
    ordered[index] as f64 / 1000.0
}

/// Loads one native client result and checks its derived fields against
/// its raw samples.
pub fn native(path: &Path) -> Result<Value> {
    let data = read(path)?;
    let at_path = util::display(path);
    let count = key(&data, "successful")?;
    ensure!(
        count.as_i64().is_some_and(|n| n > 0) && kf(&data, "errors")? == 0.0,
        "{at_path}"
    );
    let n = count.as_i64().unwrap_or_default() as usize;
    let samples = list(&data, "latency_ns")?;
    ensure!(samples.len() == n, "{at_path}");
    ensure!(samples.iter().all(Value::is_u64), "{at_path}");
    let mut ordered: Vec<i64> = samples
        .iter()
        .map(|value| value.as_u64().unwrap_or_default() as i64)
        .collect();
    let wall = kf(&data, "wall_s")?;
    ensure!(wall.is_finite() && wall > 0.0, "{at_path}");
    let ints: Vec<Num> = ordered.iter().map(|&value| Num::Int(value)).collect();
    ensure!(
        isclose(kf(&data, "mean_us")?, mean(&ints)?.f() / 1000.0, 1e-8, 1e-6),
        "{at_path}"
    );
    ordered.sort_unstable();
    // Match the native client's nonnegative .round() index; Python round()
    // instead rounds halfway indices to even and can select a different item.
    for (name, quantile) in [("p50_us", 0.50), ("p95_us", 0.95), ("p99_us", 0.99)] {
        ensure!(
            isclose(
                kf(&data, name)?,
                rounded_quantile(&ordered, quantile),
                1e-8,
                1e-6
            ),
            "{at_path}: {name}"
        );
    }
    ensure!(
        isclose(kf(&data, "ops_per_s")?, n as f64 / wall, 1e-8, 1e-6),
        "{at_path}: ops_per_s"
    );
    for process in list(&data, "daemon_cpu")? {
        ensure!(
            py_eq(
                at(process, &["before", "start_ticks"])?,
                at(process, &["after", "start_ticks"])?
            ),
            "{at_path}"
        );
        ensure!(
            kf(process, "cpu_s")? >= 0.0 && kf(process, "child_cpu_s")? >= 0.0,
            "{at_path}"
        );
    }
    Ok(data)
}

pub fn timing(data: &Value) -> Result<Map<String, Value>> {
    pick(data, &TIMING_KEYS)
}

pub fn memory(process: &Value) -> Result<Map<String, Value>> {
    pick(process, &MEMORY_KEYS)
}

/// Rejects a kernel-log substitute that makes an otherwise idle logd spin.
pub fn logd_idle(path: &Path, subject: &Value) -> Result<Value> {
    let samples = json_lines(path)?;
    let at_path = util::display(path);
    ensure!(samples.len() == 4, "{at_path}");
    let elapsed = kn(&samples[3], "uptime_s")?.sub(kn(&samples[0], "uptime_s")?);
    ensure!((2.9..=3.2).contains(&elapsed.f()), "{at_path}");
    let group = samples
        .iter()
        .map(|sample| need_pid(list(sample, "processes")?, subject))
        .collect::<Result<Vec<_>>>()?;
    for process in &group {
        ensure!(
            py_eq(key(process, "start_ticks")?, key(group[0], "start_ticks")?),
            "{at_path}"
        );
    }
    let hz = kf(&samples[0], "clock_ticks_per_second")?;
    let cpu = kn(group[3], "cpu_ticks")?
        .sub(kn(group[0], "cpu_ticks")?)
        .f()
        / hz;
    ensure!(
        0.0 <= cpu && cpu <= elapsed.f() * 0.01 + 1.0 / hz,
        "logd is busy before any workload"
    );
    Ok(
        json!({"elapsed_s": elapsed.value(), "cpu_s": cpu, "cpu_one_core_pct": cpu / elapsed.f() * 100.0}),
    )
}

fn sum_field(
    processes: &[Value],
    name: &str,
    mut keep: impl FnMut(&Value) -> Result<bool>,
) -> Result<Num> {
    let mut total = Num::Int(0);
    for process in processes {
        if keep(process)? {
            total = total.add(kn(process, name)?);
        }
    }
    Ok(total)
}

type Rows = Vec<Value>;

fn components(
    root: &Path,
    manifest: &Value,
    partial: bool,
) -> Result<(Rows, Rows, Rows, Vec<String>)> {
    let (mut rows, mut residents, mut sources, mut missing) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (component, workloads) in COMPONENT_WORK {
        for (index, implementation) in ORDER.iter().enumerate() {
            let name = format!("{component}/{:02}-{implementation}", index + 1);
            let run = root.join("components").join(&name);
            if !run.join("COMPLETE").exists() {
                missing.push(format!("component:{name}"));
                continue;
            }
            let raw = run.join("raw");
            ensure!(raw.join("COMPLETE").exists(), "{}", util::display(&run));
            let meta = read(&raw.join("meta.json"))?;
            ensure!(
                py_eq(
                    &json!([
                        key(&meta, "component")?,
                        key(&meta, "implementation")?,
                        key(&meta, "iterations")?
                    ]),
                    &json!([component, implementation, 10000])
                ),
                "{name}: unexpected meta"
            );
            let role = if *implementation == "rs" {
                "rust"
            } else {
                "original"
            };
            let expected = at(manifest, &["components", *component, role, "sha256"])?;
            ensure!(
                py_eq(
                    &json!(first_word(&raw.join("binary-sha256.txt"))?),
                    expected
                ),
                "{name}: binary identity"
            );
            ensure!(
                py_eq(
                    &json!(first_word(&raw.join("benchmark-sha256.txt"))?),
                    at(manifest, &["tools", "owrt-benchmark", "sha256"])?
                ),
                "{name}: benchmark identity"
            );
            let side = if *implementation == "rs" {
                "rust"
            } else {
                "stock"
            };
            let subject = key(&meta, "subject_pid")?;
            let mut source = Map::new();
            source.insert("run".into(), json!(name));
            source.insert(
                "archive_sha256".into(),
                json!(digest(&run.join("raw.tar.gz"))?),
            );
            source.insert("subject_sha256".into(), expected.clone());
            source.insert(
                "kernel".into(),
                json!(text(&raw.join("kernel.txt"))?.trim()),
            );
            if *component == "logd" {
                ensure!(
                    meta.get("kernel_log_mask").and_then(Value::as_str) == Some("empty-held-fifo"),
                    "invalid logd kernel-log fixture"
                );
                source.insert(
                    "kernel_log_idle_gate".into(),
                    logd_idle(&raw.join("kernel-log-idle.jsonl"), subject)?,
                );
            }
            if raw.join("harness-sha256.txt").exists() {
                source.insert(
                    "harness_sha256".into(),
                    json!(first_word(&raw.join("harness-sha256.txt"))?),
                );
            }
            sources.push(Value::Object(source));
            for workload in *workloads {
                let data = native(&raw.join(format!("{workload}.json")))?;
                let n = ki(&data, "successful")?;
                let expected_count = if *component == "fw4" {
                    100
                } else if matches!(*component, "uci" | "reload-config") || *workload == "cgi" {
                    500
                } else if *workload == "syslog_128" {
                    100_000
                } else {
                    10_000
                };
                ensure!(n == expected_count, "{name} {workload}: {n} operations");
                let one_shot = subject.is_null();
                let daemons = list(&data, "daemon_cpu")?;
                let own = super::json::find_pid(daemons, subject)?;
                ensure!(
                    one_shot || own.is_some(),
                    "{name} {workload}: subject is missing"
                );
                let subject_cpu = match (one_shot, own) {
                    (false, Some(own)) => kf(own, "cpu_s")? + kf(own, "child_cpu_s")?,
                    _ => kf(&data, "child_cpu_s")?,
                };
                let dependencies =
                    sum_field(daemons, "cpu_s", |p| Ok(!py_eq(key(p, "pid")?, subject)))?.f();
                let mut row = Map::new();
                for (field, value) in [
                    ("study", "component"),
                    ("component", *component),
                    ("workload", *workload),
                    ("side", side),
                ] {
                    row.insert(field.into(), json!(value));
                }
                row.insert("run".into(), json!(name));
                merge(&mut row, timing(&data)?);
                let n = n as f64;
                row.insert("subject_cpu_us_per_op".into(), json!(subject_cpu * 1e6 / n));
                row.insert(
                    "dependency_cpu_us_per_op".into(),
                    json!(dependencies * 1e6 / n),
                );
                row.insert(
                    "client_cpu_us_per_op".into(),
                    json!(kf(&data, "client_cpu_s")? * 1e6 / n),
                );
                row.insert(
                    "clock_ticks_per_second".into(),
                    key(&data, "clock_ticks_per_second")?.clone(),
                );
                rows.push(Value::Object(row));
            }
            if !subject.is_null() {
                let sample = read(&raw.join("resident.json"))?;
                let process = need_pid(list(&sample, "processes")?, subject)?;
                let mut resident = Map::new();
                resident.insert("component".into(), json!(component));
                resident.insert("side".into(), json!(side));
                resident.insert("run".into(), json!(name));
                merge(&mut resident, memory(process)?);
                resident.insert(
                    "temperature_millic".into(),
                    key(&sample, "temperature_millic")?.clone(),
                );
                residents.push(Value::Object(resident));
            }
        }
    }
    ensure!(partial || missing.is_empty(), "{missing:?}");
    Ok((rows, residents, sources, missing))
}

fn stats_by(samples: &[Value], value: impl Fn(&Value) -> Result<Num>) -> Result<Value> {
    stats(&samples.iter().map(value).collect::<Result<Vec<_>>>()?)
}

fn idle(path: &Path, names: &[(i64, String)]) -> Result<Value> {
    let samples = json_lines(path)?;
    let at_path = util::display(path);
    ensure!(samples.len() == 121, "{at_path}: idle sample count");
    let (before, after) = (&samples[0], &samples[120]);
    let elapsed = kn(after, "uptime_s")?.sub(kn(before, "uptime_s")?);
    ensure!(
        (119.0..=122.0).contains(&elapsed.f()),
        "{at_path}: idle interval"
    );
    let hz = kf(before, "clock_ticks_per_second")?;
    let ticks = list(before, "system_cpu_ticks")?
        .iter()
        .zip(list(after, "system_cpu_ticks")?)
        .map(|(a, b)| Ok(num(b)?.sub(num(a)?)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(ticks.len() > 4, "{at_path}: system CPU ticks");
    let total = sum_nums(ticks.iter().take(8).copied());
    let busy = total.sub(ticks[3]).sub(ticks[4]).f() / total.f() * 100.0;
    let summed = |name: &'static str| {
        move |sample: &Value| sum_field(list(sample, "processes")?, name, |_| Ok(true))
    };
    let mut result = Map::new();
    result.insert("samples".into(), json!(samples.len()));
    result.insert("elapsed_s".into(), elapsed.value());
    result.insert("system_busy_capacity_pct".into(), json!(busy));
    result.insert(
        "memory_available_kib".into(),
        stats_by(&samples, |s| num(at(s, &["memory_kib", "MemAvailable"])?))?,
    );
    result.insert(
        "summed_daemon_rss_kib".into(),
        stats_by(&samples, summed("VmRSS"))?,
    );
    result.insert(
        "summed_daemon_anon_kib".into(),
        stats_by(&samples, summed("RssAnon"))?,
    );
    result.insert(
        "temperature_millic".into(),
        stats_by(&samples, |s| kn(s, "temperature_millic"))?,
    );
    let mut processes = Map::new();
    let mut total_daemon_ticks = Num::Int(0);
    for (pid, name) in names {
        let pid = json!(pid);
        let group = samples
            .iter()
            .map(|s| need_pid(list(s, "processes")?, &pid))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            py_eq(
                key(group[0], "start_ticks")?,
                key(group[group.len() - 1], "start_ticks")?
            ),
            "{name} restarted while idle"
        );
        let cpu_ticks = kn(group[group.len() - 1], "cpu_ticks")?.sub(kn(group[0], "cpu_ticks")?);
        total_daemon_ticks = total_daemon_ticks.add(cpu_ticks);
        let mut process = Map::new();
        for field in MEMORY_KEYS {
            process.insert(
                field.into(),
                value_stats(
                    group
                        .iter()
                        .map(|p| key(p, field))
                        .collect::<Result<Vec<_>>>()?,
                )?,
            );
        }
        process.insert(
            "cpu_one_core_pct".into(),
            json!(cpu_ticks.f() / hz / elapsed.f() * 100.0),
        );
        processes.insert(name.clone(), Value::Object(process));
    }
    result.insert("processes".into(), Value::Object(processes));
    result.insert(
        "daemon_cpu_one_core_pct".into(),
        json!(total_daemon_ticks.f() / hz / elapsed.f() * 100.0),
    );
    let mut system = Map::new();
    for field in SYSTEM_MEMORY_KEYS {
        system.insert(
            field.into(),
            stats_by(&samples, |s| num(at(s, &["memory_kib", field])?))?,
        );
    }
    result.insert("system_memory_kib".into(), Value::Object(system));
    Ok(Value::Object(result))
}

/// Python `len(value)` of a decoded container.
fn py_len(value: &Value) -> Result<usize> {
    match value {
        Value::Array(items) => Ok(items.len()),
        Value::Object(fields) => Ok(fields.len()),
        Value::String(text) => Ok(text.chars().count()),
        _ => bail!("{value} has no length"),
    }
}

fn tree_bytes(root: &Path) -> Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            total += tree_bytes(&path)?;
        } else if let Ok(target) = fs::metadata(&path) {
            if target.is_file() {
                total += target.len();
            }
        }
    }
    Ok(total)
}

type WindowEvidence = (Rows, Rows, Rows, Rows, Vec<String>);

fn windows(root: &Path, manifest: &Value, partial: bool) -> Result<WindowEvidence> {
    let (mut rows, mut resources, mut tls_rows, mut sources, mut missing) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let (mut configs, mut execution_planes, mut rulesets) = (Vec::new(), Vec::new(), Vec::new());
    let counters = Regex::new(r"packets \d+ bytes \d+")?;
    let expiry = Regex::new(r"(expires|timeout) [0-9smhd]+")?;
    for name in WINDOWS {
        let window = root.join("windows").join(name);
        let out = window.join("measurements");
        if !out.join("COMPLETE").exists() {
            missing.push(format!("window:{name}"));
            continue;
        }
        let raw = out.join("live");
        ensure!(
            raw.join("COMPLETE").exists(),
            "{name}: live collection incomplete"
        );
        let meta = read(&raw.join("meta.json"))?;
        let side = name.split('-').next().unwrap_or(name);
        ensure!(
            py_eq(
                &meta,
                &json!({"mode": side, "iterations": 10000, "repeats": 5, "idle_seconds": 120, "mixed_lanes": 4})
            ),
            "{name}: unexpected meta"
        );
        ensure!(
            py_eq(
                &json!(first_word(&raw.join("benchmark-sha256.txt"))?),
                at(manifest, &["tools", "owrt-benchmark", "sha256"])?
            ),
            "{name}: benchmark identity"
        );
        ensure!(
            bytes(&raw.join("config-before.sha256"))? == bytes(&raw.join("config-after.sha256"))?,
            "{name}: configuration changed"
        );
        ensure!(
            bytes(&raw.join("running-hashes.txt"))?
                == bytes(&raw.join("final-running-hashes.txt"))?,
            "{name}: running identity changed"
        );
        configs.push(bytes(&raw.join("config-before.sha256"))?);
        let rules = text(&out.join("nft-ruleset.txt"))?;
        let rules = counters.replace_all(&rules, "packets N bytes N");
        rulesets.push(expiry.replace_all(&rules, "${1} T").into_owned());
        let mut plane = BTreeSet::new();
        for line in lines(&raw.join("execution-plane.txt"))? {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if !fields.is_empty() {
                ensure!(fields.len() > 2, "{name}: short execution-plane row");
                plane.insert((fields[0].to_owned(), fields[2].to_owned()));
            }
        }
        execution_planes.push(plane);
        let role = if side == "rust" { "rust" } else { "original" };
        let mut names: Vec<(i64, String)> = Vec::new();
        for line in lines(&raw.join("running-hashes.txt"))? {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [component, pid, actual] = fields[..] else {
                bail!("{name}: invalid running-hashes row")
            };
            ensure!(
                py_eq(
                    &json!(actual),
                    at(manifest, &["components", component, role, "sha256"])?
                ),
                "{name}: {component} identity"
            );
            if pid != "-" {
                let pid: i64 = pid.trim().parse()?;
                match names.iter_mut().find(|entry| entry.0 == pid) {
                    Some(entry) => entry.1 = component.to_owned(),
                    None => names.push((pid, component.to_owned())),
                }
            }
        }
        let daemons: BTreeSet<&str> = names.iter().map(|entry| entry.1.as_str()).collect();
        ensure!(
            daemons == BTreeSet::from(["procd", "ubusd", "netifd", "rpcd", "logd", "httpd"]),
            "{name}: daemon set"
        );
        let health = read(&window.join("health.json"))?;
        ensure!(
            health.get("status").and_then(Value::as_str) == Some("healthy")
                && at(&health, &["post", "mode"])?.as_str() == Some(side),
            "{name}: unhealthy window"
        );
        ensure!(
            py_eq(
                &json!(text(&raw.join("boot-id.txt"))?.trim()),
                at(&health, &["post", "boot_id"])?
            ),
            "{name}: boot changed"
        );
        sources.push(
            json!({"run": name, "archive_sha256": digest(&out.join("live.tar.gz"))?,
                            "kernel": text(&raw.join("kernel.txt"))?.trim()}),
        );
        let (mut total_ops, mut total_server_cpu) = (0i64, Num::Int(0));
        for repeat in 1..=5 {
            let run = format!("{name}/{repeat}");
            let row_head = |workload: &str| {
                let mut row = Map::new();
                for (field, value) in [
                    ("study", "whole"),
                    ("component", "all"),
                    ("workload", workload),
                    ("side", side),
                ] {
                    row.insert(field.into(), json!(value));
                }
                row.insert("run".into(), json!(run));
                row
            };
            for workload in SERIAL {
                let data = native(&raw.join(format!("{repeat}-{workload}.json")))?;
                let n: i64 = match workload {
                    "uci" => 100,
                    "fw4" => 30,
                    _ => 10_000,
                };
                ensure!(
                    ki(&data, "successful")? == n,
                    "{run} {workload}: operation count"
                );
                let program_cpu = if matches!(workload, "uci" | "fw4") {
                    kn(&data, "child_cpu_s")?
                } else {
                    Num::Int(0)
                };
                let server_cpu =
                    sum_field(list(&data, "daemon_cpu")?, "cpu_s", |_| Ok(true))?.add(program_cpu);
                let mut row = row_head(workload);
                merge(&mut row, timing(&data)?);
                row.insert(
                    "server_cpu_us_per_op".into(),
                    json!(server_cpu.f() * 1e6 / n as f64),
                );
                row.insert(
                    "client_cpu_us_per_op".into(),
                    json!(kf(&data, "client_cpu_s")? * 1e6 / n as f64),
                );
                rows.push(Value::Object(row));
                total_ops += n;
                total_server_cpu = total_server_cpu.add(server_cpu);
            }
            // One non-overlapping CPU bracket covers all four concurrent
            // clients. Their individual daemon CPU counters must not be added.
            let data = native(&raw.join(format!("{repeat}-mixed-total.json")))?;
            ensure!(ki(&data, "successful")? == 1, "{run}: mixed total");
            let n = 40_000i64;
            let server_cpu = sum_field(list(&data, "daemon_cpu")?, "cpu_s", |_| Ok(true))?;
            let mut row = row_head("mixed-total");
            row.insert("successful".into(), json!(n));
            row.insert("wall_s".into(), key(&data, "wall_s")?.clone());
            row.insert("ops_per_s".into(), json!(n as f64 / kf(&data, "wall_s")?));
            row.insert(
                "server_cpu_us_per_op".into(),
                json!(server_cpu.f() * 1e6 / n as f64),
            );
            row.insert(
                "client_cpu_us_per_op".into(),
                json!(
                    kn(&data, "client_cpu_s")?
                        .add(kn(&data, "child_cpu_s")?)
                        .f()
                        * 1e6
                        / n as f64
                ),
            );
            rows.push(Value::Object(row));
            total_ops += n;
            total_server_cpu = total_server_cpu.add(server_cpu);
            for lane in ["procd", "network", "rpcd", "http"] {
                let lane_data = native(&raw.join(format!("{repeat}-mixed-{lane}.json")))?;
                ensure!(
                    ki(&lane_data, "successful")? == 10_000,
                    "{run} {lane}: operation count"
                );
                let mut row = row_head(lane);
                row.insert("study".into(), json!("mixed-lane"));
                merge(&mut row, timing(&lane_data)?);
                rows.push(Value::Object(row));
            }
        }
        ensure!(total_ops == 500_650, "{name}: total operations {total_ops}");
        let services = read(&raw.join("services.json"))?;
        let services = services
            .as_object()
            .ok_or_else(|| Error::new("services.json is not an object"))?;
        let mut instances = 0;
        for service in services.values() {
            instances += match service.get("instances") {
                Some(value) => py_len(value)?,
                None => 0,
            };
        }
        resources.push(json!({"window": name, "side": side, "successful": total_ops,
                              "service_count": services.len(), "service_instance_count": instances,
                              "active_server_cpu_s": total_server_cpu.value(),
                              "first_ssh_s": key(&health, "first_ssh_s")?, "health_confirmed_s": key(&health, "elapsed_s")?,
                              "idle_before": idle(&raw.join("idle-before.jsonl"), &names)?,
                              "idle_after": idle(&raw.join("idle-after.jsonl"), &names)?,
                              "raw_live_bytes": tree_bytes(&raw)?}));
        let prefixes: &[&str] = if name.ends_with("-2") {
            &["tls", "tls-common"]
        } else {
            &["tls"]
        };
        for prefix in prefixes {
            for connection in ["keepalive", "fresh"] {
                for concurrency in [1i64, 4] {
                    let label = format!("{prefix}-{connection}-c{concurrency}");
                    let data = read(&out.join(format!("{label}.json")))?;
                    ensure!(
                        ki(&data, "successful")? == 1000
                            && list(&data, "latency_ns")?.len() == 1000
                            && kf(&data, "errors")? == 0.0,
                        "{name} {label}: incomplete"
                    );
                    ensure!(
                        py_eq(key(&data, "tls_versions")?, &json!(["TLSv1.2"])),
                        "{name} {label}: TLS version"
                    );
                    let limit = if connection == "fresh" {
                        json!(20)
                    } else {
                        Value::Null
                    };
                    ensure!(
                        py_eq(key(&data, "request_rate_limit_per_s")?, &limit),
                        "{name} {label}: rate limit"
                    );
                    let bracket = read(&out.join(format!("{label}-server.json")))?;
                    let (before, after) = (key(&bracket, "before")?, key(&bracket, "after")?);
                    let hz = kf(before, "clock_ticks_per_second")?;
                    let mut cpu = BTreeMap::new();
                    for process in list(before, "processes")? {
                        let pid = key(process, "pid")?;
                        let last = need_pid(list(after, "processes")?, pid)?;
                        ensure!(
                            py_eq(key(last, "start_ticks")?, key(process, "start_ticks")?),
                            "{name} {label}: server restarted"
                        );
                        let pid = pid.as_i64().ok_or_else(|| Error::new("invalid PID"))?;
                        let component = names
                            .iter()
                            .find(|entry| entry.0 == pid)
                            .ok_or_else(|| Error::new(format!("unknown PID {pid}")))?;
                        cpu.insert(
                            component.1.clone(),
                            kn(last, "cpu_ticks")?.sub(kn(process, "cpu_ticks")?).f() / hz,
                        );
                    }
                    let count = ki(&bracket, "successful_including_warmup")?;
                    ensure!(
                        count == 1000 + 10 * concurrency,
                        "{name} {label}: bracket count"
                    );
                    let httpd = *cpu
                        .get("httpd")
                        .ok_or_else(|| Error::new("httpd CPU is missing"))?;
                    let mut row = Map::new();
                    row.insert(
                        "study".into(),
                        json!(if *prefix == "tls-common" {
                            "tls-common"
                        } else {
                            "tls-default"
                        }),
                    );
                    row.insert("component".into(), json!("httpd"));
                    row.insert(
                        "workload".into(),
                        json!(format!("{connection}-c{concurrency}")),
                    );
                    row.insert("side".into(), json!(side));
                    row.insert("run".into(), json!(name));
                    row.insert("successful".into(), json!(1000));
                    merge(
                        &mut row,
                        pick(
                            &data,
                            &[
                                "wall_s",
                                "ops_per_s",
                                "mean_ms",
                                "p50_ms",
                                "p95_ms",
                                "p99_ms",
                            ],
                        )?,
                    );
                    row.insert("cpu_bracket_successful".into(), json!(count));
                    row.insert(
                        "httpd_cpu_us_per_op".into(),
                        json!(httpd * 1e6 / count as f64),
                    );
                    row.insert("ciphers".into(), key(&data, "tls_ciphers")?.clone());
                    row.insert(
                        "resumed_handshakes".into(),
                        key(&data, "resumed_tls_handshakes")?.clone(),
                    );
                    tls_rows.push(Value::Object(row));
                }
            }
        }
    }
    ensure!(partial || missing.is_empty(), "{missing:?}");
    ensure!(
        configs.iter().all(|c| *c == configs[0]),
        "configuration drift between boots"
    );
    ensure!(
        execution_planes.iter().all(|p| *p == execution_planes[0]),
        "execution-plane drift"
    );
    ensure!(
        rulesets.iter().all(|r| *r == rulesets[0]),
        "firewall ruleset drift"
    );
    Ok((rows, resources, tls_rows, sources, missing))
}

/// Groups rows by `keys` and retains per-run dispersion for every numeric
/// metric shared by the whole group.
pub fn summarize(rows: &[Value], keys: &[&str]) -> Result<Vec<Value>> {
    let mut groups: BTreeMap<Vec<String>, Vec<&Value>> = BTreeMap::new();
    for row in rows {
        let group = keys
            .iter()
            .map(|name| Ok(super::json::ks(row, name)?.to_owned()))
            .collect::<Result<Vec<_>>>()?;
        groups.entry(group).or_default().push(row);
    }
    let mut result = Vec::new();
    for (group, items) in groups {
        let mut shared: BTreeSet<&String> = obj_keys(items[0])?;
        for item in &items[1..] {
            let names = obj_keys(item)?;
            shared.retain(|name| names.contains(name));
        }
        let mut metrics = Map::new();
        for metric in shared {
            if keys.contains(&metric.as_str()) || !items[0][metric.as_str()].is_number() {
                continue;
            }
            metrics.insert(
                metric.clone(),
                value_stats(items.iter().map(|row| &row[metric.as_str()]))?,
            );
        }
        let mut entry = Map::new();
        for (name, value) in keys.iter().zip(group) {
            entry.insert((*name).to_owned(), json!(value));
        }
        entry.insert("runs".into(), json!(items.len()));
        entry.insert("metrics".into(), Value::Object(metrics));
        result.push(Value::Object(entry));
    }
    Ok(result)
}

fn obj_keys(value: &Value) -> Result<BTreeSet<&String>> {
    Ok(value
        .as_object()
        .ok_or_else(|| Error::new("row is not an object"))?
        .keys()
        .collect())
}

pub fn main(raw: &[String]) -> Result<i32> {
    let args = util::Args::parse(raw, &["--manifest", "--output"], &["--partial"])?;
    let [root] = &args.exact(&["PRIVATE_ROOT"])?[..] else {
        unreachable!()
    };
    let root = Path::new(root);
    let partial = args.flag("--partial");
    let output = Path::new(args.required("--output")?);
    let manifest = read(Path::new(args.required("--manifest")?))?;
    let (component_rows, residents, component_sources, component_missing) =
        components(root, &manifest, partial)?;
    let (whole_rows, resources, tls_rows, window_sources, window_missing) =
        windows(root, &manifest, partial)?;
    let mut final_missing = Vec::new();
    let component_root = root.join("components");
    if component_root.join("COMPLETE").exists() {
        ensure!(
            bytes(&component_root.join("config-before.sha256"))?
                == bytes(&component_root.join("config-after.sha256"))?,
            "component host configuration changed"
        );
    } else {
        final_missing.push("component-host-final-verification".to_owned());
    }
    let final_health = root.join("final-health.json");
    if final_health.exists() {
        let health = read(&final_health)?;
        ensure!(
            health.get("mode").and_then(Value::as_str) == Some("rust")
                && list(&health, "verified_components")?.len() == 9,
            "final health is not the verified Rust stack"
        );
        ensure!(
            py_eq(
                key(&health, "boot_id")?,
                at(
                    &read(&root.join("windows/rust-2/health.json"))?,
                    &["post", "boot_id"]
                )?
            ),
            "final health boot differs from rust-2"
        );
    } else {
        final_missing.push("final-rust-health".to_owned());
    }
    ensure!(partial || final_missing.is_empty(), "{final_missing:?}");
    let complete =
        component_missing.is_empty() && window_missing.is_empty() && final_missing.is_empty();
    let component_runs = component_sources.len();
    let window_count = resources.len();
    let rows: Vec<Value> = component_rows
        .into_iter()
        .chain(whole_rows)
        .chain(tls_rows)
        .collect();
    let pending: Vec<String> = component_missing
        .into_iter()
        .chain(window_missing)
        .chain(final_missing)
        .collect();
    let pending_count = pending.len();
    let sources: Vec<Value> = component_sources
        .into_iter()
        .chain(window_sources)
        .collect();
    let mut result = Map::new();
    result.insert("schema".into(), json!(1));
    result.insert(
        "status".into(),
        json!(if complete { "complete" } else { "partial" }),
    );
    result.insert("image".into(), key(&manifest, "image")?.clone());
    result.insert(
        "benchmark_sha256".into(),
        at(&manifest, &["tools", "owrt-benchmark", "sha256"])?.clone(),
    );
    result.insert("notes".into(), json!({
        "aggregation": "median of per-run means; ranges and individual runs retained",
        "component_cpu": "subject plus waited children; dependencies and client reported separately",
        "whole_cpu": "six daemon own counters plus one-shot program children; mixed outer interval only",
        "tls_cpu": "HTTP daemon; entire invocation includes counted warm-up and SSH sampling",
        "rss": "not PSS/USS; shared mappings can be counted more than once",
        "idle_after_memory": "includes raw output on tmpfs; use idle-before for main memory comparison",
        "page_cache": "integrity verification reads full executables and reference copies; MemAvailable is conditional on this cache state",
        "common_tls": "one boot per implementation; measured after primary samples"}));
    result.insert("pending".into(), json!(pending));
    let workload_rows = rows.len();
    let summaries = summarize(&rows, &["study", "component", "workload", "side"])?;
    let component_memory = summarize(&residents, &["component", "side"])?;
    result.insert("rows".into(), Value::Array(rows));
    result.insert("summaries".into(), Value::Array(summaries));
    result.insert("component_residents".into(), Value::Array(residents));
    result.insert("component_memory".into(), Value::Array(component_memory));
    result.insert("windows".into(), Value::Array(resources));
    result.insert("sources".into(), Value::Array(sources));
    for name in [
        "configuration_equal_across_completed_windows",
        "execution_plane_equal_across_completed_windows",
        "nft_rules_equal_after_counter_normalization",
    ] {
        result.insert(name.into(), json!(true));
    }
    let result = Value::Object(result);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, util::pretty_json(&result) + "\n")?;
    println!(
        "{}",
        util::line_json(
            &json!({"status": result["status"], "component_runs": component_runs, "windows": window_count,
                                            "workload_rows": workload_rows, "pending": pending_count})
        )
    );
    Ok(0)
}

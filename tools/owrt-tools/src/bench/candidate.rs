//! `analyze-candidate`: publish derived component timings, resource counts
//! and executable hashes of one side-by-side matrix.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use regex::Regex;
use serde_json::{json, Map, Value};

use super::analyze::{component_work, logd_idle, memory, native, rounded_quantile, timing};
use super::json::{
    at, bytes, find_pid, first_word, first_words, is, json_lines, key, kf, ki, kn, lines, list,
    merge, need_pid, pid_set, read, strings, text, truthy, Procs,
};
use super::stats::{isclose, mean, num, py_eq, sum_nums, value_stats, Num};
use crate::util::{self, bail, ensure, Error, Result};

const STATIC: [&str; 6] = [
    "static_512_dat",
    "static_16k_dat",
    "static_16k_css",
    "static_image_css",
    "static_64k_dat",
    "static_1m_dat",
];
const RPCD_EXTRA: [&str; 5] = [
    "uci_get_64",
    "uci_get_authorized",
    "session_access_granted",
    "file_list",
    "session_access_64",
];
const PROCD_EXTRA: [&str; 2] = ["service_list_128", "service_list_named_128"];
const UBUSD_EXTRA: [&str; 2] = ["lookup_prefix_64", "lookup_all_128"];
const UBUSD_EXTENDED: [&str; 5] = [
    "register_1",
    "register_16",
    "event_1",
    "event_8",
    "event_nomatch",
];
const NETIFD_SERIAL: [&str; 2] = ["reload_unchanged", "events_static2"];
const TREE_METRICS: [&str; 4] = [
    "subject_tree_cpu_us_per_op",
    "dependency_tree_cpu_us_per_op",
    "client_tree_cpu_us_per_op",
    "command_tree_cpu_us_per_op",
];
const RUSAGE_CHILD_FIELDS: [&str; 3] = [
    "rusage_children_user_us",
    "rusage_children_system_us",
    "rusage_children_counter_source",
];
const METRICS: [&str; 8] = [
    "mean_us",
    "p50_us",
    "p95_us",
    "p99_us",
    "ops_per_s",
    "subject_cpu_us_per_op",
    "dependency_cpu_us_per_op",
    "client_cpu_us_per_op",
];
const RELOAD_METRICS: [&str; 5] = [
    "ubusd_cpu_clock_us_per_op",
    "receiver_cpu_clock_us_per_op",
    "logd_cpu_clock_us_per_op",
    "prepare_us_per_op",
    "validation_us_per_op",
];
const CLOCK_METRICS: [&str; 3] = [
    "subject_own_cpu_clock_us_per_op",
    "dependency_own_cpu_clock_us_per_op",
    "client_cpu_clock_us_per_op",
];
/// Sorted, as the Python tuple.
const NATIVE_COMPONENTS: [&str; 10] = [
    "dnsmasq",
    "fw4",
    "httpd",
    "logd",
    "netifd",
    "procd",
    "reload-config",
    "rpcd",
    "ubusd",
    "uci",
];
const RUSAGE_SOURCE: &str = "getrusage(RUSAGE_CHILDREN)";

fn set<'a>(items: impl IntoIterator<Item = &'a str>) -> BTreeSet<&'a str> {
    items.into_iter().collect()
}

fn unique(items: &[String]) -> bool {
    items.iter().collect::<BTreeSet<_>>().len() == items.len()
}

fn subset(items: &[String], allowed: &[String]) -> bool {
    items.iter().all(|item| allowed.contains(item))
}

/// Binds native-only health evidence without changing historical mode gates.
fn verify_native_health(
    root: &Path,
    settings: &Value,
    before: &Value,
    after: &Value,
) -> Result<Map<String, Value>> {
    let modes = [settings.get("stack"), before.get("mode"), after.get("mode")];
    if !modes.iter().any(|mode| is(*mode, "native")) {
        return Ok(Map::new());
    }
    ensure!(
        modes.iter().all(|mode| is(*mode, "native")),
        "native health mode mismatch"
    );
    let manifest_bytes = bytes(&root.join("native-manifest.json"))?;
    let manifest_sha = util::sha256_bytes(&manifest_bytes);
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        is(manifest.get("deployment_layout"), "native-ten"),
        "native manifest layout mismatch"
    );
    let components = super::json::obj(&manifest, "components")?;
    ensure!(
        components
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == set(NATIVE_COMPONENTS),
        "native manifest must cover exactly ten components"
    );
    let source = super::json::ks(&manifest, "source_commit")?;
    ensure!(
        Regex::new("^[0-9a-f]{40}$")?.is_match(source),
        "invalid native source commit"
    );
    ensure!(
        is(settings.get("native_manifest_sha256"), &manifest_sha),
        "native manifest bytes changed"
    );
    let identity_bytes = bytes(&root.join("host-running-hashes.txt"))?;
    let identity = String::from_utf8(identity_bytes.clone())?;
    for health in [before, after] {
        let verified = strings(list(health, "verified_components")?)?;
        ensure!(
            verified.len() == 10
                && verified.iter().map(String::as_str).collect::<BTreeSet<_>>()
                    == set(NATIVE_COMPONENTS),
            "native health must verify exactly ten components"
        );
        ensure!(
            is(health.get("native_manifest_sha256"), &manifest_sha),
            "native health manifest mismatch"
        );
        ensure!(
            is(health.get("native_source_commit"), source),
            "native health source mismatch"
        );
        ensure!(
            is(health.get("native_identity"), &identity),
            "native health identity mismatch"
        );
    }
    let (digest_re, number_re) = (Regex::new("^[0-9a-f]{64}$")?, Regex::new("^[0-9]+$")?);
    let (mut names, mut pids) = (Vec::new(), BTreeSet::new());
    for line in util::splitlines(&identity) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [name, pid, start, digest] = fields[..] else {
            bail!("invalid native identity row")
        };
        ensure!(
            NATIVE_COMPONENTS.contains(&name),
            "unknown native component"
        );
        ensure!(
            name == "dnsmasq" || !names.contains(&name),
            "duplicate native component"
        );
        names.push(name);
        ensure!(digest_re.is_match(digest), "invalid native binary hash");
        ensure!(
            is(
                at(&manifest, &["components", name])?.get("rust_sha256"),
                digest
            ),
            "native binary differs from manifest"
        );
        if matches!(name, "uci" | "reload-config" | "fw4") {
            ensure!(
                pid == "-" && start == "-",
                "native CLI has a daemon identity"
            );
        } else {
            ensure!(
                number_re.is_match(pid) && pid.parse::<u128>().is_ok_and(|pid| pid > 0),
                "invalid native daemon PID"
            );
            ensure!(
                number_re.is_match(start),
                "invalid native daemon start time"
            );
            let pid: u128 = pid.parse()?;
            ensure!(pids.insert(pid), "duplicate native daemon PID");
            ensure!(name != "procd" || pid == 1, "native procd must be PID 1");
        }
    }
    ensure!(
        names.iter().copied().collect::<BTreeSet<_>>() == set(NATIVE_COMPONENTS),
        "native identities must cover exactly ten components"
    );
    for (index, side) in strings(
        read(&root.join("order.json"))?
            .as_array()
            .ok_or_else(|| Error::new("order is not a list"))?,
    )?
    .iter()
    .enumerate()
    {
        let local = root.join(format!("{:02}-{side}", index + 1));
        for phase in ["before", "after"] {
            ensure!(
                bytes(&local.join(format!("production-{phase}.txt")))? == identity_bytes,
                "native production identity changed"
            );
        }
    }
    let mut health = Map::new();
    health.insert("native_health".into(), json!({"mode": "native", "verified_components": NATIVE_COMPONENTS,
                                                   "source_commit": source, "manifest_sha256": manifest_sha,
                                                   "identity_sha256": util::sha256_bytes(&identity_bytes)}));
    Ok(health)
}

fn process_clock_delta(before: &Value, after: &Value) -> Result<Num> {
    ensure!(
        py_eq(key(before, "pid")?, key(after, "pid")?)
            && py_eq(key(before, "start_ticks")?, key(after, "start_ticks")?),
        "CPU clock process replaced"
    );
    let resolution = kf(before, "process_cpu_resolution_ns")?;
    ensure!(
        resolution == kf(after, "process_cpu_resolution_ns")? && resolution > 0.0,
        "CPU clock resolution changed"
    );
    let delta = kn(after, "process_cpu_ns")?.sub(kn(before, "process_cpu_ns")?);
    ensure!(delta.f() >= 0.0, "process CPU clock regressed");
    Ok(delta)
}

fn same(value: &Value, number: Num) -> Result<bool> {
    Ok(num(value)?.f() == number.f())
}

fn resource_pair(
    before: &Value,
    after: &Value,
    subject: &Value,
    pid: Option<&Value>,
) -> Result<Value> {
    let pid = before.get("pid").or(pid).filter(|pid| !pid.is_null());
    let pid = pid.ok_or_else(|| Error::new("resource PID is missing"))?;
    ensure!(
        py_eq(after.get("pid").unwrap_or(pid), pid),
        "resource PID changed"
    );
    ensure!(
        py_eq(key(before, "start_ticks")?, key(after, "start_ticks")?),
        "resource process replaced"
    );
    const FIELDS: [&str; 10] = [
        "VmRSS",
        "RssAnon",
        "RssFile",
        "RssShmem",
        "VmHWM",
        "fds",
        "Threads",
        "process_cpu_resolution_ns",
        "voluntary_ctxt_switches",
        "nonvoluntary_ctxt_switches",
    ];
    let present = |snapshot: &Value| -> Map<String, Value> {
        FIELDS
            .iter()
            .filter_map(|name| {
                snapshot
                    .get(*name)
                    .map(|value| ((*name).to_owned(), value.clone()))
            })
            .collect()
    };
    Ok(
        json!({"pid": pid, "role": if py_eq(pid, subject) { "subject" } else { "dependency" },
              "before": present(before), "after": present(after)}),
    )
}

/// Monitored PIDs by role, in the Python dict order.
struct Groups {
    roles: [(&'static str, Vec<Value>); 3],
}

impl Groups {
    fn get(&self, role: &str) -> &[Value] {
        self.roles
            .iter()
            .find(|entry| entry.0 == role)
            .map_or(&[], |entry| &entry.1)
    }

    fn holds(&self, role: &str, pid: &Value) -> bool {
        self.get(role).iter().any(|member| py_eq(member, pid))
    }
}

fn role_groups(data: &Value, subject: &Value, roles: Option<&Value>) -> Result<Groups> {
    let daemons = list(data, "daemon_cpu")?;
    let processes = Procs::new(daemons)?;
    ensure!(processes.len() == daemons.len(), "duplicate monitored PID");
    let Some(roles) = roles else {
        let subjects = if subject.is_null() {
            vec![]
        } else {
            vec![subject.clone()]
        };
        let dependencies = processes
            .iter()
            .map(|(pid, _)| pid)
            .filter(|pid| !py_eq(pid, subject))
            .cloned()
            .collect();
        return Ok(Groups {
            roles: [
                ("subject", subjects),
                ("dependency", dependencies),
                ("caller_instrumentation", vec![]),
            ],
        });
    };
    ensure!(
        py_eq(key(roles, "schema")?, &json!(1)),
        "unknown role schema"
    );
    let records = list(roles, "processes")?;
    let record_pids = records
        .iter()
        .map(|record| key(record, "pid"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        pid_set(record_pids.iter().copied()).len() == records.len(),
        "duplicate role PID"
    );
    ensure!(
        pid_set(record_pids.iter().copied()) == processes.keys(),
        "roles must cover every monitored PID"
    );
    let mut groups = Groups {
        roles: [
            ("subject", vec![]),
            ("dependency", vec![]),
            ("caller_instrumentation", vec![]),
        ],
    };
    for record in records {
        let pid = key(record, "pid")?;
        let process = processes.need(pid)?;
        let role = super::json::ks(record, "role")?;
        let group = groups
            .roles
            .iter_mut()
            .find(|entry| entry.0 == role)
            .ok_or_else(|| Error::new(format!("unknown role {role}")))?;
        let start = key(record, "start_ticks")?;
        ensure!(
            py_eq(start, at(process, &["before", "start_ticks"])?)
                && py_eq(start, at(process, &["after", "start_ticks"])?),
            "role PID replaced"
        );
        group.1.push(pid.clone());
    }
    ensure!(
        py_eq(&json!(groups.get("subject")), &json!([subject])),
        "subject role mismatch"
    );
    Ok(groups)
}

fn child_cpu_parent(
    before: &Value,
    after: &Value,
    hz: f64,
    caller: bool,
    proc_child_s: Option<f64>,
) -> Result<Value> {
    ensure!(
        hz > 0.0
            && py_eq(key(before, "pid")?, key(after, "pid")?)
            && py_eq(key(before, "start_ticks")?, key(after, "start_ticks")?),
        "child CPU parent replaced"
    );
    let ticks = [
        key(before, "child_cpu_ticks")?,
        key(after, "child_cpu_ticks")?,
    ];
    ensure!(
        ticks.iter().all(|value| value.is_u64()),
        "invalid raw child ticks"
    );
    let ticks = ticks.map(|value| value.as_u64().unwrap_or_default() as i64);
    let tick_delta = ticks[1] - ticks[0];
    ensure!(tick_delta >= 0, "child CPU ticks regressed");
    if let Some(proc_child_s) = proc_child_s {
        ensure!(
            isclose(proc_child_s, tick_delta as f64 / hz, 1e-12, 1e-12),
            "child summary differs from raw ticks"
        );
    }
    let present: Vec<bool> = [before, after]
        .iter()
        .flat_map(|p| RUSAGE_CHILD_FIELDS.map(|field| p.get(field).is_some()))
        .collect();
    let mut source = "proc-stat-cutime+cstime";
    let (mut child_us, mut error_us) = (json!(tick_delta as f64 * 1e6 / hz), json!(2.0 * 1e6 / hz));
    if present.iter().any(|&field| field) {
        ensure!(
            caller && present.iter().all(|&field| field),
            "partial or non-caller rusage child counters"
        );
        ensure!(
            is(before.get(RUSAGE_CHILD_FIELDS[2]), RUSAGE_SOURCE)
                && is(after.get(RUSAGE_CHILD_FIELDS[2]), RUSAGE_SOURCE),
            "child counter source changed"
        );
        let mut total = 0i64;
        for field in &RUSAGE_CHILD_FIELDS[..2] {
            let values = [key(before, field)?, key(after, field)?];
            ensure!(
                values.iter().all(|value| value.is_u64()),
                "invalid rusage child counter"
            );
            let delta = values[1].as_u64().unwrap_or_default() as i64
                - values[0].as_u64().unwrap_or_default() as i64;
            ensure!(delta >= 0, "rusage child counter regressed");
            total += delta;
        }
        source = RUSAGE_SOURCE;
        (child_us, error_us) = (json!(total), json!(2));
    }
    Ok(
        json!({"pid": key(before, "pid")?, "start_ticks": key(before, "start_ticks")?,
              "child_counter_source": source, "child_cpu_us": child_us,
              "child_delta_representation_error_us": error_us,
              "proc_child_ticks_before": ticks[0], "proc_child_ticks_after": ticks[1]}),
    )
}

fn tree_component(
    own_us: f64,
    child_us: f64,
    parents: Vec<Value>,
    denominator: i64,
    hz: f64,
) -> Result<Value> {
    ensure!(
        own_us >= 0.0 && child_us >= 0.0 && denominator > 0 && hz > 0.0,
        "invalid tree CPU inputs"
    );
    let pids = parents
        .iter()
        .map(|p| key(p, "pid"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        pid_set(pids).len() == parents.len(),
        "tree CPU parent counted twice"
    );
    let error_us = sum_nums(
        parents
            .iter()
            .map(|p| kn(p, "child_delta_representation_error_us"))
            .collect::<Result<Vec<_>>>()?,
    )
    .f();
    Ok(
        json!({"own_us_per_op": own_us, "reaped_child_us_per_op": child_us,
              "source": "process-clock-own plus per-parent child counters",
              "parents": parents, "denominator_ops": denominator,
              "child_window_quantization_us_per_op": error_us / denominator as f64,
              "child_paired_quantization_us_per_op": 2.0 * error_us / denominator as f64,
              "child_error_scope": "counter export representation only; not kernel accounting accuracy or observed granularity"}),
    )
}

fn sum_child_us(parents: &[Value]) -> Result<f64> {
    Ok(sum_nums(
        parents
            .iter()
            .map(|p| kn(p, "child_cpu_us"))
            .collect::<Result<Vec<_>>>()?,
    )
    .f())
}

fn tree_totals(components: Map<String, Value>) -> Result<Map<String, Value>> {
    let mut trees = Map::new();
    for (role, value) in &components {
        trees.insert(
            format!("{role}_tree_cpu_us_per_op"),
            json!(kf(value, "own_us_per_op")? + kf(value, "reaped_child_us_per_op")?),
        );
    }
    trees.insert("tree_cpu_components".into(), Value::Object(components));
    Ok(trees)
}

fn serial_trees(data: &Value, groups: &Groups) -> Result<Map<String, Value>> {
    let count = ki(data, "successful")?;
    let hz = kf(data, "clock_ticks_per_second")?;
    let processes = Procs::new(list(data, "daemon_cpu")?)?;
    let mut values = Map::new();
    for (role, source) in [
        ("subject", "subject"),
        ("dependency", "dependency"),
        ("client", "caller_instrumentation"),
    ] {
        let selected = groups
            .get(source)
            .iter()
            .map(|pid| processes.need(pid))
            .collect::<Result<Vec<_>>>()?;
        let clock = sum_nums(
            selected
                .iter()
                .map(|p| kn(p, "cpu_clock_ns"))
                .collect::<Result<Vec<_>>>()?,
        );
        let mut own = clock.f() / 1000.0 / count as f64;
        let mut parents = selected
            .iter()
            .map(|p| {
                child_cpu_parent(
                    key(p, "before")?,
                    key(p, "after")?,
                    hz,
                    false,
                    Some(kf(p, "child_cpu_s")?),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        if role == "client" {
            own += kf(data, "client_cpu_clock_ns")? / 1000.0 / count as f64;
            parents.push(child_cpu_parent(
                key(data, "client_before")?,
                key(data, "client_after")?,
                hz,
                true,
                Some(kf(data, "child_cpu_s")?),
            )?);
        }
        let child = sum_child_us(&parents)? / count as f64;
        values.insert(role.into(), tree_component(own, child, parents, count, hz)?);
    }
    tree_totals(values)
}

/// Only exec intervals count; reset/check/repeat/resource work is separate.
pub fn prepared_exec(path: &Path, data: &Value) -> Result<Value> {
    let count = ki(data, "successful")?;
    let samples = list(data, "measured")?;
    ensure!(
        is(data.get("mode"), "prepared-exec") && samples.len() as i64 == count,
        "invalid prepared-exec result"
    );
    let latencies = samples
        .iter()
        .map(|s| key(s, "latency_ns").cloned())
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        py_eq(&Value::Array(latencies), key(data, "latency_ns")?),
        "prepared latency series differs"
    );
    let (resource_samples, task_samples, warmup) = (
        ki(data, "resource_samples")?,
        ki(data, "task_samples")?,
        ki(data, "warmup")?,
    );
    ensure!(
        kf(data, "timeouts")? == 0.0 && matches!(resource_samples, 0 | 3),
        "invalid prepared-exec counters"
    );
    ensure!(
        matches!(task_samples, 0 | 1),
        "invalid prepared-exec task samples"
    );
    let latency_total = sum_nums(
        list(data, "latency_ns")?
            .iter()
            .map(num)
            .collect::<Result<Vec<_>>>()?,
    );
    ensure!(
        isclose(kf(data, "wall_s")?, latency_total.f() / 1e9, 1e-9, 0.0),
        "prepared wall includes reset/check work"
    );
    ensure!(
        kf(data, "envelope_s")? >= kf(data, "wall_s")?,
        "prepared envelope is shorter than exec time"
    );
    let raw = path
        .parent()
        .ok_or_else(|| Error::new("prepared result has no directory"))?;
    let lane = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| Error::new("invalid prepared lane"))?;
    let artifacts = raw.join(lane);
    let variant = match lane {
        "single_change" => "single",
        "multi_change" => "multi",
        "comment_only" => "comment",
        _ => "base",
    };
    let expected_md5 = bytes(&raw.join(format!("{variant}.md5")))?;
    let packages: &[&[u8]] = match lane {
        "single_change" => &[b"network"],
        "multi_change" => &[b"firewall", b"network", b"r84fixture"],
        _ => &[],
    };
    let mut expected_events = Vec::new();
    for package in packages {
        expected_events.extend_from_slice(&(package.len() as u32).to_le_bytes());
        expected_events.extend_from_slice(package);
        expected_events.extend_from_slice(&[0; 4]);
    }
    ensure!(
        bytes(&artifacts.join("expected.md5"))? == expected_md5,
        "expected baseline differs"
    );
    ensure!(
        bytes(&artifacts.join("expected.events"))? == expected_events,
        "expected events differ"
    );
    let journal = json_lines(&artifacts.join("samples.jsonl"))?;
    let total = warmup + count + resource_samples + task_samples;
    ensure!(
        journal.len() as i64 == total * 2,
        "incomplete per-invocation journal"
    );
    let (mut measured, mut resources, mut tasks) = (Vec::new(), Vec::new(), Vec::new());
    for index in 0..total {
        let (start, end) = (
            &journal[index as usize * 2],
            &journal[index as usize * 2 + 1],
        );
        let phase = if index < warmup {
            "warmup"
        } else if index < warmup + count {
            "measured"
        } else if index < warmup + count + resource_samples {
            "resource"
        } else {
            "tasks"
        };
        ensure!(
            py_eq(key(start, "iteration")?, &json!(index))
                && py_eq(key(end, "iteration")?, &json!(index))
                && is(start.get("phase"), phase)
                && is(end.get("phase"), phase),
            "journal order differs"
        );
        ensure!(
            is(start.get("event"), "started") && is(end.get("event"), "completed"),
            "journal event differs"
        );
        ensure!(
            truthy(Some(key(end, "baseline_matches")?))
                && truthy(Some(key(end, "events_match")?))
                && truthy(Some(key(end, "repeat_silent")?)),
            "invocation check failed"
        );
        let one = artifacts.join(format!("iteration-{index:06}"));
        for execution in ["exec", "repeat"] {
            ensure!(
                bytes(&one.join(format!("{execution}.stdout")))?.is_empty(),
                "{execution} wrote stdout"
            );
            ensure!(
                bytes(&one.join(format!("{execution}.stderr")))?.is_empty(),
                "{execution} wrote stderr"
            );
            ensure!(
                text(&one.join(format!("{execution}.status")))?.trim() == "exit status: 0",
                "{execution} failed"
            );
        }
        let after_md5 = bytes(&one.join("after.md5"))?;
        ensure!(
            after_md5 == bytes(&one.join("repeat.md5"))? && after_md5 == expected_md5,
            "configuration baseline differs"
        );
        ensure!(
            bytes(&one.join("after.events"))? == expected_events,
            "reload events differ"
        );
        ensure!(
            bytes(&one.join("repeat.events"))?.is_empty(),
            "silent repeat emitted events"
        );
        match phase {
            "measured" => measured.push(end.clone()),
            "resource" => {
                let resource = read(&one.join("resource.json"))?;
                ensure!(
                    py_eq(key(&resource, "schema")?, &json!(1))
                        && is(resource.get("method"), "wait4")
                        && py_eq(key(&resource, "exit")?, &json!(0)),
                    "invalid resource diagnostic"
                );
                resources.push(resource);
            }
            "tasks" => {
                let task = read(&one.join("tasks.json"))?;
                ensure!(
                    py_eq(key(&task, "schema")?, &json!(1))
                        && is(task.get("method"), "ptrace")
                        && py_eq(key(&task, "exit")?, &json!(0)),
                    "invalid task diagnostic"
                );
                ensure!(
                    kf(&task, "processes")? >= 1.0
                        && kf(&task, "threads")? >= 1.0
                        && kf(&task, "live_remaining")? == 0.0,
                    "invalid task counts"
                );
                tasks.push(task);
            }
            _ => {}
        }
    }
    ensure!(
        py_eq(&Value::Array(measured), &Value::Array(samples.clone())),
        "timing series differs from durable per-invocation evidence"
    );
    let roles = read(&raw.join("reload-roles.json"))?;
    let roles = roles
        .as_object()
        .ok_or_else(|| Error::new("reload roles are not an object"))?;
    ensure!(
        roles.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == set(["ubusd", "receiver", "logd"])
            && pid_set(roles.values()).len() == 3,
        "invalid reload roles"
    );
    let mut dependency_ns: Vec<(String, Num)> = roles
        .keys()
        .map(|role| (role.clone(), Num::Int(0)))
        .collect();
    let (mut command_us, mut caller_ns, mut preparation_ns, mut validation_ns) =
        (Num::Int(0), Num::Int(0), Num::Int(0), Num::Int(0));
    for sample in samples {
        ensure!(is(sample.get("phase"), "measured"), "non-measured sample");
        for field in [
            "command_user_us",
            "command_system_us",
            "caller_cpu_ns",
            "prepare_ns",
            "validation_ns",
        ] {
            ensure!(key(sample, field)?.is_u64(), "invalid {field}");
        }
        ensure!(
            is(sample.get("child_counter_source"), RUSAGE_SOURCE),
            "invalid child counter source"
        );
        for field in ["user", "system"] {
            let delta = kn(key(sample, "command_after")?, &format!("{field}_us"))?
                .sub(kn(key(sample, "command_before")?, &format!("{field}_us"))?);
            ensure!(
                same(key(sample, &format!("command_{field}_us"))?, delta)?,
                "command CPU differs from per-exec raw counters"
            );
        }
        command_us = command_us
            .add(kn(sample, "command_user_us")?)
            .add(kn(sample, "command_system_us")?);
        caller_ns = caller_ns.add(kn(sample, "caller_cpu_ns")?);
        preparation_ns = preparation_ns.add(kn(sample, "prepare_ns")?);
        validation_ns = validation_ns.add(kn(sample, "validation_ns")?);
        let processes = Procs::new(list(sample, "dependencies")?)?;
        ensure!(
            processes.keys() == pid_set(roles.values()),
            "reload dependencies differ from roles"
        );
        for (role, total) in &mut dependency_ns {
            let process = processes.need(&roles[role.as_str()])?;
            ensure!(
                same(
                    key(process, "cpu_clock_ns")?,
                    process_clock_delta(key(process, "before")?, key(process, "after")?)?
                )?,
                "dependency CPU clock differs from raw counters"
            );
            ensure!(
                py_eq(
                    at(process, &["before", "child_cpu_ticks"])?,
                    at(process, &["after", "child_cpu_ticks"])?
                ),
                "dependency reaped children during exec"
            );
            *total = total.add(kn(process, "cpu_clock_ns")?);
        }
    }
    let envelope = Procs::new(list(data, "dependency_envelope")?)?;
    ensure!(
        envelope.keys() == pid_set(roles.values()),
        "dependency envelope differs from roles"
    );
    for (_, process) in envelope.iter() {
        ensure!(
            same(
                key(process, "cpu_clock_ns")?,
                process_clock_delta(key(process, "before")?, key(process, "after")?)?
            )?,
            "dependency envelope differs from raw counters"
        );
    }
    let count = count as f64;
    let dependency_total = sum_nums(dependency_ns.iter().map(|entry| entry.1)).f();
    let mut result = timing(data)?;
    result.insert("warmup".into(), key(data, "warmup")?.clone());
    result.insert("errors".into(), json!(0));
    result.insert("timeouts".into(), json!(0));
    result.insert(
        "command_tree_cpu_us_per_op".into(),
        json!(command_us.f() / count),
    );
    result.insert(
        "client_cpu_clock_us_per_op".into(),
        json!(caller_ns.f() / 1000.0 / count),
    );
    result.insert(
        "dependency_own_cpu_clock_us_per_op".into(),
        json!(dependency_total / 1000.0 / count),
    );
    for (role, ns) in &dependency_ns {
        result.insert(
            format!("{role}_cpu_clock_us_per_op"),
            json!(ns.f() / 1000.0 / count),
        );
    }
    result.insert(
        "subject_cpu_us_per_op".into(),
        json!(command_us.f() / count),
    );
    result.insert(
        "dependency_cpu_us_per_op".into(),
        json!(dependency_total / 1000.0 / count),
    );
    result.insert(
        "client_cpu_us_per_op".into(),
        json!(caller_ns.f() / 1000.0 / count),
    );
    result.insert(
        "prepare_us_per_op".into(),
        json!(preparation_ns.f() / 1000.0 / count),
    );
    result.insert(
        "validation_us_per_op".into(),
        json!(validation_ns.f() / 1000.0 / count),
    );
    result.insert("envelope_s".into(), key(data, "envelope_s")?.clone());
    result.insert("resources".into(), Value::Array(resources));
    result.insert("task_diagnostics".into(), Value::Array(tasks));
    let mut envelope_cpu = Map::new();
    for (role, pid) in roles {
        envelope_cpu.insert(
            role.clone(),
            json!(kf(envelope.need(pid)?, "cpu_clock_ns")? / 1000.0),
        );
    }
    result.insert(
        "dependency_envelope_cpu_us".into(),
        Value::Object(envelope_cpu),
    );
    result.insert("accounting".into(), key(data, "accounting")?.clone());
    result.insert(
        "resource_method".into(),
        json!("separate wait4 lifecycle; maxrss is not concurrent tree RSS"),
    );
    Ok(Value::Object(result))
}

pub fn serial(path: &Path, subject: &Value, roles: Option<&Value>) -> Result<Value> {
    let data = native(path)?;
    if is(data.get("mode"), "prepared-exec") {
        ensure!(subject.is_null(), "prepared exec has no resident subject");
        return prepared_exec(path, &data);
    }
    let groups = role_groups(&data, subject, roles)?;
    let daemons = list(&data, "daemon_cpu")?;
    let mut dependencies = Vec::new();
    let mut observers = Vec::new();
    for process in daemons {
        let pid = key(process, "pid")?;
        if groups.holds("dependency", pid) {
            dependencies.push(process);
        }
        if groups.holds("caller_instrumentation", pid) {
            observers.push(process);
        }
    }
    let own = find_pid(daemons, subject)?;
    ensure!(
        subject.is_null() || own.is_some(),
        "measured daemon is missing"
    );
    let cpu = match own {
        Some(own) if !subject.is_null() => kf(own, "cpu_s")? + kf(own, "child_cpu_s")?,
        _ => kf(&data, "child_cpu_s")?,
    };
    let count = ki(&data, "successful")? as f64;
    let sum = |processes: &[&Value], field: &str| -> Result<f64> {
        Ok(sum_nums(
            processes
                .iter()
                .map(|p| kn(p, field))
                .collect::<Result<Vec<_>>>()?,
        )
        .f())
    };
    let mut clocks = Map::new();
    if data.get("client_cpu_clock_ns").is_some() {
        ensure!(
            same(
                key(&data, "client_cpu_clock_ns")?,
                process_clock_delta(key(&data, "client_before")?, key(&data, "client_after")?)?
            )?,
            "client CPU clock differs from raw counters"
        );
        clocks.insert(
            "client_cpu_clock_us_per_op".into(),
            json!(kf(&data, "client_cpu_clock_ns")? / 1000.0 / count),
        );
        if let (Some(own), false) = (own, subject.is_null()) {
            for process in daemons {
                ensure!(
                    same(
                        key(process, "cpu_clock_ns")?,
                        process_clock_delta(key(process, "before")?, key(process, "after")?)?
                    )?,
                    "daemon CPU clock differs from raw counters"
                );
            }
            clocks.insert(
                "subject_own_cpu_clock_us_per_op".into(),
                json!(kf(own, "cpu_clock_ns")? / 1000.0 / count),
            );
            clocks.insert(
                "dependency_own_cpu_clock_us_per_op".into(),
                json!(sum(&dependencies, "cpu_clock_ns")? / 1000.0 / count),
            );
        }
    }
    let trees = if !subject.is_null() && !clocks.is_empty() {
        serial_trees(&data, &groups)?
    } else {
        Map::new()
    };
    let mut command_cpu = Map::new();
    let empty = json!({});
    let snapshots = (
        data.get("client_before").unwrap_or(&empty),
        data.get("client_after").unwrap_or(&empty),
    );
    let has_rusage = [snapshots.0, snapshots.1].iter().any(|s| {
        RUSAGE_CHILD_FIELDS
            .iter()
            .any(|field| s.get(*field).is_some())
    });
    if subject.is_null() && has_rusage {
        // Snapshots bracket only measured operations. Reaped descendants are
        // included (for set/commit/get: the shell and all three UCI processes).
        // Keep the legacy tick fields separate, and do not invent a fine count
        // for old tools without complete getrusage evidence.
        let parent = child_cpu_parent(
            snapshots.0,
            snapshots.1,
            kf(&data, "clock_ticks_per_second")?,
            true,
            Some(kf(&data, "child_cpu_s")?),
        )?;
        command_cpu.insert(
            "command_tree_cpu_us_per_op".into(),
            json!(kf(&parent, "child_cpu_us")? / count),
        );
    }
    let mut resources = Vec::new();
    for process in daemons {
        let pid = key(process, "pid")?;
        let mut resource = resource_pair(
            key(process, "before")?,
            key(process, "after")?,
            subject,
            Some(pid),
        )?;
        let resource_pid = &resource["pid"];
        let role = ["subject", "dependency", "caller_instrumentation"]
            .into_iter()
            .find(|role| groups.holds(role, resource_pid))
            .ok_or_else(|| Error::new("monitored PID has no role"))?;
        resource["role"] = json!(role);
        resources.push(resource);
    }
    let mut result = timing(&data)?;
    merge(&mut result, clocks);
    merge(&mut result, trees);
    merge(&mut result, command_cpu);
    result.insert("warmup".into(), key(&data, "warmup")?.clone());
    result.insert("errors".into(), key(&data, "errors")?.clone());
    result.insert("resources".into(), Value::Array(resources));
    result.insert(
        "clock_ticks_per_second".into(),
        data.get("clock_ticks_per_second")
            .cloned()
            .unwrap_or(Value::Null),
    );
    result.insert(
        "subject_reaped_child_cpu_us_per_op".into(),
        match own {
            Some(own) => json!(kf(own, "child_cpu_s")? * 1e6 / count),
            None => Value::Null,
        },
    );
    result.insert(
        "dependency_reaped_child_cpu_us_per_op".into(),
        json!(sum(&dependencies, "child_cpu_s")? * 1e6 / count),
    );
    result.insert(
        "client_reaped_child_cpu_us_per_op".into(),
        json!(kf(&data, "child_cpu_s")? * 1e6 / count),
    );
    result.insert(
        "caller_instrumentation_own_cpu_clock_us_per_op".into(),
        json!(sum(&observers, "cpu_clock_ns")? / 1000.0 / count),
    );
    result.insert(
        "caller_instrumentation_reaped_child_cpu_us_per_op".into(),
        json!(sum(&observers, "child_cpu_s")? * 1e6 / count),
    );
    result.insert("subject_cpu_us_per_op".into(), json!(cpu * 1e6 / count));
    result.insert(
        "dependency_cpu_us_per_op".into(),
        json!(sum(&dependencies, "cpu_s")? * 1e6 / count),
    );
    result.insert(
        "client_cpu_us_per_op".into(),
        json!(kf(&data, "client_cpu_s")? * 1e6 / count),
    );
    Ok(Value::Object(result))
}

pub fn parallel(path: &Path, subject: &Value) -> Result<Value> {
    parallel_with(path, subject, &mut native)
}

fn parallel_with(
    path: &Path,
    subject: &Value,
    load: &mut dyn FnMut(&Path) -> Result<Value>,
) -> Result<Value> {
    let group = read(&path.join("group.json"))?;
    ensure!(
        py_eq(key(&group, "clients")?, &json!(4)),
        "parallel group must have four clients"
    );
    let clients = (1..=4)
        .map(|index| load(&path.join(format!("client-{index}.json"))))
        .collect::<Result<Vec<_>>>()?;
    for client in &clients {
        ensure!(
            py_eq(
                key(client, "successful")?,
                key(&group, "iterations_per_client")?
            ) && py_eq(key(client, "warmup")?, key(&group, "warmup_per_client")?),
            "parallel client is incomplete"
        );
    }
    let mut samples = Vec::new();
    for client in &clients {
        for value in list(client, "latency_ns")? {
            samples.push(
                value
                    .as_i64()
                    .ok_or_else(|| Error::new("invalid latency sample"))?,
            );
        }
    }
    samples.sort_unstable();
    let count = samples.len() as i64;
    let warm = sum_nums(
        clients
            .iter()
            .map(|c| kn(c, "warmup"))
            .collect::<Result<Vec<_>>>()?,
    );
    let warm_ops = (count as f64) + warm.f();
    let (before, after) = (
        read(&path.join("before.json"))?,
        read(&path.join("after.json"))?,
    );
    let hz = kf(&before, "clock_ticks_per_second")?;
    ensure!(
        hz == kf(&after, "clock_ticks_per_second")? && hz > 0.0,
        "clock tick rate changed"
    );
    let elapsed = kn(&after, "uptime_s")?.sub(kn(&before, "uptime_s")?);
    ensure!(elapsed.f() > 0.0, "empty parallel interval");
    let old = Procs::new(list(&before, "processes")?)?;
    let new = Procs::new(list(&after, "processes")?)?;
    ensure!(
        old.keys() == new.keys() && old.contains(subject),
        "parallel process set changed"
    );
    let mut cpu = Vec::new();
    for (pid, process) in new.iter() {
        let previous = old.need(pid)?;
        ensure!(
            py_eq(key(process, "start_ticks")?, key(previous, "start_ticks")?),
            "server replaced during parallel run"
        );
        let own = kn(process, "cpu_ticks")?.sub(kn(previous, "cpu_ticks")?);
        let child = kn(process, "child_cpu_ticks")?.sub(kn(previous, "child_cpu_ticks")?);
        ensure!(own.f() >= 0.0 && child.f() >= 0.0, "CPU ticks regressed");
        cpu.push((pid, own.add(child).f() / hz));
    }
    let mut clocks = Map::new();
    let mut own_ns = Vec::new();
    if old.need(subject)?.get("process_cpu_ns").is_some() {
        for (pid, process) in new.iter() {
            own_ns.push((pid, process_clock_delta(old.need(pid)?, process)?.f()));
        }
        for client in &clients {
            ensure!(
                same(
                    key(client, "client_cpu_clock_ns")?,
                    process_clock_delta(
                        key(client, "client_before")?,
                        key(client, "client_after")?
                    )?
                )?,
                "client CPU clock differs from raw counters"
            );
        }
        let subject_ns = own_ns
            .iter()
            .find(|entry| py_eq(entry.0, subject))
            .map_or(0.0, |entry| entry.1);
        let dependency_ns: f64 = own_ns
            .iter()
            .filter(|entry| !py_eq(entry.0, subject))
            .map(|entry| entry.1)
            .sum();
        let client_ns = sum_nums(
            clients
                .iter()
                .map(|c| kn(c, "client_cpu_clock_ns"))
                .collect::<Result<Vec<_>>>()?,
        )
        .f();
        clocks.insert(
            "subject_own_cpu_clock_us_per_op".into(),
            json!(subject_ns / 1000.0 / warm_ops),
        );
        clocks.insert(
            "dependency_own_cpu_clock_us_per_op".into(),
            json!(dependency_ns / 1000.0 / warm_ops),
        );
        clocks.insert(
            "client_cpu_clock_us_per_op".into(),
            json!(client_ns / 1000.0 / count as f64),
        );
    }
    let mut trees = Map::new();
    if !clocks.is_empty() {
        let mut components = Map::new();
        let denominator = count + warm.f() as i64;
        let selections: [(&str, Vec<&Value>); 2] = [
            ("subject", vec![subject]),
            (
                "dependency",
                new.iter()
                    .map(|(pid, _)| pid)
                    .filter(|pid| !py_eq(pid, subject))
                    .collect(),
            ),
        ];
        for (role, selected) in selections {
            let own: f64 = selected
                .iter()
                .map(|pid| {
                    own_ns
                        .iter()
                        .find(|entry| py_eq(entry.0, pid))
                        .map_or(0.0, |entry| entry.1)
                })
                .sum::<f64>()
                / 1000.0
                / warm_ops;
            let parents = selected
                .iter()
                .map(|pid| child_cpu_parent(old.need(pid)?, new.need(pid)?, hz, false, None))
                .collect::<Result<Vec<_>>>()?;
            let child = sum_child_us(&parents)? / warm_ops;
            components.insert(
                role.into(),
                tree_component(own, child, parents, denominator, hz)?,
            );
        }
        let mut caller_parents = Vec::new();
        for client in &clients {
            ensure!(
                kf(client, "clock_ticks_per_second")? == hz,
                "client HZ differs from outer interval"
            );
            caller_parents.push(child_cpu_parent(
                key(client, "client_before")?,
                key(client, "client_after")?,
                hz,
                true,
                Some(kf(client, "child_cpu_s")?),
            )?);
        }
        let client_child = sum_child_us(&caller_parents)? / count as f64;
        components.insert(
            "client".into(),
            tree_component(
                kf(&Value::Object(clocks.clone()), "client_cpu_clock_us_per_op")?,
                client_child,
                caller_parents,
                count,
                hz,
            )?,
        );
        trees = tree_totals(components)?;
    }
    let mut result = clocks;
    merge(&mut result, trees);
    if clients.iter().all(|c| c.get("child_cpu_s").is_some()) {
        let child = sum_nums(
            clients
                .iter()
                .map(|c| kn(c, "child_cpu_s"))
                .collect::<Result<Vec<_>>>()?,
        )
        .f();
        result.insert(
            "client_reaped_child_cpu_us_per_op".into(),
            json!(child * 1e6 / count as f64),
        );
    }
    let subject_old = old.need(subject)?;
    let subject_new = new.need(subject)?;
    let subject_child = kn(subject_new, "child_cpu_ticks")?
        .sub(kn(subject_old, "child_cpu_ticks")?)
        .f();
    let mut dependency_child = Num::Int(0);
    for (pid, process) in new.iter() {
        if !py_eq(pid, subject) {
            dependency_child = dependency_child
                .add(kn(process, "child_cpu_ticks")?.sub(kn(old.need(pid)?, "child_cpu_ticks")?));
        }
    }
    let ints: Vec<Num> = samples.iter().map(|&value| Num::Int(value)).collect();
    let subject_cpu = cpu
        .iter()
        .find(|entry| py_eq(entry.0, subject))
        .map_or(0.0, |entry| entry.1);
    let dependency_cpu: f64 = cpu
        .iter()
        .filter(|entry| !py_eq(entry.0, subject))
        .map(|entry| entry.1)
        .sum();
    let errors = sum_nums(
        clients
            .iter()
            .map(|c| kn(c, "errors"))
            .collect::<Result<Vec<_>>>()?,
    );
    let client_cpu = sum_nums(
        clients
            .iter()
            .map(|c| kn(c, "client_cpu_s"))
            .collect::<Result<Vec<_>>>()?,
    )
    .f();
    result.insert("successful".into(), json!(count));
    result.insert("warmup".into(), warm.value());
    result.insert("wall_s".into(), elapsed.value());
    result.insert("errors".into(), errors.value());
    result.insert(
        "clock_ticks_per_second".into(),
        key(&before, "clock_ticks_per_second")?.clone(),
    );
    result.insert(
        "resources".into(),
        Value::Array(
            new.iter()
                .map(|(pid, p)| resource_pair(old.need(pid)?, p, subject, None))
                .collect::<Result<_>>()?,
        ),
    );
    result.insert(
        "subject_reaped_child_cpu_us_per_op".into(),
        json!(subject_child / hz * 1e6 / warm_ops),
    );
    result.insert(
        "dependency_reaped_child_cpu_us_per_op".into(),
        json!(dependency_child.f() / hz * 1e6 / warm_ops),
    );
    result.insert("ops_per_s".into(), json!(count as f64 / elapsed.f()));
    result.insert("mean_us".into(), json!(mean(&ints)?.f() / 1000.0));
    for (name, quantile) in [("p50_us", 0.50), ("p95_us", 0.95), ("p99_us", 0.99)] {
        result.insert(name.into(), json!(rounded_quantile(&samples, quantile)));
    }
    result.insert(
        "subject_cpu_us_per_op".into(),
        json!(subject_cpu * 1e6 / warm_ops),
    );
    result.insert(
        "dependency_cpu_us_per_op".into(),
        json!(dependency_cpu * 1e6 / warm_ops),
    );
    result.insert(
        "client_cpu_us_per_op".into(),
        json!(client_cpu * 1e6 / count as f64),
    );
    Ok(Value::Object(result))
}

pub fn check_netifd_hotplug(
    raw: &Path,
    subject: &Value,
    count: usize,
    expected_names: &[String],
) -> Result<bool> {
    let callbacks: Vec<Vec<String>> = lines(&raw.join(format!("hotplug-settled-{count}.txt")))?
        .iter()
        .map(|line| line.split_whitespace().map(str::to_owned).collect())
        .collect();
    ensure!(
        callbacks.iter().all(|c| c.len() == 3 && c[2] == "0"),
        "hotplug callback failed"
    );
    let mut ifup: Vec<String> = callbacks
        .iter()
        .filter(|c| c[1] == "ifup")
        .map(|c| c[0].clone())
        .collect();
    ifup.sort();
    ensure!(
        ifup == expected_names,
        "incomplete or duplicate ifup callbacks"
    );
    let idle = ["before", "after"]
        .map(|phase| read(&raw.join(format!("hotplug-settled-{count}-{phase}.json"))));
    let [before, after] = idle;
    let (before, after) = (before?, after?);
    let parent = [
        need_pid(list(&before, "processes")?, subject)?,
        need_pid(list(&after, "processes")?, subject)?,
    ];
    ensure!(
        py_eq(
            key(parent[0], "start_ticks")?,
            key(parent[1], "start_ticks")?
        ),
        "netifd restarted while settling"
    );
    ensure!(
        py_eq(
            key(parent[0], "child_cpu_ticks")?,
            key(parent[1], "child_cpu_ticks")?
        ),
        "setup children still running"
    );
    let child_check = raw.join(format!("hotplug-child-check-{count}.txt"));
    Ok(child_check.is_file() && text(&child_check)?.trim() == "proc-status-ppid")
}

fn interface_names(path: &Path) -> Result<Vec<Value>> {
    let interfaces = read(path)?;
    let interfaces = list(&interfaces, "interface")?;
    Ok(interfaces.clone())
}

fn check_event_lane(raw: &Path, data: &Value) -> Result<Value> {
    let events = raw.join("events_static2");
    let roles = read(&raw.join("roles.json"))?;
    let records = list(&roles, "processes")?;
    let role_names = records
        .iter()
        .map(|r| super::json::ks(r, "role"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        role_names == set(["subject", "dependency", "caller_instrumentation"]),
        "event lane roles differ"
    );
    ensure!(
        records
            .iter()
            .filter(|r| is(r.get("role"), "caller_instrumentation"))
            .count()
            == 2,
        "event lane needs two observers"
    );
    let contract = read(&raw.join("event-contract.json"))?;
    let actions = ["lan-down", "lan-up", "wired-down", "wired-up"];
    let (warmup, successful) = (ki(data, "warmup")?, ki(data, "successful")?);
    let total = warmup + successful;
    let journal = json_lines(&raw.join("events_static2-journal.jsonl"))?;
    ensure!(
        journal.len() as i64 == total * 2,
        "incomplete event journal"
    );
    let mut measured = Vec::new();
    for index in 0..total {
        let (start, end) = (
            &journal[index as usize * 2],
            &journal[index as usize * 2 + 1],
        );
        ensure!(
            py_eq(key(start, "iteration")?, &json!(index))
                && py_eq(key(end, "iteration")?, &json!(index)),
            "event journal order differs"
        );
        ensure!(
            is(start.get("event"), "started")
                && is(end.get("event"), "completed")
                && key(end, "error")?.is_null(),
            "event cycle failed"
        );
        ensure!(
            py_eq(key(end, "exit_code")?, &json!(0)) && key(end, "signal")?.is_null(),
            "event cycle exited abnormally"
        );
        let phase = if index < warmup { "warmup" } else { "measured" };
        ensure!(
            is(start.get("phase"), phase) && is(end.get("phase"), phase),
            "event journal phase differs"
        );
        if phase == "measured" {
            measured.push(key(end, "latency_ns")?.clone());
        }
    }
    ensure!(
        py_eq(
            &Value::Array(measured),
            key(&native(&raw.join("events_static2.json"))?, "latency_ns")?
        ),
        "event latencies differ from journal"
    );
    let names = std::iter::once("prelude".to_owned())
        .chain((0..total).map(|i| format!("iteration-{i:06}")));
    for name in names {
        let cycle = events.join(&name);
        ensure!(
            cycle.join("COMPLETE").exists() && !cycle.join("FAILED").exists(),
            "{name}: event cycle incomplete"
        );
        ensure!(
            lines(&cycle.join("actions.txt"))? == actions,
            "{name}: event actions differ"
        );
        ensure!(
            text(&cycle.join("children-reaped.txt"))?.trim() == "proc-status-ppid",
            "{name}: children not reaped"
        );
        let records = json_lines(&cycle.join("records.jsonl"))?;
        let steps = records
            .iter()
            .map(|r| Ok(super::json::ks(r, "step")?.to_owned()))
            .collect::<Result<Vec<_>>>()?;
        ensure!(steps == actions, "{name}: event records differ");
        for record in &records {
            ensure!(
                super::json::ks(at(record, &["raw"])?, "command.rc")?.trim() == "0",
                "{name}: event command failed"
            );
            ensure!(
                py_eq(
                    key(record, "evidence")?,
                    at(&contract, &["steps", super::json::ks(record, "step")?])?
                ),
                "{name}: event evidence differs"
            );
        }
        let interfaces = interface_names(&cycle.join("final-interfaces.json"))?;
        let names = interfaces
            .iter()
            .map(|i| Ok(super::json::ks(i, "interface")?.to_owned()))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            names == ["lan", "loopback", "wired"],
            "{name}: final interfaces differ"
        );
        ensure!(
            interfaces
                .iter()
                .all(|i| truthy(i.get("up")) && !truthy(i.get("pending"))),
            "{name}: interface not settled"
        );
    }
    ensure!(
        py_eq(
            &read(&events.join("cursor.json"))?,
            &read(&events.join("cursor-after.json"))?
        ),
        "event cursor changed"
    );
    ensure!(
        bytes(&events.join("listen.stderr"))?.is_empty()
            && bytes(&events.join("subscribe.stderr"))?.is_empty(),
        "event observer wrote stderr"
    );
    Ok(roles)
}

fn check_reload_lane(raw: &Path) -> Result<()> {
    let (prefix, suffix) = ("interfaces-", "-after-reload.json");
    let mut after_configs = Vec::new();
    for entry in fs::read_dir(raw)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.len() >= prefix.len() + suffix.len()
            && name.starts_with(prefix)
            && name.ends_with(suffix)
        {
            after_configs.push(raw.join(name));
        }
    }
    ensure!(
        after_configs.len() == 1,
        "missing reload state verification"
    );
    let interfaces = interface_names(&after_configs[0])?;
    ensure!(
        matches!(interfaces.len(), 32 | 64 | 128)
            && interfaces
                .iter()
                .all(|i| truthy(i.get("up")) && !truthy(i.get("pending"))),
        "reload left interfaces unsettled"
    );
    ensure!(
        text(&raw.join("reload-children-reaped.txt"))?.trim() == "proc-status-ppid",
        "reload children not reaped"
    );
    ensure!(
        bytes(&raw.join("hotplug-before-reload.txt"))?
            == bytes(&raw.join("hotplug-after-reload.txt"))?,
        "reload ran hotplug"
    );
    ensure!(
        bytes(&raw.join("reload-config-before.sha256"))?
            == bytes(&raw.join("reload-config-after.sha256"))?,
        "reload changed configuration"
    );
    if raw.join("handler-before-reload.log").exists() {
        ensure!(
            bytes(&raw.join("handler-before-reload.log"))?
                == bytes(&raw.join("handler-calls.log"))?,
            "reload called handlers"
        );
    }
    let identity = |path: &Path| -> Result<Value> {
        let snapshot = read(path)?;
        Ok(Value::Array(
            list(&snapshot, "processes")?
                .iter()
                .map(|p| Ok(json!([key(p, "pid")?, key(p, "start_ticks")?])))
                .collect::<Result<_>>()?,
        ))
    };
    ensure!(
        py_eq(
            &identity(&raw.join("reload-before.json"))?,
            &identity(&raw.join("reload-after.json"))?
        ),
        "reload replaced a process"
    );
    Ok(())
}

fn workload_matrix(
    settings: &Value,
    component: &str,
    matrix: bool,
    netifd_scale: i64,
) -> Result<Vec<String>> {
    let names = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let suffixed = |items: &[&str], suffixes: &[&str]| {
        items
            .iter()
            .flat_map(|name| suffixes.iter().map(move |suffix| format!("{name}{suffix}")))
            .collect::<Vec<_>>()
    };
    let base = component_work(component)
        .ok_or_else(|| Error::new(format!("unknown component {component}")))?;
    let mut workloads = names(base);
    let prepared = component == "reload-config" && truthy(settings.get("reload_prepared_exec"));
    let selected = |name: &str| -> Result<Option<Vec<String>>> {
        if !truthy(settings.get(name)) {
            return Ok(None);
        }
        let selected = strings(list(settings, name)?)?;
        ensure!(unique(&selected), "{name} repeats a workload");
        Ok(Some(selected))
    };
    if prepared {
        workloads = strings(list(settings, "reload_workloads")?)?;
        ensure!(
            !workloads.is_empty() && unique(&workloads),
            "invalid reload workloads"
        );
        ensure!(
            subset(
                &workloads,
                &names(&[
                    "first_baseline",
                    "unchanged_config",
                    "single_change",
                    "multi_change",
                    "comment_only"
                ])
            ),
            "unknown reload workload"
        );
    }
    if matrix && component == "httpd" {
        workloads = suffixed(&STATIC, &["_c1", "_c4"]);
        workloads.extend(names(&["cgi", "jsonrpc", "cgi_c4", "jsonrpc_c4"]));
        if let Some(selected) = selected("httpd_workloads")? {
            let allowed = [
                workloads.clone(),
                names(&["jsonrpc_large", "jsonrpc_large_c4"]),
            ]
            .concat();
            ensure!(subset(&selected, &allowed), "unknown httpd workload");
            workloads = selected;
        }
    } else if matrix && component == "rpcd" {
        workloads.extend(suffixed(base, &["_c4"]));
        workloads.extend(suffixed(&RPCD_EXTRA, &["", "_c4"]));
        if let Some(selected) = selected("rpcd_workloads")? {
            let extra = [
                "uci_state_network",
                "uci_get_delta",
                "session_access_acl256",
                "luci_version",
                "luci_features",
                "luci_devices",
            ];
            let allowed = [workloads.clone(), suffixed(&extra, &["", "_c4"])].concat();
            ensure!(subset(&selected, &allowed), "unknown rpcd workload");
            workloads = selected;
        }
    } else if matrix && component == "procd" {
        workloads.extend(suffixed(base, &["_c4"]));
        workloads.extend(suffixed(&PROCD_EXTRA, &["", "_c4"]));
        if let Some(selected) = selected("procd_workloads")? {
            let allowed = [workloads.clone(), names(&["service_list_instance_fields"])].concat();
            ensure!(subset(&selected, &allowed), "unknown procd workload");
            workloads = selected;
        }
    } else if matrix && component == "ubusd" {
        workloads.extend(suffixed(base, &["_c4"]));
        workloads.extend(suffixed(&UBUSD_EXTRA, &["", "_c4"]));
    } else if matrix && component == "netifd" {
        workloads.extend(suffixed(base, &["_c4"]));
        let extra = [
            "device_status_all".to_owned(),
            format!("interface_dump_{netifd_scale}"),
            format!("interface_named_{netifd_scale}"),
        ];
        workloads.extend(suffixed(
            &extra.iter().map(String::as_str).collect::<Vec<_>>(),
            &["", "_c4"],
        ));
    } else if matrix && component == "uci" {
        workloads.extend(names(&[
            "get_network",
            "export_multi",
            "show_long",
            "delta_64",
            "batch_read16",
        ]));
    } else if matrix && prepared {
        // The explicit reload workload set was validated above.
    } else {
        ensure!(!matrix, "unsupported workload matrix");
    }
    let requested = match settings.get("netifd_workloads") {
        Some(value) if !value.is_null() => strings(
            value
                .as_array()
                .ok_or_else(|| Error::new("netifd_workloads is not a list"))?,
        )?,
        _ => Vec::new(),
    };
    if matrix && component == "netifd" {
        workloads.extend(
            NETIFD_SERIAL
                .iter()
                .filter(|name| requested.iter().any(|r| r == *name))
                .map(|name| (*name).to_owned()),
        );
    }
    if truthy(settings.get("extended")) {
        ensure!(component == "ubusd", "extended lanes are ubusd only");
        workloads.extend(names(&UBUSD_EXTENDED));
    }
    if truthy(settings.get("netifd_workloads")) {
        ensure!(
            component == "netifd" && subset(&requested, &workloads),
            "invalid netifd workloads"
        );
        workloads.retain(|name| requested.contains(name));
    }
    Ok(workloads)
}

fn floor_div(a: i64, b: i64) -> i64 {
    a.div_euclid(b)
}

fn expected_operations(component: &str, name: &str, iterations: i64) -> i64 {
    let divisor = if name.starts_with("cgi") {
        20
    } else if name.starts_with("static_1m") || name.starts_with("uci_get_64") {
        10
    } else {
        1
    };
    let mut expected = floor_div(iterations, divisor).max(1);
    if component == "rpcd" && name.starts_with("luci_features") {
        expected = floor_div(iterations, 100).max(1);
    }
    if component == "rpcd" && name.starts_with("luci_devices") {
        expected = floor_div(iterations, 10).max(1);
    }
    if matches!(component, "uci" | "reload-config" | "fw4") {
        expected = floor_div(iterations, if component == "fw4" { 100 } else { 20 }).max(1);
    } else if name == "syslog_128" {
        expected = iterations * 10;
    }
    if name.ends_with("_c4") {
        expected = floor_div(expected, 4).max(1) * 4;
    }
    expected
}

fn pct(candidate: &Value, reference: &Value, metrics: &[&str]) -> Result<Value> {
    let mut result = Map::new();
    for metric in metrics {
        let base = kf(key(reference, metric)?, "median")?;
        if base > 0.0 {
            result.insert(
                (*metric).to_owned(),
                json!((kf(key(candidate, metric)?, "median")? / base - 1.0) * 100.0),
            );
        }
    }
    Ok(Value::Object(result))
}

pub fn derive(root: &Path, label: &str) -> Result<Value> {
    ensure!(
        root.join("COMPLETE").exists(),
        "collector did not complete its host gates"
    );
    let order_value = read(&root.join("order.json"))?;
    let order = strings(
        order_value
            .as_array()
            .ok_or_else(|| Error::new("order is not a list"))?,
    )?;
    let subjects = read(&root.join("subjects.json"))?;
    let settings = read(&root.join("settings.json"))?;
    ensure!(
        !truthy(settings.get("rpc_client_diagnostic")),
        "RPC client diagnostics cannot be published as performance-matrix results"
    );
    let component = match settings.get("component") {
        None => "httpd",
        Some(value) => value
            .as_str()
            .ok_or_else(|| Error::new("component is not a string"))?,
    };
    ensure!(
        component_work(component).is_some(),
        "unknown component {component}"
    );
    let baseline_label = match settings.get("baseline_label") {
        None => "r84",
        Some(value) => value
            .as_str()
            .ok_or_else(|| Error::new("baseline_label is not a string"))?,
    };
    let empty = Map::new();
    let extra_baselines = match settings.get("extra_baselines") {
        None => &empty,
        Some(value) => value
            .as_object()
            .ok_or_else(|| Error::new("extra_baselines is not an object"))?,
    };
    let mut known_sides = vec!["stock", baseline_label];
    known_sides.extend(extra_baselines.keys().map(String::as_str));
    known_sides.push("candidate");
    ensure!(
        order
            .iter()
            .all(|side| known_sides.contains(&side.as_str())),
        "unknown comparison side"
    );
    let measured_sides: Vec<&str> = known_sides
        .iter()
        .copied()
        .filter(|side| order.iter().any(|s| s == side))
        .collect();
    for (side, evidence) in extra_baselines {
        ensure!(order.contains(side), "missing historical comparison side");
        let subject = key(&subjects, side)?;
        ensure!(
            py_eq(subject, key(evidence, "subject_sha256")?)
                && py_eq(
                    key(evidence, "subject_sha256")?,
                    at(evidence, &["provenance", "subject_sha256"])?
                ),
            "historical subject identity differs"
        );
    }
    let calibration = is(settings.get("schedule"), "calibration");
    if calibration {
        ensure!(
            measured_sides == ["candidate"],
            "calibration measures only the candidate"
        );
    } else {
        ensure!(
            measured_sides.contains(&"stock") && measured_sides.contains(&"candidate"),
            "comparison needs stock and candidate"
        );
    }
    let counts: BTreeSet<usize> = measured_sides
        .iter()
        .map(|side| order.iter().filter(|s| s == side).count())
        .collect();
    ensure!(counts.len() == 1, "unbalanced comparison sides");
    if is(settings.get("schedule"), "random-blocks") {
        let width = measured_sides.len();
        let wanted: BTreeSet<&str> = measured_sides.iter().copied().collect();
        ensure!(
            order.chunks(width).all(|block| block
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == wanted),
            "incomplete comparison block"
        );
    }
    let (before, after) = (
        read(&root.join("health-before.json"))?,
        read(&root.join("health-after.json"))?,
    );
    ensure!(
        py_eq(key(&before, "boot_id")?, key(&after, "boot_id")?),
        "router rebooted during the matrix"
    );
    ensure!(
        bytes(&root.join("config-before.sha256"))? == bytes(&root.join("config-after.sha256"))?,
        "production configuration changed"
    );
    let host_health = verify_native_health(root, &settings, &before, &after)?;
    let boot_id = key(&before, "boot_id")?;
    let (mut rows, mut residents, mut sources) = (Vec::new(), Vec::new(), Vec::new());
    let mut initialization_settled: Vec<bool> = Vec::new();
    let mut identities: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut fixtures: BTreeSet<String> = BTreeSet::new();
    let matrix_value = key(&settings, "matrix")?.clone();
    let matrix = truthy(Some(&matrix_value));
    let netifd_scale = match settings.get("netifd_scale") {
        None => 32,
        Some(value) => value
            .as_i64()
            .ok_or_else(|| Error::new("invalid netifd_scale"))?,
    };
    ensure!(
        matches!(netifd_scale, 32 | 64 | 128),
        "invalid netifd_scale"
    );
    let workloads = workload_matrix(&settings, component, matrix, netifd_scale)?;
    let prepared = component == "reload-config" && truthy(settings.get("reload_prepared_exec"));
    let one_shot = matches!(component, "uci" | "reload-config" | "fw4");
    let events_only = workloads == ["events_static2"];
    let mut settled = false;
    for (index, side) in order.iter().enumerate() {
        let local = root.join(format!("{:02}-{side}", index + 1));
        let run = local
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let raw = local.join("raw");
        ensure!(
            local.join("COMPLETE").exists() && raw.join("COMPLETE").exists(),
            "{run}: incomplete run"
        );
        ensure!(
            !raw.join("TRACE_DIAGNOSTIC").exists(),
            "traced runs are not performance measurements"
        );
        ensure!(
            !raw.join("diagnostic-mode.txt").exists(),
            "HTTP diagnostics are separate from the matrix"
        );
        let meta = read(&raw.join("meta.json"))?;
        ensure!(
            is(meta.get("component"), component)
                && is(meta.get("dependencies"), "original OpenWrt"),
            "{run}: unexpected meta"
        );
        let subject = key(&meta, "subject_pid")?;
        ensure!(
            subject.is_null() == one_shot,
            "invalid subject process kind"
        );
        if component == "logd" {
            ensure!(
                is(meta.get("kernel_log_mask"), "empty-held-fifo"),
                "invalid logd kernel-log fixture"
            );
            logd_idle(&raw.join("kernel-log-idle.jsonl"), subject)?;
        }
        ensure!(
            py_eq(&json!(text(&raw.join("boot-id.txt"))?.trim()), boot_id),
            "{run}: boot changed"
        );
        let side_subject = key(&subjects, side)?;
        let identity_files: &[&str] = if subject.is_null() {
            &["binary-sha256.txt"]
        } else {
            &["binary-sha256.txt", "subject-sha256.txt"]
        };
        for file in identity_files {
            ensure!(
                py_eq(&json!(first_word(&raw.join(file))?), side_subject),
                "{run}: {file} differs from the subject"
            );
        }
        let mut identity = first_words(&raw.join("benchmark-sha256.txt"))?;
        identity.push(first_word(&raw.join("harness-sha256.txt"))?);
        identities.insert(identity.clone());
        if component == "procd" && settings.get("procd_warmup").is_some() {
            let expected_bus = at(
                &read(&root.join("host-manifest.json"))?,
                &["components", "ubusd", "original", "sha256"],
            )?
            .clone();
            let observed = first_words(&raw.join("dependencies-sha256.txt"))?;
            ensure!(
                py_eq(&json!(observed), &json!([expected_bus])),
                "procd dependency is not the exact image C ubusd"
            );
        }
        if prepared {
            let expected_bus = at(
                &read(&root.join("host-manifest.json"))?,
                &["components", "ubusd", "original", "sha256"],
            )?
            .clone();
            let running = first_words(&raw.join("reload-running-dependencies.sha256"))?;
            ensure!(
                running.len() == 3
                    && py_eq(&json!(running[..2]), &json!([expected_bus, identity[0]])),
                "reload receiver or C ubusd identity differs"
            );
            let dependency_text = text(&raw.join("reload-dependencies.sha256"))?;
            let mut dependencies = BTreeMap::new();
            for line in util::splitlines(&dependency_text) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                ensure!(fields.len() > 1, "invalid reload dependency row");
                dependencies.insert(fields[1].to_owned(), fields[0].to_owned());
            }
            let dependency = |path: &str| {
                dependencies
                    .get(path)
                    .cloned()
                    .ok_or_else(|| Error::new(format!("{path} identity is missing")))
            };
            ensure!(
                py_eq(&json!(dependency("/sbin/ubusd")?), &expected_bus)
                    && dependency("/sbin/logd")? == running[2],
                "reload dependency identity differs"
            );
            let reload = dependency("/sbin/reload_config")?;
            ensure!(
                py_eq(
                    &json!(reload),
                    subjects.get("stock").unwrap_or(&json!(reload))
                ),
                "reload_config dependency differs from stock"
            );
            for (setting, file) in [
                ("exec_resource_probe_sha256", "reload-resource-probe.sha256"),
                ("exec_task_probe_sha256", "reload-task-probe.sha256"),
            ] {
                if let Some(expected) = settings.get(setting) {
                    ensure!(
                        py_eq(&json!(first_word(&raw.join(file))?), expected),
                        "reload diagnostic probe identity differs"
                    );
                }
            }
            identities.remove(&identity);
            identity.push(dependency_text);
            identities.insert(identity);
        }
        if matrix {
            let fixture_file = match component {
                "httpd" => "static-fixtures.sha256",
                "rpcd" => "rpc-fixtures.sha256",
                "procd" => "procd-fixtures.sha256",
                "ubusd" => "ubusd-fixtures.sha256",
                "netifd" => "netifd-fixtures.sha256",
                "uci" => "uci-fixtures.sha256",
                "reload-config" => "reload-fixtures.sha256",
                _ => bail!("{component} has no fixture identity"),
            };
            let mut fixture_identity = text(&raw.join(fixture_file))?;
            if component == "httpd"
                && workloads
                    .iter()
                    .any(|name| name.starts_with("jsonrpc_large"))
            {
                fixture_identity += &text(&raw.join("large-fixture.sha256"))?;
            }
            fixtures.insert(fixture_identity);
            if component == "ubusd" {
                for count in [64, 128] {
                    let mut expected_paths: Vec<String> =
                        (1..count).map(|i| format!("bench.filler{i:04}")).collect();
                    expected_paths.push("bench.target".into());
                    for phase in ["before", "after"] {
                        ensure!(
                            lines(&raw.join(format!("objects-{count}-{phase}.txt")))?
                                == expected_paths,
                            "{run}: ubus objects differ"
                        );
                    }
                }
            }
            if component == "netifd" && !events_only {
                settled = raw
                    .join(format!("hotplug-settled-{netifd_scale}.txt"))
                    .is_file();
                initialization_settled.push(settled);
                for count in [2, netifd_scale as usize] {
                    let digits = if netifd_scale == 128 { 3 } else { 2 };
                    let mut expected_names: Vec<String> = (0..count - 2)
                        .map(|i| format!("bench{i:0digits$}"))
                        .collect();
                    expected_names.extend(["lan".to_owned(), "loopback".to_owned()]);
                    if settled {
                        let children_checked =
                            check_netifd_hotplug(&raw, subject, count, &expected_names)?;
                        let last = initialization_settled.len() - 1;
                        initialization_settled[last] =
                            initialization_settled[last] && children_checked;
                    }
                    for phase in ["before", "after"] {
                        ensure!(
                            lines(&raw.join(format!("interface-names-{count}-{phase}.txt")))?
                                == expected_names,
                            "{run}: interface names differ"
                        );
                        let objects: Vec<String> = expected_names
                            .iter()
                            .map(|name| format!("network.interface.{name}"))
                            .collect();
                        ensure!(
                            lines(&raw.join(format!("interface-objects-{count}-{phase}.txt")))?
                                == objects,
                            "{run}: interface objects differ"
                        );
                        let interfaces =
                            interface_names(&raw.join(format!("interfaces-{count}-{phase}.json")))?;
                        let names = interfaces
                            .iter()
                            .map(|i| Ok(super::json::ks(i, "interface")?.to_owned()))
                            .collect::<Result<Vec<_>>>()?;
                        ensure!(names == expected_names, "{run}: interfaces differ");
                        ensure!(
                            interfaces
                                .iter()
                                .all(|i| truthy(i.get("up")) && is(i.get("proto"), "static")),
                            "{run}: interface not static and up"
                        );
                    }
                }
            }
        }
        sources.push(json!({"run": run, "subject_sha256": side_subject,
                            "archive_sha256": util::sha256_file(&local.join("raw.tar.gz"))?,
                            "kernel": text(&raw.join("kernel.txt"))?.trim()}));
        if component == "netifd" && events_only {
            settled = true;
            initialization_settled.push(check_netifd_hotplug(
                &raw,
                subject,
                3,
                &["lan".into(), "loopback".into(), "wired".into()],
            )?);
        }
        let iterations = ki(&meta, "iterations")?;
        for name in &workloads {
            let roles = if name == "events_static2" {
                Some(read(&raw.join("roles.json"))?)
            } else {
                None
            };
            let data = if name.ends_with("_c4") {
                parallel(&raw.join(name), subject)?
            } else {
                serial(&raw.join(format!("{name}.json")), subject, roles.as_ref())?
            };
            if name == "events_static2" {
                check_event_lane(&raw, &data)?;
                let contract = at(&settings, &["netifd_event_contracts", side.as_str()])?;
                ensure!(
                    is(
                        contract.get("sha256"),
                        &util::sha256_file(&raw.join("event-contract.json"))?
                    ),
                    "event contract differs"
                );
                ensure!(
                    py_eq(
                        key(
                            &read(&raw.join("event-contract.json"))?,
                            "reference_subject_sha256"
                        )?,
                        key(contract, "reference_subject_sha256")?
                    ),
                    "event contract reference differs"
                );
            }
            if name == "reload_unchanged" {
                check_reload_lane(&raw)?;
            }
            if component == "netifd" && matrix && settled && !NETIFD_SERIAL.contains(&name.as_str())
            {
                if name.ends_with("_c4") {
                    let mut ticks = Vec::new();
                    for phase in ["before", "after"] {
                        let snapshot = read(&raw.join(name).join(format!("{phase}.json")))?;
                        ticks.push(
                            key(
                                need_pid(list(&snapshot, "processes")?, subject)?,
                                "child_cpu_ticks",
                            )?
                            .clone(),
                        );
                    }
                    ensure!(
                        py_eq(&ticks[0], &ticks[1]),
                        "{name}: query includes child setup CPU"
                    );
                } else {
                    let result = native(&raw.join(format!("{name}.json")))?;
                    let own = need_pid(list(&result, "daemon_cpu")?, subject)?;
                    ensure!(
                        kf(own, "child_cpu_s")? == 0.0,
                        "{name}: query includes child setup CPU"
                    );
                }
            }
            let expected = expected_operations(component, name, iterations);
            let successful = ki(&data, "successful")?;
            ensure!(
                successful == expected,
                "{name}: {successful} operations, expected {expected}"
            );
            if prepared {
                ensure!(
                    py_eq(key(&data, "warmup")?, key(&settings, "reload_warmup")?),
                    "reload warmup changed"
                );
            }
            if component == "procd" {
                if let Some(warmup) = settings.get("procd_warmup") {
                    let factor = if name.ends_with("_c4") { 4.0 } else { 1.0 };
                    ensure!(
                        kf(&data, "warmup")? == stats_f(warmup)? * factor,
                        "procd warmup changed"
                    );
                }
            }
            let mut row = Map::new();
            row.insert("run".into(), json!(run));
            row.insert("side".into(), json!(side));
            row.insert("workload".into(), json!(name));
            merge(&mut row, data.as_object().cloned().unwrap_or_default());
            rows.push(Value::Object(row));
        }
        if !subject.is_null() {
            let resident = read(&raw.join("resident.json"))?;
            let process = need_pid(list(&resident, "processes")?, subject)?;
            let mut entry = Map::new();
            entry.insert("run".into(), json!(run));
            entry.insert("side".into(), json!(side));
            merge(&mut entry, memory(process)?);
            entry.insert(
                "temperature_millic".into(),
                key(&resident, "temperature_millic")?.clone(),
            );
            residents.push(Value::Object(entry));
        }
    }
    ensure!(
        identities.len() == 1 && (!matrix || fixtures.len() == 1),
        "clients/harness/fixtures changed between sides"
    );
    let mut metrics: Vec<&str> = METRICS.to_vec();
    for metric in CLOCK_METRICS
        .iter()
        .chain(&TREE_METRICS)
        .chain(&RELOAD_METRICS)
    {
        if rows.iter().all(|row| row.get(*metric).is_some()) {
            metrics.push(metric);
        }
    }
    let mut summary = Map::new();
    for name in &workloads {
        let mut sides = Map::new();
        for side in &measured_sides {
            let group: Vec<&Value> = rows
                .iter()
                .filter(|r| is(r.get("workload"), name) && is(r.get("side"), side))
                .collect();
            let mut values = Map::new();
            for metric in &metrics {
                values.insert(
                    (*metric).to_owned(),
                    value_stats(
                        group
                            .iter()
                            .map(|r| key(r, metric))
                            .collect::<Result<Vec<_>>>()?,
                    )?,
                );
            }
            sides.insert((*side).to_owned(), Value::Object(values));
        }
        if !calibration {
            sides.insert(
                "candidate_vs_stock_pct".into(),
                pct(&sides["candidate"], &sides["stock"], &metrics)?,
            );
        }
        for baseline_side in extra_baselines.keys() {
            if let Some(reference) = sides.get(baseline_side).cloned() {
                sides.insert(
                    format!("candidate_vs_{baseline_side}_pct"),
                    pct(&sides["candidate"], &reference, &metrics)?,
                );
            }
        }
        if let Some(reference) = sides.get(baseline_label).cloned() {
            sides.insert(
                "candidate_vs_baseline_pct".into(),
                pct(&sides["candidate"], &reference, &metrics)?,
            );
        }
        summary.insert(name.clone(), Value::Object(sides));
    }
    let identity = identities.into_iter().next().unwrap_or_default();
    let [client, namespace, harness] = match identity.get(..3) {
        Some([client, namespace, harness]) => [client.clone(), namespace.clone(), harness.clone()],
        _ => bail!("benchmark identity needs client, namespace and harness"),
    };
    let mut limitations = Vec::new();
    if calibration {
        limitations
            .push("Same-identity calibration only; no between-implementation acceptance claim.");
    }
    if one_shot {
        if !["client_cpu_clock_us_per_op", "command_tree_cpu_us_per_op"]
            .iter()
            .all(|metric| metrics.contains(metric))
        {
            limitations.push("Caller CPU-clock or getrusage command-tree CPU is unavailable for some short-lived observations; legacy ticks remain separate.");
        }
    } else if !CLOCK_METRICS.iter().all(|metric| metrics.contains(metric)) {
        limitations.push("Process CPU-clock metrics are unavailable for some observations; legacy ticks remain separate.");
    }
    if !initialization_settled.is_empty() && !initialization_settled.iter().all(|&settled| settled)
    {
        limitations.push("This netifd matrix lacks complete evidence for finished hotplug callbacks, reaped children checked through proc status PPid, and stable child CPU before queries. Timings/CPU are retained for diagnosis, not acceptance; rerun with the complete initialization gate.");
    }
    let method = if prepared {
        "Medians of per-run statistics; prepared reload latency, command-tree CPU and throughput cover exec-to-exit intervals only. Reset, validation, silent repeat and diagnostics are separate. Dependency clocks cover each immediate exec interval; full dependency envelopes retain asynchronous and excluded-work costs separately."
    } else {
        "Medians of per-run statistics; c4 CPU uses one outer interval divided by successful plus warm-up operations. c4 outer throughput includes warm-up/startup and uses /proc/uptime resolution. Client validation runs on the same router CPUs."
    };
    let mut result = Map::new();
    result.insert("schema_version".into(), json!(1));
    result.insert("label".into(), json!(label));
    result.insert("component".into(), json!(component));
    result.insert("matrix".into(), matrix_value);
    result.insert("subjects".into(), subjects.clone());
    merge(&mut result, host_health);
    result.insert("benchmark_sha256".into(), json!(client));
    result.insert("namespace_sha256".into(), json!(namespace));
    result.insert("harness_sha256".into(), json!(harness));
    result.insert("order".into(), order_value);
    result.insert("host_gates_passed".into(), json!(true));
    result.insert("acceptance_eligible".into(), json!(limitations.is_empty()));
    result.insert("limitations".into(), json!(limitations));
    result.insert("runs".into(), Value::Array(rows));
    result.insert("summary".into(), Value::Object(summary));
    result.insert("measured_sides".into(), json!(measured_sides));
    result.insert("baseline_label".into(), json!(baseline_label));
    result.insert(
        "extra_baselines".into(),
        Value::Object(extra_baselines.clone()),
    );
    result.insert(
        "cpu_affinity".into(),
        settings.get("cpu_affinity").cloned().unwrap_or(Value::Null),
    );
    result.insert("resident".into(), Value::Array(residents));
    result.insert("sources".into(), Value::Array(sources));
    result.insert("method".into(), json!(method));
    Ok(Value::Object(result))
}

fn stats_f(value: &Value) -> Result<f64> {
    super::stats::f(value)
}

fn median(summary: &Value, side: &str, metric: &str) -> Result<f64> {
    kf(at(summary, &[side, metric])?, "median")
}

fn markdown(result: &Value, label: &str) -> Result<String> {
    let summary = super::json::obj(result, "summary")?;
    let sides = strings(list(result, "measured_sides")?)?;
    if sides == ["candidate"] {
        let mut lines = vec![
            format!("# {label}：同身份校准"),
            String::new(),
            "仅用于估计测量噪声和漂移，不是实现间的比较。".into(),
            String::new(),
            "| 负载 | mean 中位数 µs | p99 最小–最大 µs |".into(),
            "|---|---:|---:|".into(),
        ];
        for (name, values) in summary {
            let p99 = at(values, &["candidate", "p99_us"])?;
            lines.push(format!(
                "| {name} | {:.2} | {:.2}–{:.2} |",
                median(values, "candidate", "mean_us")?,
                kf(p99, "min")?,
                kf(p99, "max")?
            ));
        }
        return Ok(lines.join("\n") + "\n");
    }
    let runs = list(result, "runs")?;
    let cpu_metric = if runs
        .iter()
        .all(|row| row.get("command_tree_cpu_us_per_op").is_some())
    {
        "command_tree_cpu_us_per_op"
    } else if summary.values().all(|values| {
        values
            .get("candidate")
            .and_then(|c| c.get("subject_own_cpu_clock_us_per_op"))
            .is_some()
    }) {
        "subject_own_cpu_clock_us_per_op"
    } else {
        "subject_cpu_us_per_op"
    };
    let mut headings = vec!["负载".to_owned()];
    headings.extend(sides.iter().map(|side| format!("{side} mean µs / CPU µs")));
    headings.extend(
        sides
            .iter()
            .filter(|side| *side != "candidate")
            .map(|side| format!("候选比 {side} mean / CPU")),
    );
    let mut lines = vec![
        format!(
            "# {label}：{} 实机对照",
            super::json::ks(result, "component")?
        ),
        String::new(),
        "单位：延迟和 CPU 为 µs/请求；数值是逐轮统计的中位数。负百分比表示开销下降。".into(),
        String::new(),
        format!("CPU 口径：{cpu_metric}"),
        String::new(),
        format!("| {} |", headings.join(" | ")),
        format!(
            "|{}|",
            std::iter::once("---")
                .chain(std::iter::repeat("---:").take(headings.len() - 1))
                .collect::<Vec<_>>()
                .join("|")
        ),
    ];
    for (name, values) in summary {
        let mut row = vec![name.clone()];
        for side in &sides {
            row.push(format!(
                "{:.2} / {:.2}",
                median(values, side, "mean_us")?,
                median(values, side, cpu_metric)?
            ));
        }
        for side in sides.iter().filter(|side| *side != "candidate") {
            let delta = |metric: &str| -> Result<String> {
                let reference = median(values, side, metric)?;
                Ok(if reference != 0.0 {
                    format!(
                        "{:+.2}%",
                        (median(values, "candidate", metric)? / reference - 1.0) * 100.0
                    )
                } else {
                    "—".into()
                })
            };
            row.push(format!("{} / {}", delta("mean_us")?, delta(cpu_metric)?));
        }
        lines.push(format!("| {} |", row.join(" | ")));
    }
    let limitations = strings(list(result, "limitations")?)?;
    if !limitations.is_empty() {
        lines.extend([String::new(), "**测量边界：**".into()]);
        lines.extend(limitations.iter().map(|item| format!("- {item}")));
    }
    let per_side = list(result, "order")?.len() / sides.len();
    lines.extend([
        String::new(),
        format!(
            "每侧运行次数：{per_side}。所列完整运行的请求均成功，原版依赖和正式运行栈保持相同。"
        ),
    ]);
    if is(result.get("component"), "reload-config")
        && runs.iter().all(|row| row.get("accounting").is_some())
    {
        lines.extend([String::new(), "延迟和命令树 CPU 仅覆盖真实 exec 到退出；吞吐使用成功 exec 的时长总和。".into(),
                      "准备、完整校验、静默重复和资源诊断均单列；依赖 CPU 是立即包围 exec 的窗口，完整依赖 envelope 另存。".into(),
                      "微秒计数编码不等于微秒精度，caller CPU 也不能作为组件自身成本。".into()]);
    } else {
        lines.extend([String::new(), "c4 的 CPU 包含并计数已记录的每客户端预热，使用唯一外层区间；吞吐包括预热和启动，".into(),
                      "计时精度来自 /proc/uptime。客户端校验也使用路由器 CPU，不能把这里的吞吐视为服务端极限。".into()]);
    }
    lines.extend([
        String::new(),
        "逐轮均值、p50/p95/p99、CPU、内存、离散程度及产物身份见 [results.json](results.json)。"
            .into(),
        String::new(),
    ]);
    Ok(lines.join("\n"))
}

pub fn main(raw: &[String]) -> Result<i32> {
    let args = util::Args::parse(raw, &["--output", "--label"], &[])?;
    let [private] = &args.exact(&["PRIVATE"])?[..] else {
        unreachable!()
    };
    let output = Path::new(args.required("--output")?);
    let label = args.required("--label")?;
    let result = derive(Path::new(private), label)?;
    ensure!(!output.exists(), "{} already exists", util::display(output));
    fs::create_dir_all(output)?;
    fs::write(
        output.join("results.json"),
        util::pretty_json(&result) + "\n",
    )?;
    fs::write(output.join("results.md"), markdown(&result, label)?)?;
    let runs = list(&result, "runs")?.len();
    if strings(list(&result, "measured_sides")?)? == ["candidate"] {
        println!("{label}: {runs} calibration measurements verified");
    } else {
        println!("{label}: {runs} workload measurements verified");
    }
    Ok(0)
}

#[cfg(test)]
#[path = "candidate_tests.rs"]
mod tests;

//! Negative evidence gates for publishable benchmark summaries.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::super::analyze::{logd_idle, native, summarize, timing};
use super::*;
use crate::util::TempDir;

fn put(path: &Path, value: &Value) {
    fs::write(path, value.to_string()).unwrap();
}

fn touch(path: &Path) {
    fs::write(path, b"").unwrap();
}

fn err(result: Result<impl std::fmt::Debug>) -> String {
    result.unwrap_err().to_string()
}

fn valid() -> Value {
    json!({"successful": 2, "errors": 0, "latency_ns": [1000, 3000],
           "wall_s": 0.001, "ops_per_s": 2000, "mean_us": 2,
           "p50_us": 3, "p95_us": 3, "p99_us": 3,
           "daemon_cpu": [{"before": {"start_ticks": 17}, "after": {"start_ticks": 17},
                           "cpu_s": 0.01, "child_cpu_s": 0}]})
}

fn patched(base: &Value, patch: Value) -> Value {
    let mut data = base.clone();
    for (name, value) in patch.as_object().unwrap() {
        data[name] = value.clone();
    }
    data
}

struct Sample {
    _dir: TempDir,
    path: PathBuf,
}

fn sample() -> Sample {
    let dir = TempDir::new("owrt-bench");
    let path = dir.path().join("sample.json");
    Sample { _dir: dir, path }
}

#[test]
fn invalid_counts_errors_and_latency_are_rejected() {
    let s = sample();
    for patch in [
        json!({"successful": 3}),
        json!({"errors": 1}),
        json!({"mean_us": 99}),
        json!({"wall_s": 0}),
    ] {
        put(&s.path, &patched(&valid(), patch));
        assert!(native(&s.path).is_err());
    }
}

#[test]
fn replaced_process_is_rejected() {
    let s = sample();
    let mut data = valid();
    data["daemon_cpu"][0]["after"]["start_ticks"] = json!(18);
    put(&s.path, &data);
    assert!(native(&s.path).is_err());
}

#[test]
fn derived_percentiles_and_rate_must_match_raw_samples() {
    let s = sample();
    for name in ["p50_us", "p95_us", "p99_us", "ops_per_s"] {
        put(&s.path, &patched(&valid(), json!({name: 123456789})));
        assert!(native(&s.path).is_err(), "{name}");
    }
}

#[test]
fn invalid_raw_samples_and_nonfinite_wall_are_rejected() {
    let s = sample();
    for patch in [
        json!({"latency_ns": [-1000, 5000]}),
        json!({"latency_ns": [1000.0, 3000.0]}),
    ] {
        put(&s.path, &patched(&valid(), patch));
        assert!(native(&s.path).is_err());
    }
    for wall in ["Infinity", "NaN"] {
        let text = patched(&valid(), json!({"wall_s": "WALL"}))
            .to_string()
            .replace("\"WALL\"", wall);
        fs::write(&s.path, text).unwrap();
        assert!(native(&s.path).is_err());
    }
}

#[test]
fn even_sample_median_uses_native_half_up_index() {
    let s = sample();
    put(&s.path, &valid());
    assert_eq!(native(&s.path).unwrap()["p50_us"], json!(3));
    put(&s.path, &patched(&valid(), json!({"p50_us": 1})));
    assert!(native(&s.path).is_err());
}

#[test]
fn timing_fields_do_not_export_unrelated_payloads() {
    let s = sample();
    put(
        &s.path,
        &patched(&valid(), json!({"private_response": "must remain private"})),
    );
    let result = timing(&native(&s.path).unwrap()).unwrap();
    assert!(!result.contains_key("private_response") && !result.contains_key("latency_ns"));
    assert_eq!(result["mean_us"], json!(2));
}

#[test]
fn run_summary_retains_dispersion() {
    let rows: Vec<Value> = [1, 3, 20]
        .iter()
        .map(|value| json!({"side": "stock", "mean_us": value}))
        .collect();
    let result = &summarize(&rows, &["side"]).unwrap()[0];
    assert_eq!(result["runs"], json!(3));
    assert_eq!(result["metrics"]["mean_us"]["median"], json!(3));
    assert_eq!(result["metrics"]["mean_us"]["max"], json!(20));
}

fn f(value: &Value) -> f64 {
    value.as_f64().unwrap()
}

#[test]
fn candidate_distinguishes_child_program_cpu_from_daemon_cpu() {
    let s = sample();
    let mut data = patched(
        &valid(),
        json!({"warmup": 5, "child_cpu_s": 0.004, "client_cpu_s": 0.002}),
    );
    data["daemon_cpu"][0]["pid"] = json!(7);
    put(&s.path, &data);
    assert_eq!(
        f(&serial(&s.path, &Value::Null, None).unwrap()["subject_cpu_us_per_op"]),
        2000.0
    );
    assert_eq!(
        f(&serial(&s.path, &json!(7), None).unwrap()["subject_cpu_us_per_op"]),
        5000.0
    );
    assert!(serial(&s.path, &json!(99), None).is_err());
}

fn command_sample() -> Value {
    let mut data = patched(
        &valid(),
        json!({"warmup": 5, "child_cpu_s": 0, "client_cpu_s": 0.002,
                                            "clock_ticks_per_second": 100, "daemon_cpu": [], "client_cpu_clock_ns": 2000}),
    );
    let before = json!({"pid": 23, "start_ticks": 17, "child_cpu_ticks": 0,
                        "process_cpu_ns": 1000, "process_cpu_resolution_ns": 1,
                        "rusage_children_user_us": 100000, "rusage_children_system_us": 50000,
                        "rusage_children_counter_source": "getrusage(RUSAGE_CHILDREN)"});
    data["client_after"] = patched(
        &before,
        json!({"process_cpu_ns": 3000, "rusage_children_user_us": 101100,
                                                   "rusage_children_system_us": 50300}),
    );
    data["client_before"] = before;
    data
}

fn strip_rusage(data: &mut Value) {
    for snapshot in ["client_before", "client_after"] {
        data[snapshot]
            .as_object_mut()
            .unwrap()
            .retain(|name, _| !name.starts_with("rusage_children_"));
    }
}

#[test]
fn one_shot_command_cpu_uses_measured_delta_and_count() {
    let s = sample();
    let mut data = command_sample();
    for warmup in [5, 65] {
        data["warmup"] = json!(warmup);
        put(&s.path, &data);
        let result = serial(&s.path, &Value::Null, None).unwrap();
        assert_eq!(f(&result["command_tree_cpu_us_per_op"]), 700.0);
        assert_eq!(f(&result["subject_cpu_us_per_op"]), 0.0); // retained legacy ticks
        assert_eq!(f(&result["client_reaped_child_cpu_us_per_op"]), 0.0);
    }
}

#[test]
fn one_shot_command_cpu_rejects_partial_regressed_or_wrong_source() {
    let s = sample();
    for patch in [
        json!({"rusage_children_user_us": 99999}),
        json!({"rusage_children_counter_source": "wrong"}),
        json!({"start_ticks": 99}),
    ] {
        let mut data = command_sample();
        data["client_after"] = patched(&data["client_after"], patch);
        put(&s.path, &data);
        assert!(serial(&s.path, &Value::Null, None).is_err());
    }
    let mut data = command_sample();
    data["client_after"]
        .as_object_mut()
        .unwrap()
        .remove("rusage_children_system_us");
    put(&s.path, &data);
    assert!(err(serial(&s.path, &Value::Null, None)).contains("partial"));
    strip_rusage(&mut data);
    put(&s.path, &data);
    assert!(serial(&s.path, &Value::Null, None)
        .unwrap()
        .get("command_tree_cpu_us_per_op")
        .is_none());
}

#[test]
fn one_shot_collection_does_not_require_a_resident_process_hash() {
    let dir = TempDir::new("owrt-bench");
    let root = dir.path();
    let save = |name: &str, value: Value| put(&root.join(name), &value);
    touch(&root.join("COMPLETE"));
    save("order.json", json!(["stock", "candidate"]));
    save(
        "subjects.json",
        json!({"stock": "a".repeat(64), "candidate": "b".repeat(64)}),
    );
    save(
        "settings.json",
        json!({"component": "uci", "matrix": false}),
    );
    for phase in ["before", "after"] {
        save(
            &format!("health-{phase}.json"),
            json!({"boot_id": "same-boot"}),
        );
        fs::write(root.join(format!("config-{phase}.sha256")), "same-config\n").unwrap();
    }
    let data = patched(
        &valid(),
        json!({"warmup": 5, "child_cpu_s": 0.004, "client_cpu_s": 0.002, "daemon_cpu": []}),
    );
    let workloads = ["export_network", "export_64", "set_commit_get"];
    for (index, side) in ["stock", "candidate"].iter().enumerate() {
        let run = root.join(format!("{:02}-{side}", index + 1));
        let raw = run.join("raw");
        fs::create_dir_all(&raw).unwrap();
        touch(&run.join("COMPLETE"));
        touch(&raw.join("COMPLETE"));
        fs::write(run.join("raw.tar.gz"), b"fixture archive identity").unwrap();
        put(
            &raw.join("meta.json"),
            &json!({"component": "uci", "dependencies": "original OpenWrt", "subject_pid": null, "iterations": 40}),
        );
        fs::write(raw.join("boot-id.txt"), "same-boot\n").unwrap();
        fs::write(raw.join("kernel.txt"), "fixture-kernel\n").unwrap();
        let letter = if *side == "stock" { "a" } else { "b" };
        fs::write(raw.join("binary-sha256.txt"), letter.repeat(64) + "  uci\n").unwrap();
        fs::write(
            raw.join("benchmark-sha256.txt"),
            "client  benchmark\nnamespace  ns-exec\n",
        )
        .unwrap();
        fs::write(raw.join("harness-sha256.txt"), "harness  isolated.sh\n").unwrap();
        for workload in workloads {
            put(&raw.join(format!("{workload}.json")), &data);
        }
    }
    let result = derive(root, "one-shot fixture").unwrap();
    assert_eq!(result["resident"], json!([]));
    assert_eq!(result["runs"].as_array().unwrap().len(), 6);
    assert!(result["runs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| f(&r["subject_cpu_us_per_op"]) == 2000.0));
    assert_eq!(result["acceptance_eligible"], json!(false));
    assert!(result["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r.as_str().unwrap().contains("short-lived")));

    let rewrite = |change: &dyn Fn(&mut Value)| {
        for (index, side) in ["stock", "candidate"].iter().enumerate() {
            for workload in workloads {
                let mut data = command_sample();
                change(&mut data);
                put(
                    &root.join(format!("{:02}-{side}/raw/{workload}.json", index + 1)),
                    &data,
                );
            }
        }
    };
    // Fine command-tree CPU is aggregated when all short-lived runs have it.
    rewrite(&|_| {});
    let result = derive(root, "one-shot fine CPU fixture").unwrap();
    assert_eq!(result["acceptance_eligible"], json!(true));
    for workload in workloads {
        assert_eq!(
            f(&result["summary"][workload]["candidate"]["command_tree_cpu_us_per_op"]["median"]),
            700.0
        );
    }
    // A valid command counter cannot replace the caller's own CPU clock.
    rewrite(&|data| {
        data.as_object_mut().unwrap().remove("client_cpu_clock_ns");
    });
    assert_eq!(
        derive(root, "missing caller CPU").unwrap()["acceptance_eligible"],
        json!(false)
    );
    // A caller clock cannot turn legacy command ticks into fine evidence.
    rewrite(&strip_rusage);
    assert_eq!(
        derive(root, "missing getrusage").unwrap()["acceptance_eligible"],
        json!(false)
    );

    // Declaring a daemon to have no PID must not bypass its live identity check.
    save(
        "settings.json",
        json!({"component": "rpcd", "matrix": false}),
    );
    for (index, side) in ["stock", "candidate"].iter().enumerate() {
        let path = root.join(format!("{:02}-{side}/raw/meta.json", index + 1));
        let mut meta: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        meta["component"] = json!("rpcd");
        put(&path, &meta);
    }
    assert!(err(derive(root, "invalid daemon fixture")).contains("invalid subject process kind"));
}

#[test]
fn logd_perpetually_readable_kernel_log_is_rejected() {
    let s = sample();
    let write = |ticks: &dyn Fn(i64) -> i64| {
        let lines: Vec<String> = (0..4)
            .map(|i| {
                json!({"uptime_s": i, "clock_ticks_per_second": 100,
                            "processes": [{"pid": 7, "start_ticks": 17, "cpu_ticks": ticks(i)}]})
                .to_string()
            })
            .collect();
        fs::write(&s.path, lines.join("\n")).unwrap();
    };
    write(&|i| i * 100);
    assert!(logd_idle(&s.path, &json!(7)).is_err());
    write(&|_| 1);
    assert_eq!(logd_idle(&s.path, &json!(7)).unwrap()["cpu_s"], json!(0.0));
}

// ------------------------------------------------ parallel (httpd) groups

struct Parallel {
    dir: TempDir,
    before: Value,
    after: Value,
    clients: Vec<Value>,
}

fn parallel_fixture() -> Parallel {
    let dir = TempDir::new("owrt-bench");
    put(
        &dir.path().join("group.json"),
        &json!({"clients": 4, "iterations_per_client": 25, "warmup_per_client": 5}),
    );
    let before = json!({"uptime_s": 100, "clock_ticks_per_second": 100, "processes": [
        {"pid": 42, "start_ticks": 10, "cpu_ticks": 100, "child_cpu_ticks": 10}]});
    let after = json!({"uptime_s": 101, "clock_ticks_per_second": 100, "processes": [
        {"pid": 42, "start_ticks": 10, "cpu_ticks": 110, "child_cpu_ticks": 12}]});
    // The daemon counters overlap; their sum is deliberately very different
    // from the one outer 0.12-second interval.
    let clients = (0..4)
        .map(|i| json!({"successful": 25, "warmup": 5, "errors": 0,
                        "latency_ns": (i * 25..(i + 1) * 25).map(|n| n * 1000).collect::<Vec<i64>>(),
                        "client_cpu_s": 0.002, "daemon_cpu": [{"pid": 42, "cpu_s": 100, "child_cpu_s": 100}]}))
        .collect();
    let fixture = Parallel {
        dir,
        before,
        after,
        clients,
    };
    fixture.save();
    fixture
}

impl Parallel {
    fn save(&self) {
        put(&self.dir.path().join("before.json"), &self.before);
        put(&self.dir.path().join("after.json"), &self.after);
    }

    fn run(&self) -> Result<Value> {
        let mut clients = self.clients.clone().into_iter();
        parallel_with(self.dir.path(), &json!(42), &mut |_| {
            Ok(clients.next().unwrap())
        })
    }
}

#[test]
fn shared_cpu_is_counted_once_and_warmup_has_a_denominator() {
    let result = parallel_fixture().run().unwrap();
    assert_eq!(result["successful"], json!(100));
    assert_eq!(result["warmup"], json!(20));
    assert_eq!(f(&result["subject_cpu_us_per_op"]), 1000.0);
    assert_eq!(f(&result["ops_per_s"]), 100.0);
    assert_eq!(f(&result["mean_us"]), 49.5);
    assert_eq!(f(&result["p95_us"]), 94.0);
    assert_eq!(f(&result["p99_us"]), 98.0);
    assert!(result.get("client_reaped_child_cpu_us_per_op").is_none());
    assert!(result.get("tree_cpu_components").is_none());
}

#[test]
fn replaced_server_invalidates_the_group() {
    let mut fixture = parallel_fixture();
    fixture.after["processes"][0]["start_ticks"] = json!(99);
    fixture.save();
    assert!(fixture.run().is_err());
}

#[test]
fn missing_operations_in_one_client_invalidate_the_group() {
    let mut fixture = parallel_fixture();
    fixture.clients[2]["successful"] = json!(24);
    assert!(fixture.run().is_err());
}

#[test]
fn client_diagnostic_cannot_be_published_as_the_regular_matrix() {
    let dir = TempDir::new("owrt-bench");
    touch(&dir.path().join("COMPLETE"));
    put(
        &dir.path().join("order.json"),
        &json!(["stock", "candidate"]),
    );
    put(&dir.path().join("subjects.json"), &json!({}));
    put(
        &dir.path().join("settings.json"),
        &json!({"component": "rpcd", "rpc_client_diagnostic": true}),
    );
    assert!(err(derive(dir.path(), "not-a-performance-result"))
        .contains("diagnostics cannot be published"));
}

// ------------------------------------------------------ netifd hotplug gate

struct Hotplug {
    dir: TempDir,
    before: Value,
    after: Value,
}

fn hotplug() -> Hotplug {
    let dir = TempDir::new("owrt-bench");
    fs::write(
        dir.path().join("hotplug-settled-2.txt"),
        "lan ifup 0\nloopback ifup 0\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("hotplug-child-check-2.txt"),
        "proc-status-ppid\n",
    )
    .unwrap();
    let process = json!({"processes": [{"pid": 42, "start_ticks": 10, "child_cpu_ticks": 99}]});
    Hotplug {
        dir,
        before: process.clone(),
        after: process,
    }
}

impl Hotplug {
    fn check(&self) -> Result<bool> {
        put(
            &self.dir.path().join("hotplug-settled-2-before.json"),
            &self.before,
        );
        put(
            &self.dir.path().join("hotplug-settled-2-after.json"),
            &self.after,
        );
        check_netifd_hotplug(
            self.dir.path(),
            &json!(42),
            2,
            &["lan".into(), "loopback".into()],
        )
    }

    fn events(&self, text: &str) {
        fs::write(self.dir.path().join("hotplug-settled-2.txt"), text).unwrap();
    }
}

#[test]
fn hotplug_callbacks_finished_and_reaped() {
    assert!(hotplug().check().unwrap());
}

#[test]
fn hotplug_missing_or_inapplicable_child_check_is_not_acceptance() {
    let fixture = hotplug();
    let child_check = fixture.dir.path().join("hotplug-child-check-2.txt");
    fs::remove_file(&child_check).unwrap();
    assert!(!fixture.check().unwrap());
    fs::write(&child_check, "unavailable-proc-children\n").unwrap();
    assert!(!fixture.check().unwrap());
}

#[test]
fn hotplug_missing_or_duplicate_completion_is_rejected() {
    let fixture = hotplug();
    for text in ["lan ifup 0\n", "lan ifup 0\nlan ifup 0\nloopback ifup 0\n"] {
        fixture.events(text);
        assert!(
            err(fixture.check()).contains("incomplete or duplicate"),
            "{text}"
        );
    }
}

#[test]
fn hotplug_failed_callback_is_not_completion() {
    let fixture = hotplug();
    fixture.events("lan ifup 0\nloopback ifup 1\n");
    assert!(err(fixture.check()).contains("callback failed"));
}

#[test]
fn hotplug_running_setup_cpu_is_rejected() {
    let mut fixture = hotplug();
    fixture.after["processes"][0]["child_cpu_ticks"] = json!(100);
    assert!(err(fixture.check()).contains("children still running"));
}

#[test]
fn hotplug_restarted_daemon_is_rejected() {
    let mut fixture = hotplug();
    fixture.after["processes"][0]["start_ticks"] = json!(11);
    assert!(err(fixture.check()).contains("restarted"));
}

// ------------------------------------------------- prepared reload evidence

const MD5: &[u8] = b"11 network\n22 firewall\n";

fn events() -> Vec<u8> {
    [&7u32.to_le_bytes()[..], b"network", &[0; 4]].concat()
}

struct Reload {
    dir: TempDir,
    sample: Value,
    data: Value,
}

fn reload() -> Reload {
    let dir = TempDir::new("owrt-bench");
    let raw = dir.path();
    let lane = raw.join("single_change");
    let one = lane.join("iteration-000000");
    fs::create_dir_all(&one).unwrap();
    for (path, value) in [
        (raw.join("single.md5"), MD5.to_vec()),
        (lane.join("expected.md5"), MD5.to_vec()),
        (lane.join("expected.events"), events()),
        (one.join("after.md5"), MD5.to_vec()),
        (one.join("repeat.md5"), MD5.to_vec()),
        (one.join("after.events"), events()),
        (one.join("repeat.events"), Vec::new()),
    ] {
        fs::write(path, value).unwrap();
    }
    for execution in ["exec", "repeat"] {
        for kind in ["stdout", "stderr"] {
            touch(&one.join(format!("{execution}.{kind}")));
        }
        fs::write(one.join(format!("{execution}.status")), "exit status: 0\n").unwrap();
    }
    put(
        &raw.join("reload-roles.json"),
        &json!({"ubusd": 1, "receiver": 2, "logd": 3}),
    );
    let dependencies: Vec<Value> = (1..=3)
        .map(|pid| {
            let before = json!({"pid": pid, "start_ticks": 1, "process_cpu_resolution_ns": 1, "process_cpu_ns": 10000, "child_cpu_ticks": 0});
            let after = patched(&before, json!({"process_cpu_ns": 11000}));
            json!({"pid": pid, "before": before, "after": after, "cpu_clock_ns": 1000})
        })
        .collect();
    let sample = json!({"iteration": 0, "phase": "measured", "event": "completed",
                        "latency_ns": 1000000, "prepare_ns": 9000000, "validation_ns": 8000000,
                        "command_user_us": 100, "command_system_us": 200, "caller_cpu_ns": 5000,
                        "child_counter_source": "getrusage(RUSAGE_CHILDREN)",
                        "command_before": {"user_us": 100000, "system_us": 200000},
                        "command_after": {"user_us": 100100, "system_us": 200200},
                        "dependencies": dependencies, "baseline_matches": true,
                        "events_match": true, "repeat_silent": true});
    let data = json!({"mode": "prepared-exec", "successful": 1, "warmup": 0, "timeouts": 0,
                      "resource_samples": 0, "task_samples": 0, "measured": [sample], "latency_ns": [1000000],
                      "wall_s": 0.001, "envelope_s": 0.100, "ops_per_s": 1000,
                      "mean_us": 1000, "p50_us": 1000, "p95_us": 1000, "p99_us": 1000,
                      "accounting": "per-exec", "dependency_envelope": dependencies});
    let fixture = Reload { dir, sample, data };
    fixture.journal();
    fixture
}

impl Reload {
    fn journal(&self) {
        let start = json!({"iteration": 0, "phase": "measured", "event": "started"});
        fs::write(
            self.dir.path().join("single_change/samples.jsonl"),
            format!("{start}\n{}\n", self.sample),
        )
        .unwrap();
    }

    fn one(&self) -> PathBuf {
        self.dir.path().join("single_change/iteration-000000")
    }

    fn derive(&self) -> Result<Value> {
        prepared_exec(&self.dir.path().join("single_change.json"), &self.data)
    }
}

#[test]
fn reload_exec_cpu_and_throughput_exclude_reset_checks_and_repeat() {
    let result = reload().derive().unwrap();
    for (name, expected) in [
        ("command_tree_cpu_us_per_op", 300.0),
        ("client_cpu_clock_us_per_op", 5.0),
        ("ubusd_cpu_clock_us_per_op", 1.0),
        ("prepare_us_per_op", 9000.0),
        ("validation_us_per_op", 8000.0),
        ("ops_per_s", 1000.0),
    ] {
        assert_eq!(f(&result[name]), expected, "{name}");
    }
}

#[test]
fn reload_complete_four_side_collection_keeps_new_cpu_and_fixture_gates() {
    let fixture = reload();
    let dir = TempDir::new("owrt-bench");
    let root = dir.path();
    let sides = ["stock", "r89", "r94", "candidate"];
    let subjects: serde_json::Map<String, Value> = sides
        .iter()
        .zip(["a", "b", "c", "d"])
        .map(|(side, l)| ((*side).to_owned(), json!(l.repeat(64))))
        .collect();
    let settings = json!({"component": "reload-config", "matrix": true, "baseline_label": "r89",
                          "schedule": "random-blocks", "reload_prepared_exec": true,
                          "reload_workloads": ["single_change"], "reload_warmup": 0,
                          "extra_baselines": {"r94": {"subject_sha256": subjects["r94"],
                                                      "provenance": {"subject_sha256": subjects["r94"]}}}});
    put(&root.join("order.json"), &json!(sides));
    put(
        &root.join("subjects.json"),
        &Value::Object(subjects.clone()),
    );
    put(&root.join("settings.json"), &settings);
    put(
        &root.join("host-manifest.json"),
        &json!({"components": {"ubusd": {"original": {"sha256": "bus"}}}}),
    );
    for phase in ["before", "after"] {
        put(
            &root.join(format!("health-{phase}.json")),
            &json!({"boot_id": "boot"}),
        );
        fs::write(
            root.join(format!("config-{phase}.sha256")),
            "unchanged production",
        )
        .unwrap();
    }
    touch(&root.join("COMPLETE"));
    for (index, side) in sides.iter().enumerate() {
        let local = root.join(format!("{:02}-{side}", index + 1));
        let raw = local.join("raw");
        fs::create_dir_all(&local).unwrap();
        util::copy_tree(fixture.dir.path(), &raw).unwrap();
        touch(&local.join("COMPLETE"));
        touch(&raw.join("COMPLETE"));
        fs::write(local.join("raw.tar.gz"), b"archive fixture").unwrap();
        put(
            &raw.join("single_change.json"),
            &patched(&fixture.data, json!({"errors": 0, "daemon_cpu": []})),
        );
        put(
            &raw.join("meta.json"),
            &json!({"component": "reload-config", "dependencies": "original OpenWrt", "subject_pid": null, "iterations": 20}),
        );
        let stock = subjects["stock"].as_str().unwrap();
        for (name, value) in [
            (
                "binary-sha256.txt",
                subjects[*side].as_str().unwrap().to_owned(),
            ),
            ("boot-id.txt", "boot".into()),
            ("benchmark-sha256.txt", "bench /bench\nns /ns".into()),
            ("harness-sha256.txt", "harness /harness".into()),
            ("kernel.txt", "kernel".into()),
            ("reload-fixtures.sha256", "unchanged fixture".into()),
            (
                "reload-running-dependencies.sha256",
                "bus /proc/1/exe\nbench /proc/2/exe\nlog /proc/3/exe".into(),
            ),
            (
                "reload-dependencies.sha256",
                format!("bus /sbin/ubusd\nlog /sbin/logd\n{stock} /sbin/reload_config"),
            ),
        ] {
            fs::write(raw.join(name), value + "\n").unwrap();
        }
    }
    let result = derive(root, "four-side prepared fixture").unwrap();
    assert_eq!(result["acceptance_eligible"], json!(true));
    let summary = &result["summary"]["single_change"];
    assert_eq!(
        f(&summary["candidate"]["command_tree_cpu_us_per_op"]["median"]),
        300.0
    );
    assert_eq!(
        f(&summary["candidate"]["receiver_cpu_clock_us_per_op"]["median"]),
        1.0
    );
    assert!(summary.get("candidate_vs_r94_pct").is_some());
    let text = markdown(&result, "four-side prepared fixture").unwrap();
    assert!(
        text.contains("候选比 r94 mean / CPU")
            && text.contains("CPU 口径：command_tree_cpu_us_per_op")
    );
    fs::write(
        root.join("03-r94/raw/reload-fixtures.sha256"),
        "wrong fixture",
    )
    .unwrap();
    assert!(err(derive(root, "bad")).contains("fixtures changed"));
}

#[test]
fn reload_missing_duplicate_wrong_order_or_nonzero_result_is_rejected() {
    let fixture = reload();
    let mut doubled = events();
    doubled.extend(events());
    let mut flipped = events();
    *flipped.last_mut().unwrap() = 1;
    for bad in [Vec::new(), doubled, flipped, b"network\n".to_vec()] {
        fs::write(fixture.one().join("after.events"), bad).unwrap();
        assert!(fixture.derive().is_err());
    }
}

#[test]
fn reload_repeat_event_and_complete_baseline_mismatch_are_rejected() {
    let fixture = reload();
    fs::write(fixture.one().join("repeat.events"), events()).unwrap();
    assert!(fixture.derive().is_err());
    fs::write(fixture.one().join("repeat.events"), b"").unwrap();
    fs::write(fixture.one().join("after.md5"), &MD5[..MD5.len() - 1]).unwrap();
    assert!(fixture.derive().is_err());
}

#[test]
fn reload_cpu_counter_and_journal_mismatch_are_rejected() {
    let mut fixture = reload();
    fixture.sample["command_user_us"] = json!(101);
    fixture.data["measured"][0] = fixture.sample.clone();
    fixture.journal();
    assert!(err(fixture.derive()).contains("raw counters"));
    fixture.data["measured"][0]["command_user_us"] = json!(100);
    assert!(err(fixture.derive()).contains("durable"));
}

#[test]
fn reload_envelope_time_cannot_be_called_exec_throughput() {
    let mut fixture = reload();
    fixture.data["wall_s"] = fixture.data["envelope_s"].clone();
    assert!(err(fixture.derive()).contains("reset/check"));
}

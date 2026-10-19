//! Reload fixtures: reset/check work stays outside every measured exec interval.
//! The service receiver accepts config.change only and has no reload triggers.
use super::{
    child_cpu, cpu_clock, emit, fields_to_json, integer, num, obj, pid_list, proc_json,
    proc_sample, require, ticks_per_second, Connection, Incoming, Json, MsgType, Result,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

fn event_record(package: &[u8]) -> Vec<u8> {
    let mut bytes = (package.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(package);
    bytes.extend_from_slice(&0u32.to_le_bytes()); // successful receiver result
    bytes
}

pub fn serve(socket: &str, transcript: &str) -> Result<()> {
    let mut log = OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(transcript)?;
    let mut connection = Connection::connect(Some(socket))?;
    let object = connection.add_object(
        "service",
        &[(
            "event",
            &[("type", MsgType::String), ("data", MsgType::Table)],
        )],
        3000,
    )?;
    loop {
        let Incoming::Invoke(request) = connection.read_incoming()? else {
            continue;
        };
        let payload = fields_to_json(&request.data)?;
        require(
            request.objid == object && request.method == "event" && request.fd.is_none(),
            "unexpected service request",
        )?;
        let expected = payload
            .get("data")
            .and_then(|d| d.get("package"))
            .and_then(Json::as_bytes)
            .ok_or("missing raw package")?;
        require(
            payload
                == obj([
                    ("type", Json::Str("config.change".into())),
                    (
                        "data",
                        obj([("package", Json::from_string_bytes(expected.to_vec()))]),
                    ),
                ]),
            "unexpected event payload",
        )?;
        // Append/flush before replying. Successful command exit plus the exact
        // transcript proves the ordered request and its successful acceptance.
        log.write_all(&event_record(expected))?;
        log.flush()?;
        connection.reply_status(&request, 0, None)?;
    }
}

fn replace_config(source: &Path, target: &Path) -> Result<()> {
    for item in fs::read_dir(target)? {
        let item = item?;
        require(
            item.file_type()?.is_file(),
            "non-file in private config fixture",
        )?;
        fs::remove_file(item.path())?;
    }
    for item in fs::read_dir(source)? {
        let item = item?;
        require(
            item.file_type()?.is_file(),
            "non-file in frozen config fixture",
        )?;
        fs::copy(item.path(), target.join(item.file_name()))?;
    }
    Ok(())
}
fn run(program: &str, args: &[String], destination: &Path) -> Result<()> {
    let output = Command::new(program).args(args).output()?;
    fs::write(destination.with_extension("stdout"), &output.stdout)?;
    fs::write(destination.with_extension("stderr"), &output.stderr)?;
    fs::write(
        destination.with_extension("status"),
        format!("{}\n", output.status),
    )?;
    require(output.status.success(), "reload command failed")?;
    require(output.stdout.is_empty(), "unexpected reload stdout")?;
    require(output.stderr.is_empty(), "unexpected reload stderr")
}
fn check(
    baseline: &Path,
    transcript: &Path,
    expected_md5: &[u8],
    expected_events: &[u8],
    destination: &Path,
) -> Result<()> {
    let md5 = fs::read(baseline)?;
    let events = fs::read(transcript)?;
    fs::write(destination.with_extension("md5"), &md5)?;
    fs::write(destination.with_extension("events"), &events)?;
    require(
        md5 == expected_md5,
        "complete config.md5 differs from exact-image oracle",
    )?;
    require(
        events == expected_events,
        "raw event package/result/order/count mismatch",
    )
}
fn delta(after: u64, before: u64) -> Result<u64> {
    after
        .checked_sub(before)
        .ok_or_else(|| "CPU counter regressed".into())
}

pub fn measure(args: &[String]) -> Result<()> {
    require(
        args.len() >= 9 && args[7] == "--",
        "reload-exec LANE N WARMUP FIXTURE OUT PIDS RESOURCE_OR_- -- PROGRAM [ARGS...]",
    )?;
    let lane = &args[0];
    require(
        [
            "first_baseline",
            "unchanged_config",
            "single_change",
            "multi_change",
            "comment_only",
        ]
        .contains(&lane.as_str()),
        "unknown reload lane",
    )?;
    let n: usize = args[1].parse()?;
    let warmup: usize = args[2].parse()?;
    require(n > 0, "zero iterations")?;
    let fixture = Path::new(&args[3]);
    let out = Path::new(&args[4]);
    fs::create_dir(out)?;
    let pids = pid_list(&args[5])?;
    require(
        pids.len() == 3,
        "reload requires fixed ubusd, receiver and private logd PIDs",
    )?;
    let resource = &args[6];
    let program = &args[8];
    let command_args = &args[9..];
    let baseline = Path::new("/var/run/config.md5");
    let transcript = fixture.join("events.bin");
    let old = fs::read(fixture.join("base.md5"))?;
    let variant = match lane.as_str() {
        "single_change" => "single",
        "multi_change" => "multi",
        "comment_only" => "comment",
        _ => "base",
    };
    let expected_md5 = fs::read(fixture.join(format!("{variant}.md5")))?;
    let expected_events = match lane.as_str() {
        "single_change" => event_record(b"network"),
        "multi_change" => [
            event_record(b"firewall"),
            event_record(b"network"),
            event_record(b"r84fixture"),
        ]
        .concat(),
        _ => Vec::new(),
    };
    fs::write(out.join("expected.md5"), &expected_md5)?;
    fs::write(out.join("expected.events"), &expected_events)?;
    let mut journal = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join("samples.jsonl"))?;
    let own_before = proc_sample(std::process::id())?;
    let dependency_envelope_before = pids
        .iter()
        .map(|&pid| proc_sample(pid))
        .collect::<Result<Vec<_>>>()?;
    let epoch = Instant::now();
    let mut samples = Vec::new();
    let mut measured = Vec::new();
    let resources = if resource == "-" { 0 } else { 3 };
    let task_probe = std::env::var_os("OWRT_RELOAD_TASK_PROBE");
    let task_samples = usize::from(task_probe.is_some());
    for i in 0..warmup + n + resources + task_samples {
        let phase = if i < warmup {
            "warmup"
        } else if i < warmup + n {
            "measured"
        } else if i < warmup + n + resources {
            "resource"
        } else {
            "tasks"
        };
        let iteration = out.join(format!("iteration-{i:06}"));
        fs::create_dir(&iteration)?;
        writeln!(
            journal,
            "{}",
            obj([
                ("iteration", integer(i as u64)),
                ("phase", Json::Str(phase.into())),
                ("event", Json::Str("started".into()))
            ])
            .to_compact()
        )?;
        journal.flush()?;
        let prepare_start = Instant::now();
        replace_config(&fixture.join(variant), Path::new("/etc/config"))?;
        fs::write(&transcript, [])?;
        if lane == "first_baseline" {
            match fs::remove_file(baseline) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
        } else {
            fs::write(baseline, &old)?;
        }
        let prepare_ns = prepare_start.elapsed().as_nanos() as u64;
        let dependencies_before = pids
            .iter()
            .map(|&pid| proc_sample(pid))
            .collect::<Result<Vec<_>>>()?;
        let child_before = child_cpu::sample()?;
        let caller_before = cpu_clock::sample(std::process::id())?;
        let start = Instant::now();
        let result = if phase == "resource" || phase == "tasks" {
            let probe = if phase == "resource" {
                std::ffi::OsStr::new(resource)
            } else {
                task_probe.as_deref().ok_or("missing task probe")?
            };
            let output_name = if phase == "resource" {
                "resource.json"
            } else {
                "tasks.json"
            };
            let mut resource_args = vec![
                iteration.join(output_name).to_string_lossy().into_owned(),
                program.clone(),
            ];
            resource_args.extend_from_slice(command_args);
            Command::new(probe).args(resource_args).output()
        } else {
            Command::new(program).args(command_args).output()
        };
        let elapsed = start.elapsed().as_nanos() as u64;
        let caller_after = cpu_clock::sample(std::process::id())?;
        let child_after = child_cpu::sample()?;
        let dependencies_after = pids
            .iter()
            .map(|&pid| proc_sample(pid))
            .collect::<Result<Vec<_>>>()?;
        let validation_start = Instant::now();
        let output = result?;
        fs::write(iteration.join("exec.stdout"), &output.stdout)?;
        fs::write(iteration.join("exec.stderr"), &output.stderr)?;
        fs::write(
            iteration.join("exec.status"),
            format!("{}\n", output.status),
        )?;
        require(
            output.status.success() && output.stdout.is_empty() && output.stderr.is_empty(),
            "reload exec exit/stdout/stderr invalid",
        )?;
        check(
            baseline,
            &transcript,
            &expected_md5,
            &expected_events,
            &iteration.join("after"),
        )?;
        fs::write(&transcript, [])?;
        run(program, command_args, &iteration.join("repeat"))?;
        check(
            baseline,
            &transcript,
            &expected_md5,
            &[],
            &iteration.join("repeat"),
        )?;
        let validation_ns = validation_start.elapsed().as_nanos() as u64;
        let dependencies = pids
            .iter()
            .zip(&dependencies_before)
            .zip(&dependencies_after)
            .map(|((&pid, b), a)| {
                require(b.start_ticks == a.start_ticks, "dependency process changed")?;
                require(
                    b.child_ticks == a.child_ticks,
                    "receiver or ubusd unexpectedly spawned children",
                )?;
                Ok(obj([
                    ("pid", integer(pid as u64)),
                    ("before", proc_json(pid, b)),
                    ("after", proc_json(pid, a)),
                    (
                        "cpu_clock_ns",
                        integer(delta(a.cpu_clock.ns, b.cpu_clock.ns)?),
                    ),
                ]))
            })
            .collect::<Result<Vec<_>>>()?;
        let record = obj([
            ("iteration", integer(i as u64)),
            ("phase", Json::Str(phase.into())),
            ("event", Json::Str("completed".into())),
            ("latency_ns", integer(elapsed)),
            ("prepare_ns", integer(prepare_ns)),
            ("validation_ns", integer(validation_ns)),
            (
                "child_counter_source",
                Json::Str("getrusage(RUSAGE_CHILDREN)".into()),
            ),
            (
                "command_before",
                obj([
                    ("user_us", integer(child_before.user_us)),
                    ("system_us", integer(child_before.system_us)),
                ]),
            ),
            (
                "command_after",
                obj([
                    ("user_us", integer(child_after.user_us)),
                    ("system_us", integer(child_after.system_us)),
                ]),
            ),
            (
                "command_user_us",
                integer(delta(child_after.user_us, child_before.user_us)?),
            ),
            (
                "command_system_us",
                integer(delta(child_after.system_us, child_before.system_us)?),
            ),
            (
                "caller_cpu_ns",
                integer(delta(caller_after.ns, caller_before.ns)?),
            ),
            ("dependencies", Json::Array(dependencies)),
            ("baseline_matches", Json::Bool(true)),
            ("events_match", Json::Bool(true)),
            ("repeat_silent", Json::Bool(true)),
        ]);
        writeln!(journal, "{}", record.to_compact())?;
        journal.flush()?;
        if phase == "measured" {
            samples.push(elapsed);
            measured.push(record);
        }
    }
    let envelope_s = epoch.elapsed().as_secs_f64();
    let own_after = proc_sample(std::process::id())?;
    let dependency_envelope = pids
        .iter()
        .zip(&dependency_envelope_before)
        .map(|(&pid, before)| {
            let after = proc_sample(pid)?;
            require(
                before.start_ticks == after.start_ticks,
                "dependency replaced over full envelope",
            )?;
            Ok(obj([
                ("pid", integer(pid as u64)),
                ("before", proc_json(pid, before)),
                ("after", proc_json(pid, &after)),
                (
                    "cpu_clock_ns",
                    integer(delta(after.cpu_clock.ns, before.cpu_clock.ns)?),
                ),
            ]))
        })
        .collect::<Result<Vec<_>>>()?;
    let raw = Json::Array(samples.iter().copied().map(integer).collect());
    let total_ns: u64 = samples.iter().sum();
    samples.sort_unstable();
    let percentile = |p: f64| num(samples[((n - 1) as f64 * p).round() as usize] as f64 / 1000.0);
    emit(obj([("schema", integer(1)), ("mode", Json::Str("prepared-exec".into())), ("successful", integer(n as u64)), ("errors", integer(0)), ("timeouts", integer(0)),
        ("warmup", integer(warmup as u64)), ("wall_s", num(total_ns as f64 / 1e9)), ("envelope_s", num(envelope_s)),
        ("ops_per_s", num(n as f64 * 1e9 / total_ns as f64)), ("mean_us", num(total_ns as f64 / n as f64 / 1000.0)),
        ("p50_us", percentile(0.5)), ("p95_us", percentile(0.95)), ("p99_us", percentile(0.99)), ("latency_ns", raw),
        ("daemon_cpu", Json::Array(Vec::new())), ("measured", Json::Array(measured)), ("resource_samples", integer(resources as u64)), ("task_samples", integer(task_samples as u64)),
        ("client_before", proc_json(std::process::id(), &own_before)), ("client_after", proc_json(std::process::id(), &own_after)),
        ("clock_ticks_per_second", integer(ticks_per_second()?)), ("dependency_envelope", Json::Array(dependency_envelope)),
        ("accounting", Json::Str("sum of per-exec getrusage children and process clocks; reset, validation, repeat and resources excluded".into()))]));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transcript_keeps_non_utf8_and_unambiguous_package_boundaries() {
        assert_eq!(
            event_record(b"a\xff\n"),
            [3, 0, 0, 0, b'a', 255, b'\n', 0, 0, 0, 0]
        );
        assert_ne!(
            [event_record(b"a"), event_record(b"bc")].concat(),
            [event_record(b"ab"), event_record(b"c")].concat()
        );
        assert_ne!(
            [event_record(b"a"), event_record(b"b")].concat(),
            [event_record(b"b"), event_record(b"a")].concat()
        );
    }
}

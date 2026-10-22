//! Separate diagnostic caller. Its clocks perturb the workload; none of these
//! samples replaces the frozen benchmark or identifies a scheduler wait alone.
use super::{
    emit, integer, obj, proc_json, proc_sample, require, BlobBuf, Connection, Json, MsgType, Result,
};
use std::ffi::{c_int, c_long};
use std::io;
use std::os::fd::FromRawFd;

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
compile_error!("registration-phase requires 64-bit Linux");

#[repr(C)]
#[derive(Default)]
struct Timespec {
    sec: c_long,
    nsec: c_long,
}
unsafe extern "C" {
    fn clock_getcpuclockid(pid: c_int, clock: *mut c_int) -> c_int;
    fn clock_gettime(clock: c_int, value: *mut Timespec) -> c_int;
    fn clock_getres(clock: c_int, value: *mut Timespec) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
}

// PERF_ATTR_SIZE_VER0: no sampling or mmap buffer is requested. All fields
// are zero except type/config/size and disabled + context_switch flags.
#[repr(C)]
#[derive(Default)]
struct PerfAttr {
    kind: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
}

fn perf_capability() -> Json {
    #[cfg(target_arch = "aarch64")]
    const NUMBER: c_long = 241;
    #[cfg(target_arch = "x86_64")]
    const NUMBER: c_long = 298;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    compile_error!("perf capability syscall number audited only on aarch64/x86_64");
    let attr = PerfAttr {
        kind: 1,
        size: std::mem::size_of::<PerfAttr>() as u32,
        config: 1,
        flags: 1 | (1 << 26),
        ..Default::default()
    };
    // SAFETY: pointer is valid for attr.size; pid=0/cpu=-1 opens only this
    // calling thread. Disabled means no counts; the owned fd is closed now.
    let fd = unsafe {
        syscall(
            NUMBER,
            &attr as *const PerfAttr,
            0 as c_int,
            -1 as c_int,
            -1 as c_int,
            0 as c_long,
        )
    };
    let error = if fd < 0 {
        io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    } else {
        // SAFETY: successful perf_event_open returns a fresh owned descriptor.
        unsafe {
            drop(std::fs::File::from_raw_fd(fd as c_int));
        }
        0
    };
    obj([("available", Json::Bool(fd >= 0)), ("errno", Json::Int(error as i64)),
        ("event", Json::Str("PERF_TYPE_SOFTWARE/PERF_COUNT_SW_TASK_CLOCK; disabled=1; context_switch=1; self thread only; immediately closed".into()))])
}

fn read(clock: c_int, resolution: bool) -> Result<u64> {
    let mut t = Timespec::default();
    // SAFETY: Timespec follows time_t/long on the selected Linux 64-bit ABI.
    let rc = unsafe {
        if resolution {
            clock_getres(clock, &mut t)
        } else {
            clock_gettime(clock, &mut t)
        }
    };
    if rc != 0 {
        return Err(io::Error::last_os_error().into());
    }
    require(
        t.sec >= 0 && (0..1_000_000_000).contains(&t.nsec),
        "invalid clock timespec",
    )?;
    Ok((t.sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|x| x.checked_add(t.nsec as u64))
        .ok_or("clock overflow")?)
}

fn cpu_clock(pid: u32) -> Result<c_int> {
    let mut clock = 0;
    // SAFETY: clock is writable; the PID is explicitly range checked.
    let rc = unsafe { clock_getcpuclockid(c_int::try_from(pid)?, &mut clock) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc).into());
    }
    Ok(clock)
}

// Each CPU observation is bounded by two monotonic reads. CPU deltas span
// instrumentation too; operation wall intervals exclude the middle snapshot.
#[derive(Clone, Copy, Default)]
struct Stamp {
    wall_before: u64,
    caller: u64,
    daemon: u64,
    wall_after: u64,
}

fn stamp(caller: c_int, daemon: c_int) -> Result<Stamp> {
    Ok(Stamp {
        wall_before: read(1, false)?,
        caller: read(caller, false)?,
        daemon: read(daemon, false)?,
        wall_after: read(1, false)?,
    })
}

#[derive(Clone, Copy, Default)]
struct Sample {
    cycle_start: u64,
    add_end: u64,
    remove_start: u64,
    cycle_end: u64,
    cpu: [Stamp; 3],
}

fn array(values: impl IntoIterator<Item = u64>) -> Json {
    Json::Array(values.into_iter().map(integer).collect())
}

pub fn run(a: &[String]) -> Result<()> {
    require(a.len() == 10,
        "register-phase SOCKET METHODS NAME_BYTES N WARMUP DAEMON_PID cycle-wall|phase-wall|phase-cpu PROBE_N")?;
    let methods_count: usize = a[3].parse()?;
    let name_bytes: usize = a[4].parse()?;
    let n: usize = a[5].parse()?;
    let warmup: usize = a[6].parse()?;
    let daemon_pid: u32 = a[7].parse()?;
    let mode = a[8].as_str();
    let probe_n: usize = a[9].parse()?;
    require(
        (1..=64).contains(&methods_count)
            && (8..=128).contains(&name_bytes)
            && (1..=100_000).contains(&n)
            && warmup <= 100_000
            && (1..=10_000).contains(&probe_n),
        "diagnostic bounds exceeded",
    )?;
    require(
        matches!(mode, "cycle-wall" | "phase-wall" | "phase-cpu"),
        "invalid phase mode",
    )?;
    require(
        daemon_pid > 0 && daemon_pid != std::process::id(),
        "invalid daemon PID",
    )?;
    let perf_capability = perf_capability();
    let daemon_clock = cpu_clock(daemon_pid)?;
    let caller_clock = cpu_clock(std::process::id())?;
    let clock_resolutions = [
        read(1, true)?,
        read(caller_clock, true)?,
        read(daemon_clock, true)?,
    ];
    require(
        clock_resolutions.iter().all(|&v| v > 0),
        "zero clock resolution",
    )?;
    let daemon_before = proc_sample(daemon_pid)?;
    let caller_before = proc_sample(std::process::id())?;
    require(
        daemon_before.values.get("Threads") == Some(&1)
            && caller_before.values.get("Threads") == Some(&1),
        "single-threaded subjects required",
    )?;

    // Identical path, signature, encoding and Connection calls to register-cycle.
    let names: Vec<String> = (0..methods_count)
        .map(|i| format!("{i:08}{}", "x".repeat(name_bytes - 8)))
        .collect();
    let policy = [("policy", MsgType::Int32)];
    let methods: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), &policy[..]))
        .collect();
    let mut expected = BlobBuf::new();
    for name in &names {
        let table = expected.msg_open_table(name);
        expected.msg_u32("policy", MsgType::Int32 as u32);
        expected.msg_close(table);
    }
    let mut c = Connection::connect(Some(&a[2]))?;
    let path = "bench.cycle";
    let id = c.add_object(path, &methods, 5000)?;
    let found = c.lookup(Some(path), 5000)?;
    require(
        found.len() == 1
            && found[0].id == id
            && found[0].path == path
            && found[0].signature == expected.payload(),
        "registration signature mismatch",
    )?;
    c.remove_object(id, 5000)?;
    require(
        c.lookup(None, 5000)?.is_empty(),
        "registration preflight left objects",
    )?;

    let mut samples = vec![Sample::default(); n];
    let mut probes = vec![[0; 4]; probe_n];
    for value in &mut samples {
        // SAFETY: uniquely borrowed initialized storage; pre-fault output pages.
        unsafe {
            std::ptr::write_volatile(value, Sample::default());
        }
    }
    for value in &mut probes {
        // SAFETY: each probe is initialized, aligned and uniquely borrowed.
        unsafe {
            std::ptr::write_volatile(value, [0; 4]);
        }
    }
    // Probe all modes identically before warmup. These are elapsed brackets,
    // never per-operation corrections or claims of intrinsic clock cost.
    for value in &mut probes {
        for (index, clock) in [1, caller_clock, daemon_clock].into_iter().enumerate() {
            let before = read(1, false)?;
            std::hint::black_box(read(clock, false)?);
            value[index] = read(1, false)? - before;
        }
        let s = stamp(caller_clock, daemon_clock)?;
        value[3] = s.wall_after - s.wall_before;
    }
    for _ in 0..warmup {
        let id = c.add_object(path, &methods, 5000)?;
        c.remove_object(id, 5000)?;
    }
    require(
        c.lookup(None, 5000)?.is_empty(),
        "registration warmup left objects",
    )?;
    let loop_before = stamp(caller_clock, daemon_clock)?;
    match mode {
        "cycle-wall" => {
            for s in &mut samples {
                s.cycle_start = read(1, false)?;
                let id = c.add_object(path, &methods, 5000)?;
                c.remove_object(id, 5000)?;
                s.cycle_end = read(1, false)?;
            }
        }
        "phase-wall" => {
            for s in &mut samples {
                s.cycle_start = read(1, false)?;
                let id = c.add_object(path, &methods, 5000)?;
                s.add_end = read(1, false)?;
                s.remove_start = s.add_end;
                c.remove_object(id, 5000)?;
                s.cycle_end = read(1, false)?;
            }
        }
        "phase-cpu" => {
            for s in &mut samples {
                s.cpu[0] = stamp(caller_clock, daemon_clock)?;
                s.cycle_start = s.cpu[0].wall_after;
                let id = c.add_object(path, &methods, 5000)?;
                s.cpu[1] = stamp(caller_clock, daemon_clock)?;
                s.add_end = s.cpu[1].wall_before;
                s.remove_start = s.cpu[1].wall_after;
                c.remove_object(id, 5000)?;
                s.cpu[2] = stamp(caller_clock, daemon_clock)?;
                s.cycle_end = s.cpu[2].wall_before;
            }
        }
        _ => unreachable!("phase mode was validated before measuring"),
    }
    let loop_after = stamp(caller_clock, daemon_clock)?;
    require(
        c.lookup(None, 5000)?.is_empty(),
        "registration measurement left objects",
    )?;
    // Recheck full signature after measurement, outside the measured loop.
    let id = c.add_object(path, &methods, 5000)?;
    let found = c.lookup(Some(path), 5000)?;
    require(
        found.len() == 1
            && found[0].id == id
            && found[0].path == path
            && found[0].signature == expected.payload(),
        "final registration signature mismatch",
    )?;
    c.remove_object(id, 5000)?;
    require(
        c.lookup(None, 5000)?.is_empty(),
        "final validation left objects",
    )?;
    let daemon_after = proc_sample(daemon_pid)?;
    let caller_after = proc_sample(std::process::id())?;
    require(
        daemon_before.start_ticks == daemon_after.start_ticks
            && daemon_before.cpus_allowed == daemon_after.cpus_allowed
            && caller_before.cpus_allowed == caller_after.cpus_allowed
            && daemon_after.values.get("Threads") == Some(&1)
            && caller_after.values.get("Threads") == Some(&1),
        "subject identity/affinity/thread count changed",
    )?;
    for s in &samples {
        require(s.cycle_end > s.cycle_start, "invalid cycle clock ordering")?;
        if mode != "cycle-wall" {
            require(
                s.add_end > s.cycle_start
                    && s.remove_start >= s.add_end
                    && s.cycle_end > s.remove_start,
                "invalid phase clock ordering",
            )?;
        }
        if mode == "phase-cpu" {
            for pair in s.cpu.windows(2) {
                require(
                    pair[1].caller >= pair[0].caller && pair[1].daemon >= pair[0].daemon,
                    "CPU clock moved backwards",
                )?;
            }
        }
    }
    let stamp_json = |s: Stamp| array([s.wall_before, s.caller, s.daemon, s.wall_after]);
    emit(obj([
        ("schema", integer(1)), ("fixture", Json::Str("rust_register_phase_diagnostic".into())),
        ("mode", Json::Str(mode.into())), ("n", integer(n as u64)), ("warmup", integer(warmup as u64)),
        ("perf_capability", perf_capability),
        ("methods", integer(methods_count as u64)), ("name_bytes", integer(name_bytes as u64)),
        ("successful", integer(n as u64)), ("errors", integer(0)),
        ("full_signature_checked", Json::Bool(true)), ("final_empty", Json::Bool(true)),
        ("daemon_before", proc_json(daemon_pid, &daemon_before)), ("daemon_after", proc_json(daemon_pid, &daemon_after)),
        ("caller_before", proc_json(std::process::id(), &caller_before)), ("caller_after", proc_json(std::process::id(), &caller_after)),
        ("clock_resolution_ns", array(clock_resolutions)),
        ("clock_order", Json::Str("CLOCK_MONOTONIC, caller process CPU, daemon process CPU".into())),
        ("cpu_stamp_columns", Json::Str("wall_before_ns, caller_cpu_ns, daemon_cpu_ns, wall_after_ns".into())),
        ("loop_before", stamp_json(loop_before)), ("loop_after", stamp_json(loop_after)),
        ("probe_columns", Json::Str("wall_read_bracket_ns, caller_cpu_read_bracket_ns, daemon_cpu_read_bracket_ns, combined_stamp_ns".into())),
        ("clock_probes_ns", Json::Array(probes.into_iter().map(array).collect())),
        ("sample_columns", Json::Str("cycle_start_ns, add_end_ns, remove_start_ns, cycle_end_ns; phase fields zero in cycle-wall".into())),
        ("wall_samples_ns", Json::Array(samples.iter().map(|s|
            array([s.cycle_start, s.add_end, s.remove_start, s.cycle_end])).collect())),
        ("cpu_stamps", Json::Array(if mode == "phase-cpu" { samples.iter().map(|s|
            Json::Array(s.cpu.iter().copied().map(stamp_json).collect())).collect() } else { vec![] })),
        ("interpretation", Json::Str("Exploratory perturbed caller; CPU spans include instrumentation and cross-core overlap. Wall minus CPU is not scheduler wait. Context switches in proc snapshots cover setup and validation too.".into())),
    ]));
    Ok(())
}

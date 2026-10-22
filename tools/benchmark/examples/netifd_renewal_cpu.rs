//! Frozen cold-renewal sampler: eight events at a shared monotonic start.
//! The caller owns A/B order, process lifetime and the one-batch decision.
use owrt_ubus::convert::{fields_to_json, object_to_payload};
use owrt_ubus::json::{self, Json};
use owrt_ubus::Connection;
use std::error::Error;
use std::fs;
use std::time::Duration;

#[path = "../src/cpu_clock.rs"]
mod cpu_clock;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const LEASE: &str = r#"{"action":0,"link-up":true,"ipaddr":[{"ipaddr":"192.0.2.2","mask":"24"}],"routes":[{"target":"0.0.0.0","netmask":"0","gateway":"192.0.2.1"}],"dns":["192.0.2.53"],"data":{"leasetime":60}}"#;
const ROUND_NS: u64 = 30_000_000_000;
const OFFSET_NS: u64 = 2_000_000_000;
const SETTLE_NS: u64 = 1_000_000;

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn monotonic_ns() -> Result<u64> {
    #[repr(C)]
    struct Timespec {
        sec: i64,
        nsec: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: i32, value: *mut Timespec) -> i32;
    }
    let mut value = Timespec { sec: 0, nsec: 0 };
    // SAFETY: Linux 64-bit timespec ABI, live aligned output, CLOCK_MONOTONIC=1.
    if unsafe { clock_gettime(1, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    require(
        value.sec >= 0 && (0..1_000_000_000).contains(&value.nsec),
        "invalid monotonic clock",
    )?;
    Ok((value.sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(value.nsec as u64))
        .ok_or("monotonic clock overflow")?)
}

fn wait_until(deadline: u64) -> Result<()> {
    loop {
        let now = monotonic_ns()?;
        if now >= deadline {
            return Ok(());
        }
        std::thread::sleep(Duration::from_nanos(deadline - now));
    }
}

fn start_ticks(pid: u32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let rest = stat.rsplit_once(") ").ok_or("invalid process stat")?.1;
    Ok(rest
        .split_whitespace()
        .nth(19)
        .ok_or("short process stat")?
        .parse()?)
}

fn integer(value: u64) -> Json {
    Json::Int(value.try_into().expect("measurement fits i64"))
}
fn emit(fields: Vec<(&str, Json)>) {
    println!(
        "{}",
        Json::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect()).to_compact()
    );
}

fn status(connection: &mut Connection, object: u32) -> Result<Json> {
    let reply = connection.invoke(object, "status", &[], 3000)?;
    require(reply.fd.is_none(), "status unexpectedly returned an fd")?;
    let status = fields_to_json(&reply.fields())?;
    require(
        status.get("up") == Some(&Json::Bool(true)),
        "interface is not up",
    )?;
    let addresses = status
        .get("ipv4-address")
        .and_then(Json::as_array)
        .ok_or("missing addresses")?;
    require(addresses.len() == 1, "expected one IPv4 address")?;
    require(
        addresses[0].get("address").and_then(Json::as_str) == Some("192.0.2.2")
            && addresses[0].get("mask") == Some(&Json::Int(24)),
        "address changed",
    )?;
    let routes = status
        .get("route")
        .and_then(Json::as_array)
        .ok_or("missing routes")?;
    require(routes.len() == 1, "expected one route")?;
    require(
        routes[0].get("target").and_then(Json::as_str) == Some("0.0.0.0")
            && routes[0].get("mask") == Some(&Json::Int(0))
            && routes[0].get("nexthop").and_then(Json::as_str) == Some("192.0.2.1"),
        "route changed",
    )?;
    require(
        status.get("dns-server") == Some(&Json::Array(vec![Json::Str("192.0.2.53".into())])),
        "DNS changed",
    )?;
    require(
        status.get("data").and_then(|v| v.get("leasetime")) == Some(&Json::Int(60)),
        "lease data changed",
    )?;
    Ok(status)
}

fn notify(connection: &mut Connection, object: u32, payload: &[u8]) -> Result<()> {
    let reply = connection.invoke(object, "notify_proto", payload, 3000)?;
    require(
        reply.fd.is_none() && reply.fields().is_empty(),
        "notify returned unexpected data",
    )
}

fn scheduled(t0: u64, side: &str, round: u64) -> u64 {
    let second = (side == "A") != round.is_multiple_of(2);
    t0 + ROUND_NS * round + if second { OFFSET_NS } else { 0 }
}

fn run(args: &[String]) -> Result<()> {
    if args.len() == 2 && args[1] == "now" {
        println!("{}", monotonic_ns()?);
        return Ok(());
    }
    require(
        std::env::var("OWRT_BENCH_NAMESPACE").as_deref() == Ok("1"),
        "requires ns-exec namespace",
    )?;
    let prepare = args.get(1).map(String::as_str) == Some("prepare");
    let check = args.get(1).map(String::as_str) == Some("check");
    require(
        (prepare && args.len() == 5)
            || ((args.get(1).map(String::as_str) == Some("run") || check) && args.len() == 7),
        "prepare SOCKET PID OBJECT | run|check SOCKET PID OBJECT A|B T0_MONOTONIC_NS",
    )?;
    let pid: u32 = args[3].parse()?;
    require(pid > 1 && pid != std::process::id(), "invalid subject PID")?;
    let identity = start_ticks(pid)?;
    let executable = fs::read_link(format!("/proc/{pid}/exe"))?;
    let mut connection = Connection::connect(Some(&args[2]))?;
    let object = connection.lookup_id(&args[4], 3000)?;
    let payload = object_to_payload(&json::parse(LEASE)?);
    if prepare {
        notify(&mut connection, object, &payload)?;
        println!("{}", status(&mut connection, object)?.to_compact());
        return Ok(());
    }
    let side = args[5].as_str();
    require(side == "A" || side == "B", "side must be A or B")?;
    let t0: u64 = args[6].parse()?;
    require(
        t0 >= monotonic_ns()? + 1_000_000_000,
        "T0 arrived too late; do not reschedule",
    )?;
    require(t0.checked_add(8 * ROUND_NS).is_some(), "T0 overflow")?;
    status(&mut connection, object)?;
    // `check` is one Oracle instrumentation check, never a device A/B window.
    for round in 0..if check { 1 } else { 8 } {
        let due = scheduled(t0, side, round);
        // A separate, un-subtracted 1 ms idle floor ends before the event.
        wait_until(due - 3 * SETTLE_NS)?;
        let idle_before = cpu_clock::sample(pid)?;
        let idle_start = monotonic_ns()?;
        wait_until(idle_start + SETTLE_NS)?;
        let idle_after = cpu_clock::sample(pid)?;
        let idle_end = monotonic_ns()?;
        wait_until(due)?;
        let before = cpu_clock::sample(pid)?;
        let invoke_start = monotonic_ns()?;
        notify(&mut connection, object, &payload)?;
        let reply_time = monotonic_ns()?;
        let at_reply = cpu_clock::sample(pid)?;
        wait_until(reply_time + SETTLE_NS)?;
        let after = cpu_clock::sample(pid)?;
        let settled_time = monotonic_ns()?;
        require(
            start_ticks(pid)? == identity
                && fs::read_link(format!("/proc/{pid}/exe"))? == executable,
            "subject identity changed",
        )?;
        require(
            before.resolution_ns == after.resolution_ns
                && before.resolution_ns == at_reply.resolution_ns
                && before.resolution_ns == idle_before.resolution_ns
                && before.resolution_ns == idle_after.resolution_ns,
            "CPU clock resolution changed",
        )?;
        let cpu = after
            .ns
            .checked_sub(before.ns)
            .ok_or("CPU clock regressed")?;
        let reply_cpu = at_reply
            .ns
            .checked_sub(before.ns)
            .ok_or("reply CPU clock regressed")?;
        let idle_cpu = idle_after
            .ns
            .checked_sub(idle_before.ns)
            .ok_or("idle CPU clock regressed")?;
        status(&mut connection, object)?;
        emit(vec![
            ("schema", Json::Int(1)),
            ("side", Json::Str(side.into())),
            ("round", integer(round)),
            ("instrument_preflight", Json::Bool(check)),
            (
                "phase",
                Json::Str(if round < 3 { "calibration" } else { "formal" }.into()),
            ),
            (
                "order",
                Json::Str(if round % 2 == 0 { "AB" } else { "BA" }.into()),
            ),
            ("t0_ns", integer(t0)),
            ("scheduled_ns", integer(due)),
            ("invoke_start_ns", integer(invoke_start)),
            ("reply_ns", integer(reply_time)),
            ("settled_ns", integer(settled_time)),
            ("start_lag_ns", integer(invoke_start.saturating_sub(due))),
            ("subject_pid", integer(u64::from(pid))),
            ("subject_start_ticks", integer(identity)),
            ("subject_cpu_before_ns", integer(before.ns)),
            ("subject_cpu_reply_ns", integer(at_reply.ns)),
            ("subject_cpu_after_ns", integer(after.ns)),
            ("subject_cpu_ns", integer(cpu)),
            ("subject_reply_cpu_ns", integer(reply_cpu)),
            ("subject_resolution_ns", integer(before.resolution_ns)),
            ("idle_before_ns", integer(idle_before.ns)),
            ("idle_after_ns", integer(idle_after.ns)),
            ("idle_cpu_ns", integer(idle_cpu)),
            ("idle_wall_ns", integer(idle_end - idle_start)),
            ("settle_wall_ns", integer(settled_time - reply_time)),
            ("successful", Json::Int(1)),
            ("errors", Json::Int(0)),
            ("identity_and_state_checked", Json::Bool(true)),
        ]);
    }
    Ok(())
}

fn main() {
    if let Err(error) = run(&std::env::args().collect::<Vec<_>>()) {
        eprintln!("netifd-renewal-cpu: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_schedule_has_three_calibration_and_five_formal_events() {
        let t0 = 1_000_000_000;
        for round in 0..8 {
            let a = scheduled(t0, "A", round);
            let b = scheduled(t0, "B", round);
            assert_eq!(a.min(b), t0 + round * ROUND_NS);
            assert_eq!(a.abs_diff(b), OFFSET_NS);
            assert_eq!(a < b, round % 2 == 0);
        }
        assert_eq!(scheduled(t0, "A", 7), t0 + 212_000_000_000);
    }
}

//! fw4-rs: firewall4 replacement (contract C4). Same command surface as
//! `/sbin/fw4`; `FW4_MOCK_DIRS=dir1:dir2` switches all inputs to the upstream
//! test-suite fixture layout and `FW4_TRACE=stderr` emits the `[call]` trace.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]

mod emit;
mod input;
mod ip;
mod parse;
mod render;
mod sections;
mod state;
mod statefile;
mod uci;
mod val;

use input::Inputs;
use owrt_ubus::json::Json;
use parse::Fw4;
use statefile::STATEFILE;
use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

const LOCK: &str = "/var/run/fw4.lock";

extern "C" {
    fn flock(fd: i32, op: i32) -> i32;
}

struct Lock(#[allow(dead_code)] std::fs::File);

fn lock() -> Option<Lock> {
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(LOCK).ok()?;
    use std::os::unix::io::AsRawFd;
    // SAFETY: flock(2) on a descriptor this function just opened and still
    // owns. LOCK_EX == 2.
    if unsafe { flock(f.as_raw_fd(), 2) } != 0 {
        return None;
    }
    Some(Lock(f))
}

fn is_mock() -> bool {
    std::env::var("FW4_MOCK_DIRS").is_ok()
}

fn new_fw4(quiet: bool) -> Fw4 {
    let inputs = match std::env::var("FW4_MOCK_DIRS") {
        Ok(dirs) => Inputs::mock(
            dirs.split(':').filter(|d| !d.is_empty()).map(str::to_owned).collect(),
            std::env::var("FW4_TRACE").map(|t| t == "stderr" || t == "1").unwrap_or(false),
        ),
        Err(_) => Inputs::real(),
    };
    Fw4 {
        inputs,
        firewall: uci::Config::empty(),
        helpers_cfg: uci::Config::empty(),
        state: state::State::default(),
        kernel: 0,
        quiet: quiet || std::env::var("QUIET").map(|q| !q.is_empty()).unwrap_or(false),
        tty: std::env::var("TTY").map(|t| !t.is_empty()).unwrap_or(false),
    }
}

fn die(quiet: bool, msg: &str) -> ! {
    if !quiet {
        eprintln!("{msg}");
    }
    std::process::exit(1);
}

/// Exit code of the ucode interpreter when an uncaught exception aborts
/// `main.uc`; the shell `/sbin/fw4` propagates it through `set -o pipefail`.
const UCODE_ABORT: i32 = 254;

/// `ACTION=start|print`: render the ruleset; with `use_statefile` also write
/// the state file like ucode's `load(true)`.  `None` is ucode aborting inside
/// `load()` — nothing is rendered and no state file is written.
fn render(quiet: bool, use_statefile: bool) -> Option<String> {
    let mut fw = new_fw4(quiet);
    fw.load().ok()?;
    if use_statefile {
        let json = statefile::to_json(&fw.state).to_compact();
        if !fw.inputs.write_file(STATEFILE, &json) {
            fw.raw_warn(&format!("Unable to write '{STATEFILE}': Permission denied\n"));
        }
    }
    Some(fw.render_ruleset())
}

/// Feed `ruleset` to `nft [-e] [-c] -f -`; returns the exit code.
fn nft_load(ruleset: &str, verbose: bool, check: bool, quiet_io: bool) -> i32 {
    let mut cmd = Command::new("nft");
    if verbose {
        cmd.arg("-e");
    }
    if check {
        cmd.arg("-c");
    }
    cmd.args(["-f", "-"]).stdin(Stdio::piped());
    if quiet_io {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let Ok(mut child) = cmd.spawn() else { return 127 };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(ruleset.as_bytes());
    }
    child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1)
}

fn read_saved(fw: &Fw4) -> statefile::Saved {
    let Some(text) = fw.inputs.read_all(STATEFILE) else {
        fw.raw_warn("Unable to read firewall state - do you need to start the firewall?\n");
        std::process::exit(1);
    };
    match owrt_ubus::json::parse(&text) {
        Ok(j) => statefile::parse(&j),
        Err(e) => {
            fw.raw_warn(&format!("Unable to parse '{STATEFILE}': {e}\n"));
            fw.raw_warn("Unable to read firewall state - do you need to start the firewall?\n");
            std::process::exit(1);
        }
    }
}

fn run_includes(quiet: bool) -> i32 {
    let fw = new_fw4(quiet);
    let saved = read_saved(&fw);
    for inc in &saved.includes {
        if inc.ty != "script" {
            continue;
        }
        let path = inc.path.replace('\'', "'\\''");
        let argv = vec![
            "sh".to_owned(),
            "-c".to_owned(),
            format!("exec 1000>&-; config() {{ echo \"You cannot use UCI in firewall includes!\" >&2; exit 1; }}; . '{path}'"),
        ];
        let rc = fw.inputs.system_argv(&argv, 30000);
        if rc != 0 {
            fw.raw_warn(&format!("Include '{}' failed with exit code {rc}\n", inc.path));
        }
    }
    0
}

fn reload_sets(quiet: bool) -> String {
    let fw = new_fw4(quiet);
    let saved = read_saved(&fw);
    let sets = fw.check_set_types();
    let mut out = String::new();
    for set in &saved.ipsets {
        if set.loadfile.is_none() && set.entries.is_empty() {
            continue;
        }
        let Some((_, types)) = sets.iter().find(|(n, _)| *n == set.name) else {
            fw.raw_warn(&format!(
                "Named set '{}' does not exist - do you need to restart the firewall?\n",
                set.name
            ));
            continue;
        };
        if emit::concat(types) != emit::concat(&set.types) {
            fw.raw_warn(&format!(
                "Named set '{}' has a different type - want '{}' but is '{}' - do you need to restart the firewall?\n",
                set.name,
                emit::concat(&set.types),
                emit::concat(types)
            ));
            continue;
        }
        out.push_str(&format!("flush set inet fw4 {}\n", set.name));
        let mut first = true;
        let mut body = String::new();
        {
            let mut printer = |entry: &[String]| {
                if first {
                    body.push_str(&format!("add element inet fw4 {} {{\n", set.name));
                    first = false;
                }
                body.push_str(&format!("\t{},\n", entry.join(" . ")));
            };
            for e in &set.entries {
                printer(e);
            }
            if set.loadfile.is_some() {
                fw.parse_setfile(set, &mut printer);
            }
        }
        out.push_str(&body);
        if !first {
            out.push_str("}\n\n");
        }
    }
    out
}

fn lookup(quiet: bool, action: &str, object: Option<&str>, device: Option<&str>) -> i32 {
    let fw = new_fw4(quiet);
    let saved = read_saved(&fw);
    let name = |z: &Json| z.get("name").map(val::to_str).unwrap_or_default();
    let devices_of = |z: &Json| -> Vec<String> {
        let mut out = Vec::new();
        if let Some(Json::Array(rules)) = z.get("match_rules") {
            for r in rules {
                if let Some(Json::Array(d)) = r.get("devices_pos") {
                    out.extend(d.iter().map(val::to_str));
                }
            }
        }
        out
    };
    let object = object.unwrap_or("");
    match action {
        "network" => {
            for z in &saved.zones {
                if let Some(Json::Array(nets)) = z.get("network") {
                    if nets.iter().any(|n| n.get("device").map(|d| val::loose_eq_str(d, object)).unwrap_or(false)) {
                        println!("{}", name(z));
                        return 0;
                    }
                }
            }
            1
        }
        "device" => {
            for z in &saved.zones {
                if devices_of(z).iter().any(|d| d == object) {
                    println!("{}", name(z));
                    return 0;
                }
            }
            1
        }
        _ => {
            for z in &saved.zones {
                if name(z) == object {
                    let devices = devices_of(z);
                    if let Some(dev) = device.filter(|d| !d.is_empty()) {
                        if devices.iter().any(|d| d == dev) {
                            println!("{dev}");
                            return 0;
                        }
                        return 1;
                    }
                    if !devices.is_empty() {
                        println!("{}", devices.join("\n"));
                    }
                    return 0;
                }
            }
            1
        }
    }
}

fn usage(argv0: &str) {
    print!(
        "Usage:
  {argv0} [-v] [-q] start|stop|flush|restart|reload
    Start, stop, flush, restart or reload the firewall respectively.
  {argv0} [-v] [-q] reload-sets
    Reload the contents of all declared sets but do not touch the
    ruleset.
  {argv0} [-q] print
    Print the rendered ruleset.
  {argv0} [-q] check
    Test the rendered ruleset using nftables' check mode without
    applying it to the running system.
  {argv0} [-q] network {{net}}
    Print the name of the firewall zone covering the given network.
    Exits with code 1 if the network is not found or if no zone is
    covering it.
  {argv0} [-q] device {{dev}}
    Print the name of the firewall zone covering the given device.
    Exits with code 1 if the device is not found or if no zone is
    covering it.
  {argv0} [-q] zone {{zone}} [dev]
    Print all covered devices of the given zone, optionally restricted
    to only the given device name.
    Exits with code 1 if zone is not found or if a device is specified
    and not covered by the given zone.
"
    );
}

fn start(quiet: bool, verbose: bool, mode: &str) -> i32 {
    let _lock = lock();
    match mode {
        "start" if std::path::Path::new(STATEFILE).exists() => {
            die(quiet, "The fw4 firewall appears to be already loaded.")
        }
        "reload" => {
            if !std::path::Path::new(STATEFILE).exists() {
                die(quiet, "The fw4 firewall does not appear to be loaded.");
            }
            let _ = std::fs::remove_file(STATEFILE);
        }
        _ => {}
    }
    let Some(ruleset) = render(quiet, true) else { return UCODE_ABORT };
    nft_load(&ruleset, verbose, false, false);
    run_includes(quiet)
}

fn stop() -> i32 {
    let _lock = lock();
    let _ = Command::new("nft").args(["delete", "table", "inet", "fw4"]).status();
    let _ = std::fs::remove_file(STATEFILE);
    0
}

fn flush() -> i32 {
    let _lock = lock();
    if let Ok(out) = Command::new("nft").args(["list", "tables"]).output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let _ = Command::new("nft").args(["delete", "table", parts[1], parts[2]]).status();
            }
        }
    }
    let _ = std::fs::remove_file(STATEFILE);
    0
}

fn main() {
    let argv0 = std::env::args().next().unwrap_or_else(|| "fw4".into());
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut quiet = false;
    let mut verbose = false;
    while let Some(first) = args.first() {
        match first.as_str() {
            "-q" => {
                quiet = true;
                args.remove(0);
            }
            "-v" => {
                verbose = true;
                args.remove(0);
            }
            _ => break,
        }
    }
    if quiet {
        std::env::set_var("QUIET", "1");
    }
    if !is_mock() && std::io::stderr().is_terminal() {
        std::env::set_var("TTY", "1");
    }
    let action = args.first().map(String::as_str).unwrap_or("");
    let code = match action {
        "start" | "reload" => start(quiet, verbose, action),
        "stop" => stop(),
        "flush" => flush(),
        "restart" => {
            // the shell runs `QUIET=1 print` in a pipeline, so an abort there
            // reaches `die` just like a ruleset nft rejects.
            let Some(ruleset) = render(true, false) else {
                die(quiet, "The rendered ruleset contains errors, not doing firewall restart.")
            };
            if nft_load(&ruleset, verbose, true, false) != 0 {
                die(quiet, "The rendered ruleset contains errors, not doing firewall restart.");
            }
            stop();
            start(quiet, verbose, "")
        }
        "check" => {
            let Some(ruleset) = render(quiet, false) else { std::process::exit(UCODE_ABORT) };
            let rc = nft_load(&ruleset, verbose, true, quiet);
            if rc == 0 && !quiet {
                println!("Ruleset passes nftables check.");
            }
            rc
        }
        "print" => {
            let Some(out) = render(quiet, false) else { std::process::exit(UCODE_ABORT) };
            let _ = std::io::stdout().write_all(out.as_bytes());
            0
        }
        "reload-sets" => {
            let _lock = if is_mock() { None } else { lock() };
            let out = reload_sets(quiet);
            if is_mock() {
                let _ = std::io::stdout().write_all(out.as_bytes());
                0
            } else {
                nft_load(&out, verbose, false, false)
            }
        }
        "includes" => run_includes(quiet),
        "network" | "device" | "zone" => {
            let _lock = if is_mock() { None } else { lock() };
            lookup(quiet, action, args.get(1).map(String::as_str), args.get(2).map(String::as_str))
        }
        _ => {
            usage(&argv0);
            0
        }
    };
    std::process::exit(code);
}

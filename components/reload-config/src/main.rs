#![deny(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]
// The ubus transport targets Linux; other hosts only provide smoke builds.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

mod engine;
mod json;
mod md5;
mod syslog;
mod trace;
mod unix;

use engine::{Error, Settings};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use trace::Trace;

const EX_OK: i32 = 0;
const EX_DELIVERY: i32 = 2;
const EX_USAGE: i32 = 64;
const EX_SOFTWARE: i32 = 70;
const EX_TEMPFAIL: i32 = 75;
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

static CANCELLED: AtomicBool = AtomicBool::new(false);

fn is_cancelled() -> bool {
    CANCELLED.load(Ordering::Relaxed)
}

extern "C" fn handle_signal(_: i32) {
    CANCELLED.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() -> Result<(), std::io::Error> {
    for signal in [unix::SIGINT, unix::SIGTERM] {
        // SAFETY: the fixed handler performs only an atomic store and cannot
        // allocate, lock, access TLS, or unwind through the signal trampoline.
        #[expect(unsafe_code, reason = "register the fixed async-signal-safe handler")]
        unsafe {
            unix::set_signal_handler(signal, handle_signal)?;
        }
    }
    Ok(())
}

fn usage() -> &'static str {
    "usage: reload-config-rs [--root PATH] [--timeout-ms 1..60000] [--trace-stderr]\n\
     defaults: --root / --timeout-ms 10000, JSONL trace to syslog (daemon.info, tag reload_config)"
}

fn parse_args() -> Result<(Settings, bool), String> {
    let mut root = PathBuf::from("/");
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut trace_stderr = false;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--root" => {
                root = PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--root requires a path".to_owned())?,
                );
                if !root.is_absolute() {
                    return Err("--root must be absolute".into());
                }
            }
            "--timeout-ms" => {
                timeout_ms = arguments
                    .next()
                    .ok_or_else(|| "--timeout-ms requires a value".to_owned())?
                    .parse()
                    .map_err(|_| "--timeout-ms must be an integer".to_owned())?;
                if !(1..=60_000).contains(&timeout_ms) {
                    return Err("--timeout-ms must be between 1 and 60000".into());
                }
            }
            "--trace-stderr" => trace_stderr = true,
            "-h" | "--help" => {
                let _ = writeln!(std::io::stdout(), "{}", usage());
                std::process::exit(EX_OK);
            }
            value => return Err(format!("unknown argument {value:?}")),
        }
    }
    Ok((
        Settings {
            root,
            timeout: Duration::from_millis(timeout_ms),
        },
        trace_stderr,
    ))
}

fn main() {
    let (settings, trace_stderr) = match parse_args() {
        Ok(parsed) => parsed,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "{error}\n{}", usage());
            std::process::exit(EX_USAGE);
        }
    };
    if let Err(error) = install_signal_handlers() {
        let _ = writeln!(std::io::stderr(), "cannot install signal handlers: {error}");
        std::process::exit(EX_SOFTWARE);
    }

    let writer: Box<dyn Write> = if trace_stderr {
        Box::new(std::io::stderr())
    } else {
        Box::new(syslog::SyslogWriter::open())
    };
    let mut trace = Trace::new(writer);
    let exit = match engine::run(&settings, &CANCELLED, &mut trace) {
        Ok(outcome) if outcome.delivery_failures == 0 => EX_OK,
        Ok(_) => EX_DELIVERY,
        Err(error) => {
            let class = match error {
                Error::Cancelled => "temporary",
                Error::InvalidInput(_) => "input",
                Error::Io(_, _) => "dependency",
            };
            let _ = trace.fatal(class, &error.to_string());
            match error {
                Error::Cancelled => EX_TEMPFAIL,
                Error::InvalidInput(_) => EX_USAGE,
                Error::Io(_, _) => EX_SOFTWARE,
            }
        }
    };
    std::process::exit(exit);
}

//! fw4-rs: firewall4 replacement (contract C4). Same command surface as
//! `/sbin/fw4`; `FW4_MOCK_DIRS=dir1:dir2` switches all inputs to the upstream
//! test-suite fixture layout and `FW4_TRACE=stderr` emits the `[call]` trace.

mod emit;
mod input;
mod ip;
mod parse;
mod render;
mod sections;
mod state;
mod uci;
mod val;

use input::Inputs;
use parse::Fw4;
use std::io::{IsTerminal, Write};

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

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut quiet = false;
    while let Some(first) = args.first() {
        match first.as_str() {
            "-q" => {
                quiet = true;
                args.remove(0);
            }
            "-v" => {
                args.remove(0);
            }
            _ => break,
        }
    }
    if std::io::stderr().is_terminal() && std::env::var("FW4_MOCK_DIRS").is_err() {
        std::env::set_var("TTY", "1");
    }
    let action = args.first().map(String::as_str).unwrap_or("");
    let code = match action {
        "print" => {
            let mut fw = new_fw4(quiet);
            fw.load();
            let out = fw.render_ruleset();
            let _ = std::io::stdout().write_all(out.as_bytes());
            0
        }
        _ => {
            eprintln!("fw4-rs: unsupported action '{action}'");
            1
        }
    };
    std::process::exit(code);
}

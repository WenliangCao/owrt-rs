//! Shell protocol handlers: discovery, invocation, and the `notify_proto`
//! callbacks they use to report back.
//!
//! **Staged, not yet wired into the daemon.** Discovery, the state machine and
//! the argv construction are implemented and unit-tested here; the
//! `notify_proto` callbacks that let an interface actually reach IFS_UP are
//! not. Until those exist the daemon keeps reporting only `static` from
//! `get_proto_handlers` and refuses a shell proto outright, because a handler
//! that is advertised but cannot finish setup would leave an interface in
//! SETUP forever with no indication why.
//!
//! The contract is recorded in docs/contracts/netifd-proto-shell.md. Two parts
//! of it are easy to get wrong and fail silently:
//!
//!   * The scripts source `../netifd-proto.sh` by relative path, so they must
//!     be run with the proto directory as the working directory. Without it
//!     they fail on line 7 **and still exit 0**.
//!   * netifd starts the protocol helper itself, on the script's request
//!     (action 1). A helper the shell backgrounded would be invisible to us.

// Staged: the daemon does not call into this module yet. The lint would
// otherwise bury the fact that it is complete and tested.
#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};

use owrt_ubus::blob::{BlobBuf, MsgType};
use owrt_ubus::json::Json;

use crate::process::Slot;

/// `state->sm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Sm {
    #[default]
    Idle,
    Setup,
    Teardown,
    SetupAbort,
}

/// One discovered handler, as `dump` describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handler {
    pub name: String,
    /// The script, as an absolute path.
    pub script: PathBuf,
    /// `(option name, validation expression)`, in `dump` order.
    pub config: Vec<(String, String)>,
    pub no_device: bool,
    pub no_device_config: bool,
    pub no_task: bool,
    pub init_available: bool,
    pub renew_available: bool,
    pub last_error: bool,
    pub teardown_on_l3_link_down: bool,
}

/// A `config` entry with no `:` takes its validation name from the blobmsg
/// type: string, int32 and int8 are what the handlers on this device use.
fn default_validation(ty: u32) -> &'static str {
    match ty {
        t if t == MsgType::String as u32 => "string",
        t if t == MsgType::Int32 as u32 => "uinteger",
        t if t == MsgType::Int8 as u32 => "bool",
        t if t == MsgType::Int64 as u32 => "uinteger",
        t if t == MsgType::Array as u32 => "list(string)",
        _ => "string",
    }
}

fn json_bool(v: &Json, key: &str) -> bool {
    matches!(v.get(key), Some(Json::Bool(true)))
}

impl Handler {
    /// Parse one `dump` document.
    pub fn parse(script: &Path, text: &str) -> Result<Self, String> {
        let j = owrt_ubus::json::parse(text).map_err(|e| format!("{e}"))?;
        let Some(Json::Str(name)) = j.get("name") else {
            return Err("dump has no name".into());
        };
        let mut config = Vec::new();
        if let Some(Json::Array(items)) = j.get("config") {
            for item in items {
                let Json::Array(pair) = item else { continue };
                let (Some(Json::Str(spec)), ty) = (pair.first(), pair.get(1)) else { continue };
                let ty = match ty {
                    Some(Json::Int(n)) => *n as u32,
                    _ => MsgType::String as u32,
                };
                match spec.split_once(':') {
                    Some((n, v)) => config.push((n.to_string(), v.to_string())),
                    None => config.push((spec.clone(), default_validation(ty).to_string())),
                }
            }
        }
        Ok(Self {
            name: name.clone(),
            script: script.to_path_buf(),
            config,
            no_device: json_bool(&j, "no-device"),
            no_device_config: json_bool(&j, "no-device-config"),
            no_task: json_bool(&j, "no-proto-task"),
            init_available: json_bool(&j, "available"),
            renew_available: json_bool(&j, "renew-handler"),
            last_error: json_bool(&j, "lasterror"),
            teardown_on_l3_link_down: json_bool(&j, "teardown-on-l3-link-down"),
        })
    }

    /// The `get_proto_handlers` entry for this handler. `immediate` and
    /// `force_link_default` are not in `dump` and are false for every shell
    /// handler.
    pub fn dump_info(&self, b: &mut BlobBuf) {
        let t = b.msg_open_table(&self.name);
        let v = b.msg_open_table("validate");
        for (name, validation) in &self.config {
            b.msg_string(name, validation);
        }
        b.msg_close(v);
        b.msg_bool("immediate", false);
        b.msg_bool("no_device", self.no_device);
        b.msg_bool("init_available", self.init_available);
        b.msg_bool("renew_available", self.renew_available);
        b.msg_bool("force_link_default", false);
        b.msg_bool("last_error", self.last_error);
        b.msg_bool("teardown_on_l3_link_down", self.teardown_on_l3_link_down);
        b.msg_bool("no_task", self.no_task);
        b.msg_close(t);
    }
}

/// Discover the handlers in `dir` by running each script's `dump`.
///
/// A script that fails to describe itself is skipped with a message, not
/// silently: an interface using it would then get "unknown proto", which is
/// the honest outcome.
pub fn discover(dir: &Path) -> Vec<Handler> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut names: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "sh"))
        .collect();
    // stable order, so `get_proto_handlers` does not depend on readdir
    names.sort();
    for path in names {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
        match run_dump(dir, &path, stem) {
            Ok(text) => match Handler::parse(&path, &text) {
                Ok(h) => out.push(h),
                Err(e) => eprintln!("netifd-rs: {} dump is not usable: {e}", path.display()),
            },
            Err(e) => eprintln!("netifd-rs: cannot run {} dump: {e}", path.display()),
        }
    }
    out
}

/// `<script> <name> dump`, with the proto directory as the working directory.
fn run_dump(dir: &Path, script: &Path, name: &str) -> io::Result<String> {
    let out = std::process::Command::new(script)
        .arg(name)
        .arg("dump")
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if text.trim().is_empty() {
        // the scripts exit 0 even when sourcing netifd-proto.sh failed, so an
        // empty document is the only signal that something went wrong
        return Err(io::Error::other(format!(
            "empty dump; stderr: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(text)
}

/// The per-interface state of a shell protocol.
#[derive(Default)]
pub struct ProtoState {
    pub sm: Sm,
    /// The setup/teardown/renew script.
    pub script: Slot,
    /// The helper netifd runs on the script's behalf (action 1).
    pub task: Slot,
    /// `-1` for "none"; passed to teardown as `ERROR=<n>`.
    pub last_error: i32,
    pub renew_pending: bool,
    pub task_killed: bool,
    pub available: bool,
    pub block_restart: bool,
}

impl ProtoState {
    pub fn new() -> Self {
        Self { last_error: -1, ..Default::default() }
    }
}

/// What `proto_shell_handler` decided to do. Returned rather than performed so
/// the state machine can be tested without running anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Run the script with this action word, and this extra environment.
    Run { action: &'static str, env: Vec<(String, String)> },
    /// Signal the running script and helper, and wait for them.
    Abort,
    /// Nothing to do; the caller returns success.
    Nothing,
    /// Refused: the command is not valid in this state.
    Refuse,
}

/// `proto_shell_handler`, as a decision over the state machine. The comments
/// mark each branch's counterpart in the C.
pub fn plan(
    state: &mut ProtoState,
    cmd: Cmd,
    handler: &Handler,
) -> Action {
    match cmd {
        Cmd::Setup => match state.sm {
            Sm::Idle => {
                state.last_error = -1;
                state.sm = Sm::Setup;
                Action::Run { action: "setup", env: Vec::new() }
            }
            // "default: return -1"
            _ => Action::Refuse,
        },
        Cmd::Renew => {
            if !handler.renew_available {
                return Action::Nothing;
            }
            if state.script.is_running() {
                // a renew while the script runs is remembered, not queued
                state.renew_pending = true;
                return Action::Nothing;
            }
            state.renew_pending = false;
            Action::Run { action: "renew", env: Vec::new() }
        }
        Cmd::Teardown => match state.sm {
            Sm::Setup if state.script.is_running() => {
                state.renew_pending = false;
                state.sm = Sm::SetupAbort;
                Action::Abort
            }
            Sm::Setup | Sm::Idle => {
                state.renew_pending = false;
                state.sm = Sm::Teardown;
                let mut env = Vec::new();
                if state.last_error >= 0 {
                    env.push(("ERROR".to_string(), state.last_error.to_string()));
                }
                Action::Run { action: "teardown", env }
            }
            // "case S_TEARDOWN: return 0"
            Sm::Teardown => Action::Nothing,
            Sm::SetupAbort => Action::Refuse,
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    Setup,
    Renew,
    Teardown,
}

/// The argv `proto_shell_handler` builds:
/// `<script> <proto> <action> <interface> <config-json> [<main-device>]`.
pub fn argv(
    handler: &Handler,
    action: &str,
    iface: &str,
    config_json: &str,
    main_device: Option<&str>,
) -> Vec<String> {
    let mut v = vec![
        handler.script.to_string_lossy().into_owned(),
        handler.name.clone(),
        action.to_string(),
        iface.to_string(),
        config_json.to_string(),
    ];
    if let Some(d) = main_device {
        v.push(d.to_string());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const DHCP_DUMP: &str = r#"{ "name": "dhcp", "config": [ [ "ipaddr:ipaddr", 3 ],
        [ "clientid", 3 ], [ "broadcast:bool", 7 ], [ "delegate", 7 ],
        [ "mtu6rd", 5 ], [ "sendopts:list(string)", 1 ] ],
        "no-device": false, "no-device-config": false, "no-proto-task": false,
        "available": false, "renew-handler": true, "lasterror": false,
        "teardown-on-l3-link-down": false }"#;

    fn dhcp() -> Handler {
        Handler::parse(Path::new("/lib/netifd/proto/dhcp.sh"), DHCP_DUMP).unwrap()
    }

    #[test]
    fn a_dump_without_a_colon_takes_its_type_default() {
        let h = dhcp();
        let get = |n: &str| h.config.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
        assert_eq!(get("ipaddr"), Some("ipaddr"));
        assert_eq!(get("clientid"), Some("string"));
        assert_eq!(get("broadcast"), Some("bool"));
        assert_eq!(get("delegate"), Some("bool"));
        assert_eq!(get("mtu6rd"), Some("uinteger"));
        assert_eq!(get("sendopts"), Some("list(string)"));
    }

    #[test]
    fn the_config_order_is_the_dump_order() {
        let h = dhcp();
        assert_eq!(
            h.config.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            vec!["ipaddr", "clientid", "broadcast", "delegate", "mtu6rd", "sendopts"]
        );
    }

    #[test]
    fn the_flags_map_onto_get_proto_handlers() {
        let h = dhcp();
        assert!(h.renew_available);
        assert!(!h.init_available);
        assert!(!h.no_device);
        let mut b = BlobBuf::new();
        h.dump_info(&mut b);
        let j = owrt_ubus::convert::fields_to_json(b.payload()).to_compact();
        assert!(j.contains("\"renew_available\":true"), "{j}");
        assert!(j.contains("\"immediate\":false"), "{j}");
        assert!(j.contains("\"force_link_default\":false"), "{j}");
        assert!(j.contains("\"no_task\":false"), "{j}");
    }

    #[test]
    fn setup_is_only_accepted_when_idle() {
        let h = dhcp();
        let mut s = ProtoState::new();
        assert!(matches!(plan(&mut s, Cmd::Setup, &h), Action::Run { action: "setup", .. }));
        assert_eq!(s.sm, Sm::Setup);
        // a second setup while setting up is refused
        assert_eq!(plan(&mut s, Cmd::Setup, &h), Action::Refuse);
    }

    #[test]
    fn teardown_during_setup_aborts_instead_of_running_the_script() {
        let h = dhcp();
        let mut s = ProtoState::new();
        plan(&mut s, Cmd::Setup, &h);
        // the script has to be running for the abort path
        s.script.start(&["/bin/sh".into(), "-c".into(), "sleep 30".into()], &[]).unwrap();
        assert_eq!(plan(&mut s, Cmd::Teardown, &h), Action::Abort);
        assert_eq!(s.sm, Sm::SetupAbort);
        s.script.terminate();
    }

    #[test]
    fn teardown_carries_the_last_error_in_the_environment() {
        let h = dhcp();
        let mut s = ProtoState::new();
        s.sm = Sm::Idle;
        s.last_error = 7;
        match plan(&mut s, Cmd::Teardown, &h) {
            Action::Run { action: "teardown", env } => {
                assert_eq!(env, vec![("ERROR".to_string(), "7".to_string())]);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(s.sm, Sm::Teardown);
    }

    #[test]
    fn no_error_means_no_error_variable() {
        let h = dhcp();
        let mut s = ProtoState::new();
        match plan(&mut s, Cmd::Teardown, &h) {
            Action::Run { env, .. } => assert!(env.is_empty()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_second_teardown_is_idempotent() {
        let h = dhcp();
        let mut s = ProtoState::new();
        plan(&mut s, Cmd::Teardown, &h);
        assert_eq!(plan(&mut s, Cmd::Teardown, &h), Action::Nothing);
    }

    #[test]
    fn renew_is_remembered_rather_than_queued_while_the_script_runs() {
        let h = dhcp();
        let mut s = ProtoState::new();
        s.script.start(&["/bin/sh".into(), "-c".into(), "sleep 30".into()], &[]).unwrap();
        assert_eq!(plan(&mut s, Cmd::Renew, &h), Action::Nothing);
        assert!(s.renew_pending);
        s.script.terminate();
    }

    #[test]
    fn renew_is_a_no_op_for_a_handler_that_does_not_offer_it() {
        let mut h = dhcp();
        h.renew_available = false;
        let mut s = ProtoState::new();
        assert_eq!(plan(&mut s, Cmd::Renew, &h), Action::Nothing);
        assert!(!s.renew_pending);
    }

    #[test]
    fn the_argv_puts_the_device_last_and_only_when_there_is_one() {
        let h = dhcp();
        let with = argv(&h, "setup", "wan", "{}", Some("eth1"));
        assert_eq!(
            with,
            vec!["/lib/netifd/proto/dhcp.sh", "dhcp", "setup", "wan", "{}", "eth1"]
        );
        let without = argv(&h, "teardown", "wan", "{}", None);
        assert_eq!(without.len(), 5);
        assert_eq!(without[4], "{}");
    }

    #[test]
    fn an_empty_dump_is_an_error_not_an_empty_handler() {
        assert!(Handler::parse(Path::new("/x.sh"), "").is_err());
        assert!(Handler::parse(Path::new("/x.sh"), "{}").is_err());
    }
}

//! Shell protocol handlers: discovery, invocation, and the `notify_proto`
//! callbacks they use to report back.
//!
//! The contract is recorded in docs/contracts/netifd-proto-shell.md. Two parts
//! of it are easy to get wrong and fail silently:
//!
//!   * The scripts source `../netifd-proto.sh` by relative path, so they must
//!     be run with the proto directory as the working directory. Without it
//!     they fail on line 7 **and still exit 0**.
//!   * netifd starts the protocol helper itself, on the script's request
//!     (action 1). A helper the shell backgrounded would be invisible to us.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use owrt_ubus::blob::{self, BlobBuf, MsgType};
use owrt_ubus::json::Json;

use crate::process::Slot;
use crate::{interface, logging, sys};

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

/// Parse every document in a `dump`. One script may register more than one
/// protocol — `ppp.sh` emits both `ppp` and `pppoe`, back to back with no
/// separator — so a parser that reads a single object drops the second and
/// then fails on the "trailing characters".
pub fn parse_dump(script: &Path, text: &str) -> Result<Vec<Handler>, String> {
    let mut out = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        let (j, used) =
            owrt_ubus::json::parse_prefix(rest).map(|j| (j, 0)).map_err(|e| e.to_string())?;
        // parse_prefix does not tell us how much it consumed, so find the end
        // of this object by matching braces outside strings
        let end = if used == 0 { object_end(rest).ok_or("unterminated JSON object")? } else { used };
        out.push(Handler::from_json(script, &j)?);
        rest = rest[end..].trim_start();
    }
    if out.is_empty() {
        return Err("no documents in dump".into());
    }
    Ok(out)
}

/// The byte offset just past the first complete `{...}`, ignoring braces
/// inside strings and after a backslash.
fn object_end(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    for (i, &c) in b.iter().enumerate() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

impl Handler {
    /// Parse one `dump` document.
    #[cfg(test)]
    pub fn parse(script: &Path, text: &str) -> Result<Self, String> {
        let j = owrt_ubus::json::parse(text).map_err(|e| e.to_string())?;
        Self::from_json(script, &j)
    }

    fn from_json(script: &Path, j: &owrt_ubus::json::Json) -> Result<Self, String> {
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
            no_device: json_bool(j, "no-device"),
            no_device_config: json_bool(j, "no-device-config"),
            no_task: json_bool(j, "no-proto-task"),
            init_available: json_bool(j, "available"),
            renew_available: json_bool(j, "renew-handler"),
            last_error: json_bool(j, "lasterror"),
            teardown_on_l3_link_down: json_bool(j, "teardown-on-l3-link-down"),
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
            Ok(text) => match parse_dump(&path, &text) {
                Ok(hs) => out.extend(hs),
                Err(e) => logging::log!(Warning, "{} dump is not usable: {e}", path.display()),
            },
            Err(e) => logging::log!(Warning, "cannot run {} dump: {e}", path.display()),
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
    /// A reload replaces the desired config before the running protocol
    /// finishes. Keep its old contract until do_reload drops this state.
    /// Allocated only during a reload, never on the steady query path.
    pub teardown_config: Option<Box<crate::config::InterfaceConfig>>,
    /// The setup/teardown/renew script.
    pub script: Slot,
    /// Rust observes exec failures synchronously; deliver the missing child
    /// completion on the next loop turn, like the C's exit-127 callback.
    pub script_start_failed: bool,
    /// The helper netifd runs on the script's behalf (action 1).
    pub task: Slot,
    /// `-1` for "none"; passed to teardown as `ERROR=<n>`.
    pub last_error: i32,
    pub renew_pending: bool,
    pub task_killed: bool,
    pub available: bool,
    pub block_restart: bool,
    /// Seconds-since-boot at which the checkup fires, while it is armed.
    pub checkup_at: Option<u64>,
    /// `teardown_timeout`, in milliseconds since boot: 1 s after a setup is
    /// aborted, 5 s after a teardown starts. Past it both children are
    /// SIGKILLed and the state machine completes as if they had exited.
    pub teardown_deadline: Option<u64>,
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
            if !handler.renew_available || matches!(state.sm, Sm::Teardown | Sm::SetupAbort) {
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

/// Which of the two slots exited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Script,
    Task,
}

/// What has to happen after a child exits, from `proto_shell_task_finish`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finish {
    /// `IFPEV_LINK_LOST`: the helper died while the interface was up.
    LinkLost,
    Teardown,
    Renew,
    /// Arm the checkup timer: the setup script finished but the interface is
    /// not up yet.
    ArmCheckup,
    /// The helper is still running during teardown and has not been signalled.
    SignalTask(u32),
    /// `IFPEV_DOWN`: teardown is complete.
    Down,
}

/// `proto_shell_task_finish`, as a list of effects. The state machine moves
/// here; the caller performs the effects.
///
/// The C's `S_IDLE` case falls through into `S_SETUP`, so a script exit is
/// handled the same way in both — that fallthrough is easy to miss and decides
/// whether a finished setup script tears the interface back down.
pub fn task_finish(
    state: &mut ProtoState,
    which: Which,
    handler: &Handler,
    checkup_interval: u32,
) -> Vec<Finish> {
    let mut out = Vec::new();
    match state.sm {
        Sm::Idle | Sm::Setup => {
            if which == Which::Task {
                if state.sm == Sm::Idle {
                    out.push(Finish::LinkLost);
                }
                out.push(Finish::Teardown);
                return out;
            }
            // the script exited
            if state.renew_pending {
                out.push(Finish::Renew);
            } else if !handler.no_task && !state.task.is_running() && state.sm == Sm::Setup {
                out.push(Finish::Teardown);
            }
            if state.sm == Sm::Setup && checkup_interval > 0 {
                out.push(Finish::ArmCheckup);
            }
        }
        Sm::SetupAbort => {
            if state.script.is_running() || state.task.is_running() {
                return out;
            }
            state.sm = Sm::Idle;
            state.teardown_deadline = None;
            out.push(Finish::Teardown);
        }
        Sm::Teardown => {
            if state.script.is_running() {
                return out;
            }
            if state.task.is_running() {
                if !state.task_killed {
                    out.push(Finish::SignalTask(crate::process::SIGTERM as u32));
                }
                return out;
            }
            state.sm = Sm::Idle;
            state.teardown_deadline = None;
            out.push(Finish::Down);
        }
    }
    out
}

/// The interface options netifd itself declares (`iface_attrs`), with the
/// blobmsg type each carries. The config document handed to a script is the
/// union of these and the handler's own `config` list, so an option that is in
/// neither is not passed at all — matching `uci_to_blob`, which only copies
/// what a parameter list names.
pub const IFACE_ATTRS: &[(&str, MsgType)] = &[
    ("device", MsgType::String),
    ("proto", MsgType::String),
    ("ifname", MsgType::String),
    ("auto", MsgType::Int8),
    ("zone", MsgType::String),
    ("jail", MsgType::String),
    ("jail_device", MsgType::String),
    ("jail_ifname", MsgType::String),
    ("host_device", MsgType::String),
    ("defaultroute", MsgType::Int8),
    ("peerdns", MsgType::Int8),
    ("metric", MsgType::Int32),
    ("dns", MsgType::Array),
    ("renew", MsgType::Int8),
    ("dns_search", MsgType::Array),
    ("dns_metric", MsgType::Int32),
    ("interface", MsgType::String),
    ("ip6assign", MsgType::Int32),
    ("ip6hint", MsgType::String),
    ("ip4table", MsgType::String),
    ("ip6table", MsgType::String),
    ("ip6class", MsgType::Array),
    ("delegate", MsgType::Int8),
    ("ip6ifaceid", MsgType::String),
    ("force_link", MsgType::Int8),
    ("ip6weight", MsgType::Int32),
    ("tags", MsgType::Array),
];

/// The blobmsg type an option is carried as: the handler's declaration wins,
/// then netifd's own interface attributes, otherwise it is not passed.
fn option_type(handler: &Handler, name: &str) -> Option<MsgType> {
    if let Some((_, spec)) = handler.config.iter().find(|(n, _)| n == name) {
        return Some(if spec.starts_with("list(") {
            MsgType::Array
        } else if spec == "bool" {
            MsgType::Int8
        } else if spec == "uinteger" || spec.starts_with("range(") {
            MsgType::Int32
        } else {
            MsgType::String
        });
    }
    IFACE_ATTRS.iter().find(|(n, _)| *n == name).map(|(_, t)| *t)
}

/// The config document a script receives as its fourth argument, built the way
/// `blobmsg_format_json(state->config, true)` renders the blob: a JSON object
/// whose values carry the declared types, not the raw strings.
pub fn config_json(handler: &Handler, opts: &[(String, Vec<String>)]) -> String {
    let mut b = BlobBuf::new();
    for (name, values) in opts {
        let Some(ty) = option_type(handler, name) else { continue };
        match ty {
            MsgType::Array => {
                let a = b.msg_open_array(name);
                for v in values {
                    b.msg_string("", v);
                }
                b.msg_close(a);
            }
            MsgType::Int8 => {
                let v = values.first().map(|s| s.as_str()).unwrap_or("");
                b.msg_bool(name, matches!(v, "1" | "on" | "true" | "enabled" | "yes"));
            }
            MsgType::Int32 => {
                let v: i64 = values.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                b.msg_u32(name, v as u32);
            }
            _ => {
                // a scalar written as a list is joined, as uci_to_blob does
                b.msg_string(name, &values.join(" "));
            }
        }
    }
    owrt_ubus::convert::fields_to_json(b.payload()).to_compact()
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
    fn renew_during_teardown_or_abort_is_dropped_with_or_without_a_script() {
        let h = dhcp();
        for sm in [Sm::Teardown, Sm::SetupAbort] {
            for running in [false, true] {
                let mut s = ProtoState::new();
                s.sm = sm;
                if running {
                    s.script.start(&["/bin/sleep".into(), "30".into()], &[]).unwrap();
                }
                assert_eq!(plan(&mut s, Cmd::Renew, &h), Action::Nothing);
                assert!(!s.renew_pending);
                assert_eq!(s.sm, sm);
                s.script.terminate();
            }
        }
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
    fn a_helper_dying_while_idle_reports_the_link_lost_then_tears_down() {
        let h = dhcp();
        let mut s = ProtoState::new();
        assert_eq!(
            task_finish(&mut s, Which::Task, &h, 0),
            vec![Finish::LinkLost, Finish::Teardown]
        );
    }

    #[test]
    fn a_helper_dying_during_setup_tears_down_without_a_link_lost() {
        let h = dhcp();
        let mut s = ProtoState::new();
        s.sm = Sm::Setup;
        assert_eq!(task_finish(&mut s, Which::Task, &h, 0), vec![Finish::Teardown]);
    }

    #[test]
    fn a_setup_script_that_started_no_helper_tears_the_interface_back_down() {
        let h = dhcp();
        let mut s = ProtoState::new();
        s.sm = Sm::Setup;
        // no helper running and the handler is not NO_TASK: nothing is going
        // to bring the interface up, so netifd gives up
        assert_eq!(task_finish(&mut s, Which::Script, &h, 0), vec![Finish::Teardown]);
    }

    #[test]
    fn a_setup_script_that_started_a_helper_waits_for_it() {
        let h = dhcp();
        let mut s = ProtoState::new();
        s.sm = Sm::Setup;
        s.task.start(&["/bin/sh".into(), "-c".into(), "sleep 30".into()], &[]).unwrap();
        assert!(task_finish(&mut s, Which::Script, &h, 0).is_empty());
        s.task.terminate();
    }

    #[test]
    fn a_pending_renew_wins_over_the_teardown() {
        let h = dhcp();
        let mut s = ProtoState::new();
        s.sm = Sm::Setup;
        s.renew_pending = true;
        assert_eq!(task_finish(&mut s, Which::Script, &h, 0), vec![Finish::Renew]);
    }

    #[test]
    fn the_checkup_timer_is_armed_only_while_still_setting_up() {
        let h = dhcp();
        let mut s = ProtoState::new();
        s.sm = Sm::Setup;
        s.task.start(&["/bin/sh".into(), "-c".into(), "sleep 30".into()], &[]).unwrap();
        assert_eq!(task_finish(&mut s, Which::Script, &h, 10), vec![Finish::ArmCheckup]);
        s.task.terminate();
        // idle: no checkup
        let mut s2 = ProtoState::new();
        assert!(task_finish(&mut s2, Which::Script, &h, 10).is_empty());
    }

    #[test]
    fn an_abort_becomes_idle_and_then_tears_down_once_both_children_are_gone() {
        let h = dhcp();
        let mut s = ProtoState::new();
        s.sm = Sm::SetupAbort;
        s.script.start(&["/bin/sh".into(), "-c".into(), "sleep 30".into()], &[]).unwrap();
        assert!(task_finish(&mut s, Which::Script, &h, 0).is_empty());
        assert_eq!(s.sm, Sm::SetupAbort);
        s.script.terminate();
        assert_eq!(task_finish(&mut s, Which::Script, &h, 0), vec![Finish::Teardown]);
        assert_eq!(s.sm, Sm::Idle);
    }

    #[test]
    fn teardown_signals_a_surviving_helper_once_and_only_once() {
        let h = dhcp();
        let mut s = ProtoState::new();
        s.sm = Sm::Teardown;
        s.task.start(&["/bin/sh".into(), "-c".into(), "sleep 30".into()], &[]).unwrap();
        assert_eq!(
            task_finish(&mut s, Which::Script, &h, 0),
            vec![Finish::SignalTask(crate::process::SIGTERM as u32)]
        );
        s.task_killed = true;
        assert!(task_finish(&mut s, Which::Script, &h, 0).is_empty());
        s.task.terminate();
        assert_eq!(task_finish(&mut s, Which::Script, &h, 0), vec![Finish::Down]);
        assert_eq!(s.sm, Sm::Idle);
    }

    #[test]
    fn the_config_document_carries_the_declared_types() {
        let h = dhcp();
        let opts = vec![
            ("proto".to_string(), vec!["dhcp".to_string()]),
            ("clientid".to_string(), vec!["abc".to_string()]),
            ("broadcast".to_string(), vec!["1".to_string()]),
            ("mtu6rd".to_string(), vec!["1400".to_string()]),
            ("sendopts".to_string(), vec!["a".to_string(), "b".to_string()]),
            ("metric".to_string(), vec!["13".to_string()]),
        ];
        let j = config_json(&h, &opts);
        assert!(j.contains("\"proto\":\"dhcp\""), "{j}");
        assert!(j.contains("\"broadcast\":true"), "{j}");
        assert!(j.contains("\"mtu6rd\":1400"), "{j}");
        assert!(j.contains("\"sendopts\":[\"a\",\"b\"]"), "{j}");
        assert!(j.contains("\"metric\":13"), "{j}");
    }

    #[test]
    fn an_option_neither_side_declares_is_not_passed() {
        let h = dhcp();
        let opts = vec![("wombat".to_string(), vec!["x".to_string()])];
        assert_eq!(config_json(&h, &opts), "{}");
    }

    #[test]
    fn one_script_may_register_two_protocols() {
        // ppp.sh emits both documents back to back with no separator
        let text = format!(
            "{}\n{}",
            DHCP_DUMP,
            DHCP_DUMP.replace("\"name\": \"dhcp\"", "\"name\": \"dhcpv6\"")
        );
        let hs = parse_dump(Path::new("/lib/netifd/proto/ppp.sh"), &text).unwrap();
        assert_eq!(hs.len(), 2);
        assert_eq!(hs[0].name, "dhcp");
        assert_eq!(hs[1].name, "dhcpv6");
    }

    #[test]
    fn a_brace_inside_a_string_does_not_end_the_object() {
        let text = r#"{ "name": "x", "config": [ [ "a:or(\"{\",\"}\")", 3 ] ] }"#;
        let hs = parse_dump(Path::new("/x.sh"), text).unwrap();
        assert_eq!(hs.len(), 1);
        assert_eq!(hs[0].config[0].1, "or(\"{\",\"}\")");
    }

    #[test]
    fn an_empty_dump_is_an_error_not_an_empty_handler() {
        assert!(Handler::parse(Path::new("/x.sh"), "").is_err());
        assert!(Handler::parse(Path::new("/x.sh"), "{}").is_err());
    }
}

// ---------------------------------------------------------------------------
// notify_proto action 0: the payload the handler scripts actually send.
//
// The shapes here are `notify_attr` in proto-ext.c plus `proto_ip_attributes`,
// `proto_ip_addr` and `route_attr`. They are NOT the flat UCI shape that
// proto-static reads: `ipaddr` is an array of tables, and the addresses and
// routes carry their own masks.

/// `parse_netmask_string`. Returns `u32::MAX` for a string it rejects, as the
/// C's `~0` does, so a caller's single "greater than 32/128" check covers both
/// a rejected string and an out-of-range number.
pub fn parse_netmask(s: &str, v6: bool) -> u32 {
    if !s.contains('.') {
        return strtoul0(s).unwrap_or(u32::MAX);
    }
    if v6 {
        return u32::MAX;
    }
    match dotted_quad(s) {
        // 32 - fls(~mask). Deliberately not a contiguity check: the C gives a
        // defined answer for a non-contiguous mask rather than refusing it.
        Some(m) => 32 - fls(!m),
        None => u32::MAX,
    }
}

/// `fls`: 0 for zero, else the 1-based index of the highest set bit.
fn fls(x: u32) -> u32 {
    if x == 0 {
        0
    } else {
        32 - x.leading_zeros()
    }
}

/// `strtoul(s, &err, 0)` with the C's "reject only trailing garbage" rule.
/// Base 0 means `0x` is hex and a leading `0` is octal; an empty string is
/// accepted as 0, because strtoul leaves `*endptr` at the terminator.
fn strtoul0(s: &str) -> Option<u32> {
    let t = s.trim_start();
    let (digits, radix) = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        (h, 16)
    } else if t.len() > 1 && t.starts_with('0') {
        (&t[1..], 8)
    } else {
        (t, 10)
    };
    if digits.is_empty() {
        // "" and "0" both land here; strtoul returns 0 for both
        return Some(0);
    }
    let end = digits
        .find(|c: char| !c.is_digit(radix))
        .unwrap_or(digits.len());
    if end != digits.len() {
        return None; // trailing garbage
    }
    u32::from_str_radix(digits, radix).ok()
}

/// Dotted-quad only. `inet_aton` also takes "10", "10.1" and hex octets; the
/// scripts on this device always send four decimal octets, and the difference
/// is recorded in docs/contracts/netifd-proto-shell.md.
fn dotted_quad(s: &str) -> Option<u32> {
    let ip: std::net::Ipv4Addr = s.trim().parse().ok()?;
    Some(u32::from_be_bytes(ip.octets()))
}

/// One entry of `ipaddr` / `ip6addr`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotifyAddr {
    pub ip: IpAddr,
    pub mask: u8,
    pub broadcast: Option<std::net::Ipv4Addr>,
    pub point_to_point: Option<IpAddr>,
    pub offlink: bool,
    pub class: Option<String>,
    pub preferred: Option<u32>,
    pub valid: Option<u32>,
}

/// `parse_address_item`. `None` is the C's `goto error`, which makes
/// `parse_address_list` return -1 and abandons the rest of the IP settings --
/// but does NOT stop the interface coming up, because
/// `proto_ext_update_link` ignores `proto_apply_ip_settings`'s return value.
pub fn parse_addr_item(f: &blob::Field, v6: bool) -> Option<NotifyAddr> {
    if f.ty != MsgType::Table as u32 {
        return None;
    }
    let kids: Vec<blob::Field> = f.children().collect();
    let get = |n: &str| kids.iter().find(|k| k.name == n).copied();

    let max = if v6 { 128 } else { 32 };
    let mut mask = max;
    // blobmsg_parse_attr filters optional attributes by their policy type.
    // A numeric mask is absent to the C parser, so the host mask remains.
    if let Some(value) = get("mask").and_then(|c| c.as_str()) {
        let m = parse_netmask(value, v6);
        if m > max as u32 {
            return None;
        }
        mask = m as u8;
    }
    let ip: IpAddr = match v6 {
        false => IpAddr::V4(get("ipaddr")?.as_str()?.parse().ok()?),
        true => IpAddr::V6(get("ipaddr")?.as_str()?.parse().ok()?),
    };
    let mut a = NotifyAddr {
        ip,
        mask,
        broadcast: None,
        point_to_point: None,
        offlink: get("offlink").and_then(|c| c.as_bool()).unwrap_or(false),
        class: None,
        preferred: None,
        valid: None,
    };
    if !v6 {
        if let Some(value) = get("broadcast").and_then(|c| c.as_str()) {
            a.broadcast = Some(value.parse().ok()?);
        }
        if let Some(value) = get("ptp").and_then(|c| c.as_str()) {
            a.point_to_point = Some(IpAddr::V4(value.parse().ok()?));
        }
    } else {
        // 0xffffffff is "infinite" and is dropped rather than stored
        a.preferred = get("preferred").and_then(|c| c.as_u32()).filter(|v| *v != u32::MAX);
        a.valid = get("valid").and_then(|c| c.as_u32()).filter(|v| *v != u32::MAX);
        if let (Some(p), Some(v)) = (a.preferred, a.valid) {
            if p > v {
                return None;
            }
        }
        if a.valid.is_some() && a.preferred.is_none() {
            a.preferred = a.valid;
        }
        a.class = get("class").and_then(|c| c.as_str()).map(|s| s.to_string());
    }
    Some(a)
}

/// `interface_ip_add_route` for one table of `routes` / `routes6`. `None`
/// means the C's `goto error`, which drops just this route.
pub fn parse_route_item(f: &blob::Field, v6: bool) -> Option<interface::Route> {
    if f.ty != MsgType::Table as u32 {
        return None;
    }
    let kids: Vec<blob::Field> = f.children().collect();
    let get = |n: &str| kids.iter().find(|k| k.name == n).copied();

    if get("disabled").and_then(|c| c.as_bool()).unwrap_or(false) {
        return None;
    }
    let max: u8 = if v6 { 128 } else { 32 };
    let unspec: IpAddr = if v6 {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    };
    let mut mask = max;
    if let Some(c) = get("netmask") {
        let m = parse_netmask(c.as_str()?, v6);
        if m > max as u32 {
            return None;
        }
        mask = m as u8;
    }
    let mut target = unspec;
    if let Some(c) = get("target") {
        let s = c.as_str()?;
        // parse_ip_and_netmask: an inline "/len" overrides `netmask`
        let (astr, m) = match s.split_once('/') {
            Some((a, m)) => {
                let m = parse_netmask(m, v6);
                if m > max as u32 {
                    return None;
                }
                (a, m as u8)
            }
            None => (s, mask),
        };
        mask = m;
        target = match v6 {
            false => IpAddr::V4(astr.parse().ok()?),
            true => IpAddr::V6(astr.parse().ok()?),
        };
        // "Mask out IPv4 host bits" -- v4 only, and only below /32
        if let (IpAddr::V4(v4), true) = (target, !v6 && mask < 32) {
            let bits = u32::from_be_bytes(v4.octets());
            let keep = if mask == 0 { 0 } else { u32::MAX << (32 - mask) };
            target = IpAddr::V4(std::net::Ipv4Addr::from(bits & keep));
        }
    }
    let mut r = interface::Route::new(target, mask, unspec);
    if let Some(c) = get("gateway") {
        r.nexthop = match v6 {
            false => IpAddr::V4(c.as_str()?.parse().ok()?),
            true => IpAddr::V6(c.as_str()?.parse().ok()?),
        };
    }
    if let Some(c) = get("metric") {
        r.metric = c.as_u32()?;
        r.flags |= interface::devroute::METRIC;
    }
    if let Some(c) = get("mtu") {
        r.mtu = c.as_u32()?;
        r.flags |= interface::devroute::MTU;
    }
    if let Some(c) = get("source") {
        let s = c.as_str()?;
        let (astr, m) = match s.split_once('/') {
            Some((a, m)) => (a, m.parse::<u8>().ok().filter(|v| *v <= max)?),
            None => (s, max),
        };
        r.source = match v6 {
            false => IpAddr::V4(astr.parse().ok()?),
            true => IpAddr::V6(astr.parse().ok()?),
        };
        r.sourcemask = m;
    }
    if get("onlink").and_then(|c| c.as_bool()).unwrap_or(false) {
        r.flags |= interface::devroute::ONLINK;
    }
    if let Some(c) = get("table") {
        let t = resolve_rt_table(c.as_str()?)?;
        // the main table is not flagged, so it is not printed
        if t != sys::RT_TABLE_MAIN {
            r.table = t;
            r.flags |= interface::devroute::TABLE;
        }
    }
    // `route->valid_until = valid + now` unless 0xffffffff
    r.valid_until = get("valid")
        .and_then(|c| c.as_u32())
        .filter(|v| *v != u32::MAX)
        .map(|v| (crate::clock::now() + v as u64).min(u32::MAX as u64) as u32);
    if let Some(c) = get("type") {
        r.ty = resolve_rt_type(c.as_str()?)?;
        r.flags |= interface::devroute::TYPE;
    }
    if let Some(c) = get("proto") {
        r.proto = resolve_rt_proto(c.as_str()?)?;
        r.flags |= interface::devroute::PROTO;
    }
    Some(r)
}

/// `interface_ip_add_neighbor` for one entry of `neighbor` / `neighbor6`.
/// `ipaddr` is required; a `mac` that will not parse rejects the entry.
pub fn parse_neighbor_item(f: &blob::Field, v6: bool) -> Option<interface::Neighbor> {
    if f.ty != MsgType::Table as u32 {
        return None;
    }
    let kids: Vec<blob::Field> = f.children().collect();
    let get = |n: &str| kids.iter().find(|k| k.name == n).copied();
    let addr: IpAddr = match v6 {
        false => IpAddr::V4(get("ipaddr")?.as_str()?.parse().ok()?),
        true => IpAddr::V6(get("ipaddr")?.as_str()?.parse().ok()?),
    };
    let mut n = interface::Neighbor {
        addr,
        mac: None,
        proxy: get("proxy").and_then(|c| c.as_bool()).unwrap_or(false) as u32,
        router: get("router").and_then(|c| c.as_bool()).unwrap_or(false) as u32,
        enabled: true,
    };
    if let Some(c) = get("mac") {
        n.mac = Some(parse_mac(c.as_str()?)?);
    }
    Some(n)
}

/// `ether_aton`, for the six-octet colon form the scripts send.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for slot in out.iter_mut() {
        *slot = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

pub(crate) use crate::rt::{resolve_rt_proto, resolve_rt_table, resolve_rt_type};


#[cfg(test)]
mod rt_resolver_tests {
    use super::*;

    #[test]
    fn rt_numbers_use_strtoul_base_0() {
        assert_eq!(resolve_rt_table("0x10"), Some(16), "hex, like the C");
        assert_eq!(resolve_rt_table("010"), Some(8), "octal, like the C");
        assert_eq!(resolve_rt_table("16"), Some(16));
        assert_eq!(resolve_rt_table("-1"), Some(u32::MAX), "unsigned wrap");
        assert_eq!(resolve_rt_table("default"), Some(253));
        assert_eq!(resolve_rt_table("main"), Some(sys::RT_TABLE_MAIN));
        assert_eq!(resolve_rt_table("no-such-table-name"), None);
    }

    #[test]
    fn rt_proto_allows_zero_and_caps_at_255() {
        assert_eq!(resolve_rt_proto("0"), Some(0), "0 is a valid proto");
        assert_eq!(resolve_rt_proto("0xff"), Some(255));
        assert_eq!(resolve_rt_proto("256"), None);
        assert_eq!(resolve_rt_proto("static"), Some(4));
        assert_eq!(resolve_rt_proto("-1"), None, "wraps above 255");
    }
}

#[cfg(test)]
mod notify_tests {
    use super::*;

    #[test]
    fn a_netmask_is_a_length_or_a_dotted_quad() {
        assert_eq!(parse_netmask("24", false), 24);
        assert_eq!(parse_netmask("255.255.255.0", false), 24);
        assert_eq!(parse_netmask("255.255.255.255", false), 32);
        assert_eq!(parse_netmask("0.0.0.0", false), 0);
        assert_eq!(parse_netmask("64", true), 64);
        // a dotted quad is meaningless for v6 and is refused
        assert_eq!(parse_netmask("255.255.255.0", true), u32::MAX);
        // base 0, so hex works, as strtoul does
        assert_eq!(parse_netmask("0x18", false), 24);
        // out of range is returned as-is; the caller range-checks
        assert_eq!(parse_netmask("200", false), 200);
        assert_eq!(parse_netmask("24x", false), u32::MAX);
    }

    #[test]
    fn a_non_contiguous_netmask_is_not_refused() {
        // 32 - fls(~mask): the C computes a defined answer rather than
        // rejecting the mask, and a rewrite that "fixes" this diverges.
        assert_eq!(parse_netmask("255.0.255.0", false), 8);
    }

    fn table(fields: &[(&str, &str)]) -> Vec<u8> {
        let mut b = blob::BlobBuf::new();
        let c = b.msg_open_table("x");
        for (k, v) in fields {
            b.msg_string(k, v);
        }
        b.msg_close(c);
        b.payload().to_vec()
    }

    fn one(buf: &[u8]) -> blob::Field<'_> {
        blob::fields(buf).next().unwrap()
    }

    #[test]
    fn an_address_item_is_a_table_with_its_own_mask() {
        // exactly what dhcp.script sends
        let buf = table(&[("ipaddr", "10.0.0.100"), ("mask", "255.255.255.0")]);
        let a = parse_addr_item(&one(&buf), false).unwrap();
        assert_eq!(a.ip, "10.0.0.100".parse::<IpAddr>().unwrap());
        assert_eq!(a.mask, 24);
        assert_eq!(a.broadcast, None);
    }

    #[test]
    fn an_address_item_without_an_ipaddr_is_refused() {
        let buf = table(&[("mask", "24")]);
        assert!(parse_addr_item(&one(&buf), false).is_none());
    }

    #[test]
    fn an_address_mask_wider_than_the_family_is_refused() {
        let buf = table(&[("ipaddr", "10.0.0.1"), ("mask", "33")]);
        assert!(parse_addr_item(&one(&buf), false).is_none());
    }

    #[test]
    fn an_optional_address_attribute_with_the_wrong_type_is_ignored() {
        let mut b = blob::BlobBuf::new();
        let c = b.msg_open_table("x");
        b.msg_string("ipaddr", "2001:db8::1");
        b.msg_u32("mask", 64);
        b.msg_close(c);
        let a = parse_addr_item(&one(b.payload()), true).unwrap();
        assert_eq!(a.mask, 128);
    }

    #[test]
    fn a_v6_address_keeps_its_class_and_lifetimes() {
        let mut b = blob::BlobBuf::new();
        let c = b.msg_open_table("x");
        b.msg_string("ipaddr", "2001:db8::1");
        b.msg_string("mask", "64");
        b.msg_string("class", "wan6");
        b.msg_u32("preferred", 100);
        b.msg_u32("valid", 200);
        b.msg_close(c);
        let buf = b.payload().to_vec();
        let a = parse_addr_item(&one(&buf), true).unwrap();
        assert_eq!(a.mask, 64);
        assert_eq!(a.class.as_deref(), Some("wan6"));
        assert_eq!((a.preferred, a.valid), (Some(100), Some(200)));
    }

    #[test]
    fn a_v6_address_preferred_beyond_valid_is_refused() {
        let mut b = blob::BlobBuf::new();
        let c = b.msg_open_table("x");
        b.msg_string("ipaddr", "2001:db8::1");
        b.msg_u32("preferred", 300);
        b.msg_u32("valid", 200);
        b.msg_close(c);
        let buf = b.payload().to_vec();
        assert!(parse_addr_item(&one(&buf), true).is_none());
    }

    #[test]
    fn a_route_item_carries_target_mask_gateway_and_source() {
        // exactly what dhcp.script sends for the default route
        let buf = table(&[
            ("target", "0.0.0.0"),
            ("netmask", "0"),
            ("gateway", "10.0.0.1"),
            ("source", "10.0.0.100"),
        ]);
        let r = parse_route_item(&one(&buf), false).unwrap();
        assert_eq!(r.target, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(r.mask, 0);
        assert_eq!(r.nexthop, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(r.source, "10.0.0.100".parse::<IpAddr>().unwrap());
        // no explicit mask on the source means a host route
        assert_eq!(r.sourcemask, 32);
        // no metric, table, type or proto was sent, so none is flagged
        assert_eq!(r.flags, 0);
        assert_eq!(r.metric, 0);
    }

    #[test]
    fn a_route_target_masks_out_its_host_bits() {
        let buf = table(&[("target", "10.1.2.3/24")]);
        let r = parse_route_item(&one(&buf), false).unwrap();
        assert_eq!(r.target, "10.1.2.0".parse::<IpAddr>().unwrap());
        assert_eq!(r.mask, 24);
    }

    #[test]
    fn a_disabled_route_is_dropped() {
        let mut b = blob::BlobBuf::new();
        let c = b.msg_open_table("x");
        b.msg_string("target", "10.0.0.0");
        b.msg_bool("disabled", true);
        b.msg_close(c);
        let buf = b.payload().to_vec();
        assert!(parse_route_item(&one(&buf), false).is_none());
    }

    #[test]
    fn the_main_table_is_not_flagged() {
        let buf = table(&[("target", "10.0.0.0"), ("netmask", "8"), ("table", "main")]);
        let r = parse_route_item(&one(&buf), false).unwrap();
        assert_eq!(r.table, 0);
        assert_eq!(r.flags & interface::devroute::TABLE, 0);
    }

    #[test]
    fn a_named_route_type_becomes_its_number_and_is_flagged() {
        let buf = table(&[("target", "10.0.0.0"), ("netmask", "8"), ("type", "unreachable")]);
        let r = parse_route_item(&one(&buf), false).unwrap();
        assert_eq!(r.ty, 7);
        assert_ne!(r.flags & interface::devroute::TYPE, 0);
    }

    #[test]
    fn a_non_table_entry_is_not_a_route_or_an_address() {
        let mut b = blob::BlobBuf::new();
        b.msg_string("x", "10.0.0.1");
        let buf = b.payload().to_vec();
        assert!(parse_route_item(&one(&buf), false).is_none());
        assert!(parse_addr_item(&one(&buf), false).is_none());
    }
}


/// One `ip6prefix` entry: a delegated prefix, pushed by `netifd-proto.sh` as a
/// plain string, `<prefix>/<length>[,<preferred>[,<valid>[,excluded=<p>/<l>]]]`.
/// `proto_add_ipv6_prefix` builds it from what odhcp6c reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix6 {
    pub addr: std::net::Ipv6Addr,
    pub length: u8,
    pub preferred: Option<u32>,
    pub valid: Option<u32>,
    pub excl: Option<(std::net::Ipv6Addr, u8)>,
}

/// Parse one such string. An entry this build cannot read is dropped rather
/// than guessed at -- a wrong prefix hands the LAN addresses that do not route.
pub fn parse_prefix6(text: &str) -> Option<Prefix6> {
    let mut parts = text.split(',');
    let net = parts.next()?.trim();
    let (a, l) = net.split_once('/')?;
    let addr: std::net::Ipv6Addr = a.trim().parse().ok()?;
    let length: u8 = l.trim().parse().ok()?;
    if length > 128 {
        return None;
    }
    let num = |p: Option<&str>| -> Option<u32> {
        let v = p?.trim();
        if v.is_empty() {
            return None;
        }
        v.parse().ok()
    };
    let mut out = Prefix6 { addr, length, preferred: None, valid: None, excl: None };
    let mut rest: Vec<&str> = parts.collect();
    // `excluded=` can be anywhere after the network, and `class=` is stripped
    // by the script before it gets here, so an unknown key is ignored rather
    // than eaten as a lifetime.
    rest.retain(|p| {
        if let Some(v) = p.trim().strip_prefix("excluded=") {
            if let Some((ea, el)) = v.split_once('/') {
                if let (Ok(ea), Ok(el)) = (ea.trim().parse(), el.trim().parse::<u8>()) {
                    if el <= 128 {
                        out.excl = Some((ea, el));
                    }
                }
            }
            return false;
        }
        !p.contains('=')
    });
    out.preferred = num(rest.first().copied());
    out.valid = num(rest.get(1).copied());
    Some(out)
}

#[cfg(test)]
mod prefix6_tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn the_plain_form_is_prefix_preferred_valid() {
        let p = parse_prefix6("2001:db8:1:2::/60,3600,7200").unwrap();
        assert_eq!(p.addr, "2001:db8:1:2::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(p.length, 60);
        assert_eq!(p.preferred, Some(3600));
        assert_eq!(p.valid, Some(7200));
        assert_eq!(p.excl, None);
    }

    #[test]
    fn the_lifetimes_are_optional() {
        let p = parse_prefix6("2001:db8::/48").unwrap();
        assert_eq!(p.length, 48);
        assert_eq!(p.preferred, None);
        assert_eq!(p.valid, None);
    }

    #[test]
    fn an_excluded_prefix_is_kept_and_does_not_shift_the_lifetimes() {
        let p = parse_prefix6("2001:db8:1::/48,600,1200,excluded=2001:db8:1:5::/64").unwrap();
        assert_eq!(p.preferred, Some(600));
        assert_eq!(p.valid, Some(1200));
        assert_eq!(p.excl, Some(("2001:db8:1:5::".parse().unwrap(), 64)));
    }

    #[test]
    fn rubbish_is_dropped_rather_than_guessed() {
        assert!(parse_prefix6("").is_none());
        assert!(parse_prefix6("2001:db8::").is_none(), "no length");
        assert!(parse_prefix6("not-an-address/64").is_none());
        assert!(parse_prefix6("2001:db8::/129").is_none());
    }
}

//! procd's triggers: rules from `service set`, matched against events, that
//! run `run_script` commands.
//!
//! Source of truth is `service/trigger.c`. Three things there are easy to
//! miss and all of them are observable:
//!
//! - `trigger_match` truncates the pattern at `.*` and prefix-compares. The
//!   dot is NOT part of the prefix -- `strncmp(event, match, wildcard - match)`
//!   with `match = "interface.*"` compares nine characters, so `interfaceX`
//!   matches too. There is no glob engine and no separator handling.
//! - `rule_handle_command` honours exactly one command name, `run_script`.
//!   Every other command the rule produces is silently dropped.
//! - commands are deduplicated by their whole expanded argv while pending,
//!   and run through a runqueue of width one, so two events that produce the
//!   same command coalesce into a single run.

use std::collections::BTreeMap;

use owrt_ubus::blob::{Field, MsgType};

use crate::jsonscript;

/// One `[type, script, timeout?]` triple from a service's `triggers` array.
/// Who a rule belongs to. `trigger_del` takes one of these, not a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    Service(String),
    Instance(String, String),
}

impl Owner {
    /// Every rule that dies with a service: its own, and its instances'.
    fn belongs_to_service(&self, svc: &str) -> bool {
        match self {
            Owner::Service(s) => s == svc,
            Owner::Instance(s, _) => s == svc,
        }
    }
}

pub struct Trigger {
    pub kind: String,
    /// The script array, kept encoded so it can be re-walked per event.
    pub script: Vec<u8>,
    pub timeout_ms: i32,
    /// Which object registered it. The C keys trigger_del on the `id`
    /// pointer -- a service or an instance -- so a service's rules and its
    /// instances' rules are released independently.
    pub owner: Owner,
}

/// A command waiting to run. Keyed by its argv, which is how the C's
/// `trigger_pending` avl tree deduplicates.
pub struct Pending {
    pub argv: Vec<String>,
    /// Monotonic ms at which it should start.
    pub due: i64,
    /// Set when an identical command arrives while this one is running.
    pub requeue: bool,
    /// Live child, once started.
    pub pid: Option<i32>,
    /// The child has been reaped by the main loop's waitpid and this entry
    /// is waiting to be requeued or dropped.
    pub finished: bool,
}

impl std::fmt::Debug for Trigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trigger")
            .field("kind", &self.kind)
            .field("timeout_ms", &self.timeout_ms)
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("argument_count", &self.argv.len())
            .field("due", &self.due)
            .field("requeue", &self.requeue)
            .field("pid", &self.pid)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub struct Triggers {
    pub list: Vec<Trigger>,
    pub pending: Vec<Pending>,
}

/// `trigger_match()`. A `.*` anywhere in the pattern truncates it there and
/// turns the comparison into a prefix test on what came before -- the dot is
/// dropped with the star. Otherwise it is exact equality.
pub fn matches(event: &str, pattern: &str) -> bool {
    match pattern.find(".*") {
        Some(at) => event.starts_with(&pattern[..at]),
        None => event == pattern,
    }
}

impl Triggers {
    /// `trigger_add()`. Entries that are not arrays, or whose first two
    /// elements are not a string and an array, are skipped without comment --
    /// the C's switch simply leaves `type` or `script` null.
    pub fn add(&mut self, rule: Field<'_>, owner: Owner) {
        for cur in rule.children() {
            if cur.ty != MsgType::Array as u32 {
                continue;
            }
            let mut kind: Option<String> = None;
            let mut script: Option<Vec<u8>> = None;
            let mut timeout: i32 = 0;
            for (i, e) in cur.children().enumerate() {
                match i {
                    0 => kind = e.as_str().map(str::to_string),
                    1 => {
                        if e.ty == MsgType::Array as u32 {
                            script = Some(e.data.to_vec());
                        }
                    }
                    2 if e.ty == MsgType::Int32 as u32 => {
                        timeout = e.as_u32().unwrap_or(0) as i32;
                    }
                    _ => {}
                }
            }
            if let (Some(kind), Some(script)) = (kind, script) {
                self.list.push(Trigger {
                    kind,
                    script,
                    timeout_ms: timeout,
                    owner: owner.clone(),
                });
            }
        }
    }

    /// `trigger_del(id)` for one exact owner.
    pub fn del(&mut self, owner: &Owner) {
        self.list.retain(|t| &t.owner != owner);
    }

    /// Everything that dies when a service is released: its own rules and
    /// all of its instances'. The C reaches this through service_delete ->
    /// trigger_del(s) plus each instance_free -> trigger_del(in).
    pub fn del_service(&mut self, svc: &str) {
        self.list.retain(|t| !t.owner.belongs_to_service(svc));
    }

    /// `trigger_event()`: run every matching trigger's script with the event
    /// data as variables, and queue the `run_script` commands it produced.
    pub fn fire(&mut self, event: &str, vars: &BTreeMap<String, String>, now: i64) {
        let mut queued: Vec<(Vec<String>, i32)> = Vec::new();
        for t in self.list.iter() {
            if !matches(event, &t.kind) {
                continue;
            }
            // The stored script payload is an array body; wrap it back into a
            // Field so the engine sees the same shape json_script_run does.
            let block = Field {
                name: "",
                ty: MsgType::Array as u32,
                data: &t.script,
            };
            // json_script_run(&t->jctx, t->type, data): the rule is loaded
            // under its own type name, which is what `include` can reach.
            let out = jsonscript::run_rule(block, vars, Some(&t.kind));
            for (name, args) in out.commands {
                // rule_handle_command honours run_script and nothing else.
                if name == "run_script" {
                    queued.push((args, t.timeout_ms));
                }
            }
            for e in out.errors {
                // rule_handle_error()
                log!(crate::sys::LOG_ERR, "ERROR: {e} (trigger {})", t.kind);
            }
        }
        for (argv, timeout) in queued {
            self.queue(argv, timeout, now);
        }
    }

    /// `trigger_command_add()`. A pending copy has its timer extended, never
    /// shortened; a running copy is marked for one requeue; otherwise a new
    /// entry is created with a delay of at least 1 ms.
    fn queue(&mut self, argv: Vec<String>, timeout_ms: i32, now: i64) {
        if let Some(cmd) = self.pending.iter_mut().find(|c| c.argv == argv) {
            // The C tests `!cmd->delay.pending`, which is true for a command
            // that is RUNNING *and* for one whose delay already elapsed and
            // is queued behind another task. Only a delay still counting
            // down gets extended. Treating "queued but not yet running" as
            // still-pending drops the second trigger entirely.
            if cmd.pid.is_some() || now >= cmd.due {
                cmd.requeue = true;
                return;
            }
            let want = now + timeout_ms as i64;
            if cmd.due < want {
                cmd.due = want;
            }
            return;
        }
        let delay = if timeout_ms > 0 { timeout_ms as i64 } else { 1 };
        self.pending.push(Pending {
            argv,
            due: now + delay,
            requeue: false,
            pid: None,
            finished: false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_debug_does_not_disclose_script_or_expanded_arguments() {
        let secret = "trigger-secret-marker";
        let mut triggers = Triggers::default();
        triggers.list.push(Trigger {
            kind: "event".into(),
            script: secret.as_bytes().to_vec(),
            timeout_ms: 1,
            owner: Owner::Service("svc".into()),
        });
        triggers.queue(vec!["/bin/script".into(), secret.into()], 1, 0);
        let encoded = format!("{:?}", secret.as_bytes());
        for debug in [format!("{triggers:?}"), format!("{triggers:#?}")] {
            assert!(!debug.contains(secret));
            assert!(!debug.contains(&encoded));
        }
        assert_eq!(triggers.pending[0].argv[1], secret);
    }


    #[test]
    fn a_dot_star_suffix_is_a_prefix_match_and_nothing_else() {
        assert!(matches("interface.up", "interface.*"));
        assert!(matches("interface.", "interface.*"));
        // strncmp compares only what precedes ".*", so the dot is not part
        // of the prefix and an event with no separator matches as well.
        // This assertion was originally the other way round and the test
        // caught it.
        assert!(matches("interfaceX", "interface.*"));
        assert!(!matches("interfac", "interface.*"));
        // Without a wildcard it is exact.
        assert!(matches("config.change", "config.change"));
        assert!(!matches("config.changed", "config.change"));
    }

    #[test]
    fn an_identical_pending_command_extends_but_never_shortens() {
        let mut t = Triggers::default();
        t.queue(vec!["a".into()], 5000, 0);
        assert_eq!(t.pending.len(), 1);
        assert_eq!(t.pending[0].due, 5000);
        // A shorter timeout must not pull the deadline in.
        t.queue(vec!["a".into()], 100, 0);
        assert_eq!(t.pending.len(), 1);
        assert_eq!(t.pending[0].due, 5000);
        // A longer one pushes it out.
        t.queue(vec!["a".into()], 9000, 0);
        assert_eq!(t.pending[0].due, 9000);
    }

    #[test]
    fn a_queued_command_whose_delay_elapsed_is_also_requeued() {
        let mut t = Triggers::default();
        // Delay 0 -> due at now+1, so at now+5 it has elapsed but has not
        // been given a slot yet (no pid).
        t.queue(vec!["a".into()], 0, 0);
        assert!(t.pending[0].pid.is_none());
        t.queue(vec!["a".into()], 0, 5);
        assert_eq!(t.pending.len(), 1);
        assert!(
            t.pending[0].requeue,
            "an elapsed-but-unstarted command must requeue, not be swallowed"
        );
    }

    #[test]
    fn a_running_command_is_requeued_once_rather_than_duplicated() {
        let mut t = Triggers::default();
        t.queue(vec!["a".into()], 0, 0);
        t.pending[0].pid = Some(1234);
        t.queue(vec!["a".into()], 0, 0);
        assert_eq!(t.pending.len(), 1);
        assert!(t.pending[0].requeue);
    }

    #[test]
    fn a_zero_timeout_still_gets_a_one_millisecond_delay() {
        let mut t = Triggers::default();
        t.queue(vec!["a".into()], 0, 100);
        assert_eq!(t.pending[0].due, 101);
    }
}

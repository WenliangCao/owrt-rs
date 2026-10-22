//! A service: a named set of instances plus the trigger, validate and data
//! declarations that came with them.
//!
//! Source of truth is procd's `service/service.c` at the pinned revision.
//! The vlist update semantics matter and are not obvious: `set` replaces the
//! instance set (update/flush), `add` merges into it, and `s->instances`
//! carries `no_delete = true`, so a flushed instance is stopped rather than
//! dropped -- it disappears only once its child has actually reaped.

use std::collections::BTreeMap;

use owrt_ubus::blob::{BlobBuf, MsgType};

use crate::instance::{Instance, Run};

/// `service_handle_list()`: the optional name is an exact map key. Field
/// parsing keeps the original last-field-wins behaviour, including a later
/// invalid name clearing an earlier filter.
pub fn dump_list(services: &BTreeMap<String, Service>, data: &[u8], b: &mut BlobBuf) {
    let mut verbose = false;
    let mut only = None;
    for f in owrt_ubus::blob::fields(data) {
        match f.name {
            "verbose" => verbose = f.as_bool().unwrap_or(false),
            "name" => only = f.as_str(),
            _ => {}
        }
    }
    if let Some(name) = only {
        if let Some(service) = services.get(name) {
            service.dump(b, verbose);
        }
    } else {
        for service in services.values() {
            service.dump(b, verbose);
        }
    }
}

/// What `service_instance_update` decides for one name in the vlist diff.
/// One `validate` entry: a uci package and section type plus the option
/// rules for it. `service_validate_add()` drops any entry missing one of
/// package, type or data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    pub package: String,
    pub kind: String,
    /// Registration order. The C keeps every validator in one global avl
    /// keyed by package with duplicates allowed, so a walk yields packages in
    /// strcmp order and, within one package, in insertion order. Sorting by
    /// (package, seq) reproduces that walk without a second tree.
    pub seq: u64,
    /// option -> rule. BTreeMap because the C keeps them in an avl tree
    /// ordered by option name, and `validate` prints them in that order.
    pub rules: BTreeMap<String, String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstanceChange {
    /// Present on both sides: keep the running child, move the config on,
    /// and restart only if the config actually changed.
    Update,
    /// Gone from the new set: stop it, with halt.
    Stop,
    /// New: start it, but only if the service has autostart.
    Start,
}

pub struct Service {
    pub name: String,
    /// `instances`, keyed by instance name. BTreeMap because the C's vlist is
    /// an avl tree ordered by `avl_strcmp`, and `list` walks it in order.
    pub instances: BTreeMap<String, Instance>,
    pub autostart: bool,
    /// `triggers` verbatim; the rule engine reads it.
    pub trigger: Option<Vec<u8>>,
    /// `validate` entries, parsed.
    pub validate: Vec<Validator>,
    /// `data`, keeping each field's blobmsg type and payload for the same
    /// reason as the instance's: `blobmsg_add_blob` re-emits the original
    /// type, so flattening to strings drops non-string fields. A change here
    /// fires `service.data.update`.
    pub data: BTreeMap<String, (u32, Vec<u8>)>,
    /// Set by `service_delete`; the service is gone once every instance has
    /// stopped (`service_stopped`).
    pub deleted: bool,
    /// `update_start` seen, waiting for `update_complete`.
    pub update_pending: bool,
}

// The ubus data/trigger payloads may contain application credentials. Debug
// retains the service lifecycle and redacted instance summaries only.
impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("name", &self.name)
            .field("instances", &self.instances)
            .field("autostart", &self.autostart)
            .field("deleted", &self.deleted)
            .field("update_pending", &self.update_pending)
            .field("data_count", &self.data.len())
            .finish_non_exhaustive()
    }
}

impl Service {
    /// `service_alloc()`. A freshly allocated service autostarts; `set`
    /// overrides it only when the caller passed `autostart` explicitly.
    pub fn new(name: &str) -> Self {
        Service {
            name: name.to_string(),
            instances: BTreeMap::new(),
            autostart: true,
            trigger: None,
            validate: Vec::new(),
            data: BTreeMap::new(),
            deleted: false,
            update_pending: false,
        }
    }

    /// `service_stopped()`: a deleted service stays around until nothing of
    /// it is still running.
    pub fn can_be_freed(&self) -> bool {
        self.deleted && self.instances.values().all(|i| i.state == Run::Stopped)
    }

    /// The vlist diff `set` performs: old names not in `fresh` stop, shared
    /// names update, new names start.
    pub fn plan(&self, fresh: &BTreeMap<String, Instance>) -> Vec<(String, InstanceChange)> {
        let mut out = Vec::new();
        for name in self.instances.keys() {
            if fresh.contains_key(name) {
                out.push((name.clone(), InstanceChange::Update));
            } else {
                out.push((name.clone(), InstanceChange::Stop));
            }
        }
        for name in fresh.keys() {
            if !self.instances.contains_key(name) {
                out.push((name.clone(), InstanceChange::Start));
            }
        }
        out
    }

    /// `service_dump()`. Field order matters: `ubus call service list` output
    /// is compared against the C's byte for byte.
    pub fn dump(&self, b: &mut BlobBuf, verbose: bool) {
        let s = b.msg_open_table(&self.name);
        // autostart appears ONLY when it is false; the default is silent.
        if !self.autostart {
            b.msg_bool("autostart", false);
        }
        if !self.data.is_empty() {
            let d = b.msg_open_table("data");
            for (k, (ty, payload)) in &self.data {
                b.msg_field(*ty, k, payload);
            }
            b.msg_close(d);
        }
        if !self.instances.is_empty() {
            let i = b.msg_open_table("instances");
            for inst in self.instances.values() {
                inst.dump(b, verbose);
            }
            b.msg_close(i);
        }
        if verbose {
            // blobmsg_add_blob() re-emits the stored attr with its own name,
            // so the array is not re-wrapped here either.
            if let Some(t) = &self.trigger {
                b.msg_field(MsgType::Array as u32, "triggers", t);
            }
            if !self.validate.is_empty() {
                // service_validate_dump(): an array of tables, each named
                // "validate" -- the name is repeated inside an array, which
                // libubox permits and `ubus` prints as a plain list.
                let a = b.msg_open_array("validate");
                // `list_add` prepends, so the per-service list walks in
                // REVERSE declaration order -- the opposite of the grouping
                // that `service validate` prints.
                for v in self.validate.iter().rev() {
                    let j = b.msg_open_table("validate");
                    b.msg_string("package", &v.package);
                    b.msg_string("type", &v.kind);
                    let k = b.msg_open_table("rules");
                    for (opt, rule) in &v.rules {
                        b.msg_string(opt, rule);
                    }
                    b.msg_close(k);
                    b.msg_close(j);
                }
                b.msg_close(a);
            }
        }
        b.msg_close(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_debug_omits_opaque_data_and_triggers() {
        let secret = b"service-secret-marker";
        let mut service = Service::new("svc");
        service.data.insert("opaque".into(), (3, secret.to_vec()));
        service.trigger = Some(secret.to_vec());
        let debug = format!("{service:?}");
        assert!(!debug.contains(&format!("{secret:?}")));
        assert!(!debug.contains("trigger"));
        assert_eq!(service.trigger.as_deref(), Some(secret.as_slice()));
    }

    #[test]
    fn filtered_lists_keep_order_last_field_rules_and_current_services() {
        let mut services = BTreeMap::new();
        services.insert("z".into(), Service::new("z"));
        services.insert("a".into(), Service::new("a"));
        let mut request = BlobBuf::new();
        let mut reply = BlobBuf::new();
        let names = |b: &BlobBuf| {
            owrt_ubus::blob::fields(b.payload())
                .map(|f| f.name.to_owned())
                .collect::<Vec<_>>()
        };
        dump_list(&services, request.payload(), &mut reply);
        assert_eq!(names(&reply), ["a", "z"]);
        request.msg_string("name", "z");
        reply.reset_bounded(16 * 1024);
        dump_list(&services, request.payload(), &mut reply);
        assert_eq!(names(&reply), ["z"]);
        services.remove("z");
        reply.reset_bounded(16 * 1024);
        dump_list(&services, request.payload(), &mut reply);
        assert!(
            reply.payload().is_empty(),
            "deleted service is visible immediately"
        );
        request.msg_u32("name", 0);
        reply.reset_bounded(16 * 1024);
        dump_list(&services, request.payload(), &mut reply);
        assert_eq!(names(&reply), ["a"], "invalid later name clears the filter");
        request.msg_string("name", "");
        reply.reset_bounded(16 * 1024);
        dump_list(&services, request.payload(), &mut reply);
        assert!(
            reply.payload().is_empty(),
            "an empty name is still an exact filter"
        );
    }

    fn inst(name: &str) -> Instance {
        let mut i = Instance::new(name);
        i.valid = true;
        i.command = vec!["/bin/true".into()];
        i
    }

    #[test]
    fn a_replaced_instance_set_stops_what_is_gone_and_starts_what_is_new() {
        let mut s = Service::new("svc");
        s.instances.insert("a".into(), inst("a"));
        s.instances.insert("b".into(), inst("b"));

        let mut fresh = BTreeMap::new();
        fresh.insert("b".to_string(), inst("b"));
        fresh.insert("c".to_string(), inst("c"));

        let plan = s.plan(&fresh);
        assert_eq!(
            plan,
            vec![
                ("a".to_string(), InstanceChange::Stop),
                ("b".to_string(), InstanceChange::Update),
                ("c".to_string(), InstanceChange::Start),
            ]
        );
    }

    #[test]
    fn a_deleted_service_survives_until_its_children_reap() {
        let mut s = Service::new("svc");
        let mut i = inst("a");
        i.state = Run::Running;
        s.instances.insert("a".into(), i);
        s.deleted = true;
        assert!(!s.can_be_freed());
        s.instances.get_mut("a").unwrap().state = Run::Stopped;
        assert!(s.can_be_freed());
    }
}

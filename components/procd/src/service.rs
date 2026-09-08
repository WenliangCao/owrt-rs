//! A service: a named set of instances plus the trigger, validate and data
//! declarations that came with them.
//!
//! Source of truth is procd's `service/service.c` at the pinned revision.
//! The vlist update semantics matter and are not obvious: `set` replaces the
//! instance set (update/flush), `add` merges into it, and `s->instances`
//! carries `no_delete = true`, so a flushed instance is stopped rather than
//! dropped -- it disappears only once its child has actually reaped.

use std::collections::BTreeMap;

use owrt_ubus::blob::BlobBuf;

use crate::instance::{Instance, Run};

/// What `service_instance_update` decides for one name in the vlist diff.
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

#[derive(Debug)]
pub struct Service {
    pub name: String,
    /// `instances`, keyed by instance name. BTreeMap because the C's vlist is
    /// an avl tree ordered by `avl_strcmp`, and `list` walks it in order.
    pub instances: BTreeMap<String, Instance>,
    pub autostart: bool,
    /// `triggers` verbatim; the rule engine reads it.
    pub trigger: Option<Vec<u8>>,
    /// `validate` entries, verbatim.
    pub validate: Vec<Vec<u8>>,
    /// `data` table, flattened. A change here fires `service.data.update`.
    pub data: BTreeMap<String, String>,
    /// Set by `service_delete`; the service is gone once every instance has
    /// stopped (`service_stopped`).
    pub deleted: bool,
    /// `update_start` seen, waiting for `update_complete`.
    pub update_pending: bool,
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
        self.deleted
            && self
                .instances
                .values()
                .all(|i| i.state == Run::Stopped)
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
        if !self.instances.is_empty() {
            let i = b.msg_open_table("instances");
            for inst in self.instances.values() {
                inst.dump(b, verbose);
            }
            b.msg_close(i);
        }
        if !self.data.is_empty() {
            let d = b.msg_open_table("data");
            for (k, v) in &self.data {
                b.msg_string(k, v);
            }
            b.msg_close(d);
        }
        if let Some(t) = &self.trigger {
            if verbose {
                let a = b.msg_open_array("triggers");
                b.put_raw_fields(t);
                b.msg_close(a);
            }
        }
        if verbose && !self.validate.is_empty() {
            let a = b.msg_open_array("validate");
            for v in &self.validate {
                b.put_raw_fields(v);
            }
            b.msg_close(a);
        }
        b.msg_close(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

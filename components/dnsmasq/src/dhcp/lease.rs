//! IPv4 lease ownership, identity and expiry. Reference: lease.c:621-702,
//! 846-936,948-1008,1062-1170. Network policy belongs to rfc2131, not this store.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Write};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentity {
    /// C stores an int here; lease files may contain a wider type than the
    /// on-wire u8 htype. Preserve its 32-bit bit pattern for matching/output.
    pub hardware_type: u32,
    pub hardware_address: Vec<u8>,
    pub client_id: Option<Vec<u8>>,
}

impl ClientIdentity {
    pub fn valid(&self) -> bool {
        self.hardware_address.len() <= 16
            && (self.hardware_type != 0 || self.hardware_address.is_empty())
            && self
                .client_id
                .as_ref()
                .is_none_or(|v| !v.is_empty() && v.len() <= 255)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub file: bool,
    pub dns: bool,
}

/// Public u32 counter windows from lease.c, cumulative for the store lifetime.
/// These count successful operations, including startup restoration, rather
/// than active leases. Even NO_DHCP6 counts pruning 0.0.0.0 in the IPv6 slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeaseCounters {
    pub allocated4: u32,
    pub pruned4: u32,
    pub pruned6: u32,
}

#[derive(Clone, Debug)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub identity: ClientIdentity,
    /// None is the on-disk/C expiry sentinel 0 (infinite lease).
    pub expires: Option<i64>,
    pub hostname: Option<Vec<u8>>,
    pub fqdn: Option<Vec<u8>>,
    pub authoritative_name: bool,
    pub interface: u32,
    pub agent_id: Option<Vec<u8>>,
    pub vendor_class: Option<Vec<u8>>,
    pub server_override: Option<Ipv4Addr>,
    /// Lease-local helper snapshot; transient extradata is consumed on add/old.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub helper_context: Option<Box<crate::helper::LeaseEventContext>>,
    sequence: u64,
    old_hostname: Option<Vec<u8>>,
    script: ScriptFlags,
}

/// Stable lease identity. Recovery can hold several records for one address;
/// callers must retain this key when a client lookup selected a particular one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeaseId {
    address: Ipv4Addr,
    sequence: u64,
}

impl LeaseId {
    pub fn address(self) -> Ipv4Addr {
        self.address
    }
}

impl Lease {
    pub fn id(&self) -> LeaseId {
        LeaseId {
            address: self.address,
            sequence: self.sequence,
        }
    }

    /// Name currently published for this lease, in the same FQDN-first order
    /// used by script events and DNS removal.  A pruned lease remains owned by
    /// the caller long enough to derive a name-loss notification.
    pub fn published_name(&self) -> Option<&[u8]> {
        self.fqdn.as_deref().or(self.hostname.as_deref())
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ScriptFlags {
    new: bool,
    changed: bool,
    auxiliary: bool,
    expiry: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptAction {
    Add,
    Old,
    Delete,
    OldHostname,
}

#[derive(Clone, Debug)]
pub struct ScriptEvent {
    pub action: ScriptAction,
    pub lease: Lease,
    pub name: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ScriptOptions {
    pub lease_file_read_only: bool,
    pub notify_renewals: bool,
}

/// Owns deleted leases until their old-name and delete events have been
/// delivered. No process is launched here; helper/hotplug execution consumes
/// these events. Ownership models lease.c:621-648,1224-1317 explicitly.
#[derive(Default)]
pub struct ScriptQueue {
    deleted: VecDeque<Lease>,
}

impl ScriptQueue {
    pub fn add_pruned(&mut self, leases: Vec<Lease>) {
        // Each prune batch precedes older pending batches, matching the C stack.
        for lease in leases.into_iter().rev() {
            self.deleted.push_front(lease);
        }
    }

    pub fn pending_deletions(&self) -> usize {
        self.deleted.len()
    }

    pub fn next(&mut self, store: &mut LeaseStore, options: ScriptOptions) -> Option<ScriptEvent> {
        if let Some(lease) = self.deleted.front_mut() {
            if let Some(name) = lease.old_hostname.take() {
                return Some(ScriptEvent {
                    action: ScriptAction::OldHostname,
                    lease: lease.clone(),
                    name: Some(name),
                });
            }
            let lease = self.deleted.pop_front()?;
            let name = lease.fqdn.clone().or_else(|| lease.hostname.clone());
            return Some(ScriptEvent {
                action: ScriptAction::Delete,
                lease,
                name,
            });
        }
        let old_name = store
            .leases
            .values()
            .filter(|lease| lease.old_hostname.is_some())
            .max_by_key(|lease| lease.sequence)
            .map(Lease::id);
        if let Some(id) = old_name {
            let lease = store.leases.get_mut(&id)?;
            let name = lease.old_hostname.take();
            return Some(ScriptEvent {
                action: ScriptAction::OldHostname,
                lease: lease.clone(),
                name,
            });
        }
        let changed = store
            .leases
            .values()
            .filter(|lease| {
                lease.script.new
                    || lease.script.changed
                    || (lease.script.auxiliary && options.lease_file_read_only)
                    || (lease.script.expiry && options.notify_renewals)
            })
            .max_by_key(|lease| lease.sequence)
            .map(Lease::id)?;
        let lease = store.leases.get_mut(&changed)?;
        let action = if lease.script.new {
            ScriptAction::Add
        } else {
            ScriptAction::Old
        };
        lease.script = ScriptFlags::default();
        let event = ScriptEvent {
            action,
            name: lease.fqdn.clone().or_else(|| lease.hostname.clone()),
            lease: lease.clone(),
        };
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(context) = lease.helper_context.as_mut() {
            context.extra = None;
        }
        Some(event)
    }
}

/// A lease mutation failed validation, capacity, lookup or identity allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseError {
    Full,
    AddressInUse,
    NotFound,
    InvalidIdentity,
    SequenceExhausted,
}

/// Startup lease restoration failed; earlier restored records remain in the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreError {
    NonemptyStore,
    Lease(LeaseError),
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Full => "lease capacity exhausted",
            Self::AddressInUse => "lease address is already in use",
            Self::NotFound => "lease not found",
            Self::InvalidIdentity => "invalid lease client identity",
            Self::SequenceExhausted => "lease identity sequence exhausted",
        })
    }
}

impl std::error::Error for LeaseError {}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonemptyStore => {
                formatter.write_str("cannot restore into a nonempty lease store")
            }
            Self::Lease(error) => write!(formatter, "cannot restore lease: {error}"),
        }
    }
}

impl std::error::Error for RestoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NonemptyStore => None,
            Self::Lease(error) => Some(error),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameLost {
    pub address: Ipv4Addr,
    pub name: Vec<u8>,
}

/// Address/expiry indexes avoid the C full-list scans for every address lookup,
/// prune and next-alarm calculation. Each finite active lease has exactly one
/// expiry entry: renewal removes the old key (no stale-timer heap growth).
/// Client lookup retains newest-first C behavior, including duplicate IDs.
pub struct LeaseStore {
    leases: BTreeMap<LeaseId, Lease>,
    expiry: BTreeSet<(i64, LeaseId)>,
    capacity: usize,
    allocation_budget: usize,
    sequence: u64,
    changes: Changes,
    counters: LeaseCounters,
}

impl LeaseStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            leases: BTreeMap::new(),
            expiry: BTreeSet::new(),
            capacity,
            allocation_budget: usize::MAX,
            sequence: 0,
            changes: Changes::default(),
            counters: LeaseCounters::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.leases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    /// Reserve space for undelivered deletions before one packet transaction.
    /// Pruning during that transaction must not return a credit: the removed
    /// record still needs its helper callback. Renewals do not spend credits.
    pub(super) fn set_script_backlog(&mut self, pending: Option<usize>) {
        self.allocation_budget = pending.map_or(usize::MAX, |pending| {
            self.capacity
                .saturating_mul(2)
                .max(64)
                .saturating_sub(self.len())
                .saturating_sub(pending)
        });
    }

    fn key(&self, address: Ipv4Addr) -> Option<LeaseId> {
        self.leases
            .range(
                LeaseId {
                    address,
                    sequence: 0,
                }..=LeaseId {
                    address,
                    sequence: u64::MAX,
                },
            )
            .next_back()
            .map(|(&id, _)| id)
    }

    /// Address lookup returns the newest matching lease, like lease_find_by_addr.
    pub fn get(&self, address: Ipv4Addr) -> Option<&Lease> {
        self.get_by_id(self.key(address)?)
    }

    pub fn get_by_id(&self, id: LeaseId) -> Option<&Lease> {
        self.leases.get(&id)
    }

    pub fn greatest_address(&self, start: Ipv4Addr, end: Ipv4Addr) -> Option<Ipv4Addr> {
        if start > end {
            return None;
        }
        self.leases
            .range(
                LeaseId {
                    address: start,
                    sequence: 0,
                }..=LeaseId {
                    address: end,
                    sequence: u64::MAX,
                },
            )
            .next_back()
            .map(|(&id, _)| id.address)
    }

    pub fn changes(&self) -> Changes {
        self.changes
    }

    pub fn counters(&self) -> LeaseCounters {
        self.counters
    }

    /// Convert removed leases into DNS/name deletion notifications while the
    /// lease records still retain their old FQDN/hostname bytes.
    pub fn names_lost(leases: &[Lease]) -> Vec<NameLost> {
        leases
            .iter()
            .filter_map(|lease| {
                lease.published_name().map(|name| NameLost {
                    address: lease.address,
                    name: name.to_vec(),
                })
            })
            .collect()
    }

    /// A failed file write must not call this; callers retain the dirty flag
    /// until the durable write succeeds (lease.c:413-420).
    pub fn file_written(&mut self) {
        self.changes.file = false;
    }

    pub fn dns_updated(&mut self) {
        self.changes.dns = false;
    }

    pub(super) fn dns_update_pending(&mut self) {
        self.changes.dns = true;
    }

    pub fn next_expiry(&self) -> Option<i64> {
        let &(time, _) = self.expiry.first()?;
        if time >= 0 {
            return Some(time);
        }
        // Corrupt/overflowed stored timestamps can straddle the signed-long
        // boundary. Match C's newest-first difftime reduction in that case.
        let mut next = None;
        for lease in self.active_newest_first() {
            if let Some(expiry) = lease.expires {
                if next.is_none_or(|next: i64| next.wrapping_sub(expiry) > 0) {
                    next = Some(expiry);
                }
            }
        }
        next
    }

    /// CLID wins independently of hardware. Hardware fallback is allowed only
    /// when at least one side has no CLID, and never for a zero-length address.
    pub fn find_client(&self, identity: &ClientIdentity) -> Option<&Lease> {
        if let Some(clid) = &identity.client_id {
            if let Some(lease) = self
                .leases
                .values()
                .filter(|lease| lease.identity.client_id.as_ref() == Some(clid))
                .max_by_key(|lease| lease.sequence)
            {
                return Some(lease);
            }
        }
        self.leases
            .values()
            .filter(|lease| {
                (lease.identity.client_id.is_none() || identity.client_id.is_none())
                    && !identity.hardware_address.is_empty()
                    && identity.hardware_type == lease.identity.hardware_type
                    && identity.hardware_address == lease.identity.hardware_address
            })
            .max_by_key(|lease| lease.sequence)
    }

    pub fn allocate(
        &mut self,
        address: Ipv4Addr,
        identity: ClientIdentity,
    ) -> Result<(), LeaseError> {
        if !identity.valid() {
            return Err(LeaseError::InvalidIdentity);
        }
        if self.get(address).is_some() {
            return Err(LeaseError::AddressInUse);
        }
        self.allocate_record(address, identity)
    }

    fn allocate_record(
        &mut self,
        address: Ipv4Addr,
        identity: ClientIdentity,
    ) -> Result<(), LeaseError> {
        if self.leases.len() >= self.capacity || self.allocation_budget == 0 {
            return Err(LeaseError::Full);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(LeaseError::SequenceExhausted)?;
        self.sequence = sequence;
        self.allocation_budget -= 1;
        let id = LeaseId { address, sequence };
        self.leases.insert(
            id,
            Lease {
                address,
                identity,
                expires: Some(1),
                hostname: None,
                fqdn: None,
                authoritative_name: false,
                interface: 0,
                agent_id: None,
                vendor_class: None,
                server_override: None,
                #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
                helper_context: None,
                sequence,
                old_hostname: None,
                script: ScriptFlags {
                    new: true,
                    ..ScriptFlags::default()
                },
            },
        );
        self.expiry.insert((1, id));
        self.changes.file = true;
        self.counters.allocated4 = self.counters.allocated4.wrapping_add(1);
        Ok(())
    }

    pub fn set_identity(
        &mut self,
        address: Ipv4Addr,
        identity: &ClientIdentity,
    ) -> Result<(), LeaseError> {
        let id = self.key(address).ok_or(LeaseError::NotFound)?;
        self.set_identity_by_id(id, identity)
    }

    pub fn set_identity_by_id(
        &mut self,
        id: LeaseId,
        identity: &ClientIdentity,
    ) -> Result<(), LeaseError> {
        if !identity.valid() {
            return Err(LeaseError::InvalidIdentity);
        }
        let lease = self.leases.get_mut(&id).ok_or(LeaseError::NotFound)?;
        let old = &mut lease.identity;
        if old.hardware_type != identity.hardware_type
            || old.hardware_address != identity.hardware_address
        {
            old.hardware_type = identity.hardware_type;
            old.hardware_address.clone_from(&identity.hardware_address);
            lease.script.changed = true;
            self.changes.file = true;
        }
        // Missing CLID on renewal must not erase a previously stored one.
        if identity.client_id.is_some() && old.client_id != identity.client_id {
            old.client_id.clone_from(&identity.client_id);
            lease.script.auxiliary = true;
            self.changes.file = true;
        }
        Ok(())
    }

    pub fn set_expires(
        &mut self,
        address: Ipv4Addr,
        length: u32,
        now: i64,
    ) -> Result<(), LeaseError> {
        let id = self.key(address).ok_or(LeaseError::NotFound)?;
        self.set_expires_by_id(id, length, now)
    }

    pub fn set_expires_by_id(
        &mut self,
        id: LeaseId,
        length: u32,
        now: i64,
    ) -> Result<(), LeaseError> {
        self.set_expires_at(id, expiry_time(length, now))
    }

    fn set_expires_at(&mut self, id: LeaseId, expiry: Option<i64>) -> Result<(), LeaseError> {
        let lease = self.leases.get_mut(&id).ok_or(LeaseError::NotFound)?;
        if expiry != lease.expires {
            if let Some(old) = lease.expires {
                self.expiry.remove(&(old, id));
            }
            if let Some(new) = expiry {
                self.expiry.insert((new, id));
            }
            lease.expires = expiry;
            lease.script.auxiliary = true;
            lease.script.expiry = true;
            self.changes.file = true;
            self.changes.dns = true;
        }
        Ok(())
    }

    /// Restore parsed records before serving traffic. C also treats capacity
    /// exhaustion as startup-fatal. Duplicate addresses retain independent
    /// identities, expiries and helper state; names and hardware types preserve
    /// their original byte/32-bit representation without lossy conversion.
    pub fn restore(
        &mut self,
        records: Vec<super::lease_file::LeaseRecord>,
        now: i64,
    ) -> Result<Vec<Lease>, RestoreError> {
        self.restore_with_name_policy(records, now, false)
    }

    /// Restore with C's configured collision scope. FQDNs are calculated
    /// later, so fqdn-only restoration does not discard equal short names.
    pub fn restore_with_name_policy(
        &mut self,
        records: Vec<super::lease_file::LeaseRecord>,
        now: i64,
        fqdn_only: bool,
    ) -> Result<Vec<Lease>, RestoreError> {
        if !self.is_empty() {
            return Err(RestoreError::NonemptyStore);
        }
        for record in records {
            let identity = ClientIdentity {
                hardware_type: record.hardware_type,
                hardware_address: record.hardware_address,
                client_id: record.client_id,
            };
            self.allocate_record(record.address, identity)
                .map_err(RestoreError::Lease)?;
            let id = self
                .key(record.address)
                .ok_or(RestoreError::Lease(LeaseError::NotFound))?;
            self.set_expires_at(id, (record.expires != 0).then_some(record.expires))
                .map_err(RestoreError::Lease)?;
            if let Some(hostname) = record.hostname {
                self.set_hostname(record.address, Some(&hostname), false, None, fqdn_only)
                    .map_err(RestoreError::Lease)?;
            }
            let id = self
                .key(record.address)
                .ok_or(RestoreError::Lease(LeaseError::NotFound))?;
            let lease = self
                .leases
                .get_mut(&id)
                .ok_or(RestoreError::Lease(LeaseError::NotFound))?;
            lease.agent_id = record.agent_id;
            lease.vendor_class = record.vendor_class;
            // read_leases clears NEW/CHANGED; expiry is assigned directly in C.
            lease.script.new = false;
            lease.script.changed = false;
            lease.script.expiry = false;
            lease.script.auxiliary = lease.identity.client_id.is_some();
        }
        // lease_init clears prior dirtiness, then expired records dirty the
        // file again and all restored DNS names must be loaded at startup.
        self.changes.file = false;
        let expired = self.prune(None, now);
        self.changes.dns = true;
        Ok(expired)
    }

    /// lease.c lease_calc_fqdns: after restoring and resolving interface/domain
    /// configuration, build names before the first DNS publication. This does
    /// not change lease ownership, file dirtiness or helper event flags.
    pub fn initialize_fqdns<'a>(&mut self, mut domain: impl FnMut(Ipv4Addr) -> Option<&'a [u8]>) {
        for lease in self.leases.values_mut() {
            if let Some((hostname, suffix)) = lease
                .hostname
                .as_deref()
                .and_then(|hostname| domain(lease.address).map(|suffix| (hostname, suffix)))
            {
                let mut fqdn = Vec::with_capacity(hostname.len() + suffix.len() + 1);
                fqdn.extend_from_slice(hostname);
                fqdn.push(b'.');
                fqdn.extend_from_slice(suffix);
                lease.fqdn = Some(fqdn);
            }
        }
    }

    pub fn set_interface(&mut self, address: Ipv4Addr, interface: u32) -> Result<bool, LeaseError> {
        let id = self.key(address).ok_or(LeaseError::NotFound)?;
        self.set_interface_by_id(id, interface)
    }

    pub fn set_interface_by_id(&mut self, id: LeaseId, interface: u32) -> Result<bool, LeaseError> {
        let lease = self.leases.get_mut(&id).ok_or(LeaseError::NotFound)?;
        let changed = lease.interface != interface;
        lease.interface = interface;
        lease.script.changed |= changed;
        Ok(changed)
    }

    pub fn server_override(
        &mut self,
        address: Ipv4Addr,
        value: Option<Ipv4Addr>,
    ) -> Result<Option<Ipv4Addr>, LeaseError> {
        let id = self.key(address).ok_or(LeaseError::NotFound)?;
        self.server_override_by_id(id, value)
    }

    pub fn server_override_by_id(
        &mut self,
        id: LeaseId,
        value: Option<Ipv4Addr>,
    ) -> Result<Option<Ipv4Addr>, LeaseError> {
        let lease = self.leases.get_mut(&id).ok_or(LeaseError::NotFound)?;
        if value.is_some_and(|value| !value.is_unspecified()) {
            lease.server_override = value;
        }
        Ok(lease.server_override)
    }

    /// SIGHUP schedules OLD callbacks for all active leases (lease.c:1211-1222).
    pub fn rerun_scripts(&mut self) {
        for lease in self.leases.values_mut() {
            lease.script.changed = true;
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn clear_helper_contexts(&mut self) {
        for lease in self.leases.values_mut() {
            lease.helper_context = None;
        }
    }

    /// Packet context belongs to this lease, including pruned/name-loss clones.
    /// Classes are refreshed only for SELECTING, INIT-REBOOT or a new lease.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn set_helper_context(
        &mut self,
        address: Ipv4Addr,
        context: crate::helper::LeaseEventContext,
    ) -> Result<(), LeaseError> {
        let id = self.key(address).ok_or(LeaseError::NotFound)?;
        self.set_helper_context_by_id(id, context)
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn set_helper_context_by_id(
        &mut self,
        id: LeaseId,
        context: crate::helper::LeaseEventContext,
    ) -> Result<(), LeaseError> {
        let lease = self.leases.get_mut(&id).ok_or(LeaseError::NotFound)?;
        if let Some(current) = lease.helper_context.as_mut() {
            current.interface = context.interface;
            if context.relay_address.is_some() {
                current.relay_address = context.relay_address;
            }
            if context.extra.is_some() {
                current.extra = context.extra;
                lease.script.changed = true;
            }
        } else {
            lease.script.changed |= context.extra.is_some();
            lease.helper_context = Some(Box::new(context));
        }
        Ok(())
    }

    pub fn set_agent_id(
        &mut self,
        address: Ipv4Addr,
        value: Option<&[u8]>,
    ) -> Result<(), LeaseError> {
        let id = self.key(address).ok_or(LeaseError::NotFound)?;
        self.set_agent_id_by_id(id, value)
    }

    pub fn set_agent_id_by_id(
        &mut self,
        id: LeaseId,
        value: Option<&[u8]>,
    ) -> Result<(), LeaseError> {
        let lease = self.leases.get_mut(&id).ok_or(LeaseError::NotFound)?;
        if lease.agent_id.as_deref() != value {
            lease.agent_id = value.map(<[u8]>::to_vec);
            self.changes.file = true;
        }
        Ok(())
    }

    pub fn set_vendor_class(
        &mut self,
        address: Ipv4Addr,
        value: Option<&[u8]>,
    ) -> Result<(), LeaseError> {
        let id = self.key(address).ok_or(LeaseError::NotFound)?;
        self.set_vendor_class_by_id(id, value)
    }

    pub fn set_vendor_class_by_id(
        &mut self,
        id: LeaseId,
        value: Option<&[u8]>,
    ) -> Result<(), LeaseError> {
        let lease = self.leases.get_mut(&id).ok_or(LeaseError::NotFound)?;
        if lease.vendor_class.as_deref() != value {
            lease.vendor_class = value.map(<[u8]>::to_vec);
            self.changes.file = true;
        }
        Ok(())
    }

    /// Return removed leases in C's old_leases processing order (oldest first
    /// among leases removed in one prune call). The caller owns deferred script
    /// delivery, including old-hostname-before-delete, before dropping them.
    pub fn prune(&mut self, target: Option<Ipv4Addr>, now: i64) -> Vec<Lease> {
        self.prune_lease(target.and_then(|address| self.key(address)), now)
    }

    /// Prune the selected object, rather than every lease sharing its address.
    pub fn prune_lease(&mut self, target: Option<LeaseId>, now: i64) -> Vec<Lease> {
        // A targeted RELEASE normally removes one large Lease, not Vec's
        // default four-element allocation. Bulk expiry keeps ordinary growth.
        let mut removed = Vec::with_capacity(usize::from(target.is_some()));
        while let Some(&(expires, first)) = self.expiry.first() {
            let id = if lease_expired(expires, now) {
                Some(first)
            } else if expires < 0 || now < 0 {
                // A wrapped future timestamp may precede ordinary expired
                // records in the signed index. Never let it block their prune.
                self.expiry
                    .iter()
                    .find_map(|&(expires, id)| lease_expired(expires, now).then_some(id))
            } else {
                None
            };
            let Some(id) = id else { break };
            if let Some(lease) = self.remove(id) {
                removed.push(lease);
            }
        }
        if let Some(id) = target {
            if let Some(lease) = self.remove(id) {
                removed.push(lease);
            }
        }
        removed.sort_unstable_by_key(|lease| lease.sequence);
        removed
    }

    fn remove(&mut self, id: LeaseId) -> Option<Lease> {
        let lease = self.leases.remove(&id)?;
        let counter = if id.address.is_unspecified() {
            &mut self.counters.pruned6
        } else {
            &mut self.counters.pruned4
        };
        *counter = counter.wrapping_add(1);
        if let Some(expiry) = lease.expires {
            self.expiry.remove(&(expiry, id));
        }
        self.changes.file = true;
        self.changes.dns |= lease.hostname.is_some();
        Some(lease)
    }

    /// Names must already have passed rfc2131 hostname validation. Preserves
    /// authoritative-name precedence and the optional FQDN collision domain.
    /// Loss notifications must be delivered before the new name is announced.
    pub fn set_hostname(
        &mut self,
        address: Ipv4Addr,
        name: Option<&[u8]>,
        authoritative: bool,
        domain: Option<&[u8]>,
        fqdn_only: bool,
    ) -> Result<Vec<NameLost>, LeaseError> {
        let id = self.key(address).ok_or(LeaseError::NotFound)?;
        self.set_hostname_by_id(id, name, authoritative, domain, fqdn_only)
    }

    pub fn set_hostname_by_id(
        &mut self,
        id: LeaseId,
        name: Option<&[u8]>,
        authoritative: bool,
        domain: Option<&[u8]>,
        fqdn_only: bool,
    ) -> Result<Vec<NameLost>, LeaseError> {
        let lease = self.leases.get(&id).ok_or(LeaseError::NotFound)?;
        if lease
            .hostname
            .as_deref()
            .zip(name)
            .is_some_and(|(old, new)| old.eq_ignore_ascii_case(new))
        {
            if authoritative {
                self.leases
                    .get_mut(&id)
                    .ok_or(LeaseError::NotFound)?
                    .authoritative_name = true;
            }
            return Ok(Vec::new());
        }
        if lease.hostname.is_none() && name.is_none() {
            return Ok(Vec::new());
        }
        let new_fqdn = name.zip(domain).map(|(name, domain)| {
            let mut fqdn = Vec::with_capacity(name.len() + domain.len() + 1);
            fqdn.extend_from_slice(name);
            fqdn.push(b'.');
            fqdn.extend_from_slice(domain);
            fqdn
        });
        let collision = self
            .leases
            .values()
            .filter(|other| {
                let pair = if fqdn_only {
                    other.fqdn.as_deref().zip(new_fqdn.as_deref())
                } else {
                    other.hostname.as_deref().zip(name)
                };
                pair.is_some_and(|(old, new)| old.eq_ignore_ascii_case(new))
            })
            .max_by_key(|lease| lease.sequence)
            .map(|other| (other.id(), other.authoritative_name));
        if collision.is_some_and(|(_, auth)| auth && !authoritative) {
            return Ok(Vec::new());
        }
        let mut lost = Vec::new();
        if let Some((other, _)) = collision {
            let other = self.leases.get_mut(&other).ok_or(LeaseError::NotFound)?;
            take_name(other, &mut lost);
            other.script.changed = true;
        }
        let lease = self.leases.get_mut(&id).ok_or(LeaseError::NotFound)?;
        take_name(lease, &mut lost);
        lease.hostname = name.map(<[u8]>::to_vec);
        lease.fqdn = new_fqdn;
        // C never clears LEASE_AUTH_NAME when replacing a configured name.
        lease.authoritative_name |= authoritative;
        lease.script.changed = true;
        self.changes.file = true;
        self.changes.dns = true;
        Ok(lost)
    }

    pub fn active_newest_first(&self) -> Vec<&Lease> {
        let mut leases: Vec<_> = self.leases.values().collect();
        leases.sort_unstable_by_key(|lease| std::cmp::Reverse(lease.sequence));
        leases
    }

    /// The basic five-field IPv4 format consumed by rpcd-rs/LuCI. The caller
    /// handles durable I/O. Agent-info/vendorclass extension rows remain a
    /// separate, explicitly pending integration contract.
    pub fn write_basic_leases(&self, mut writer: impl Write) -> io::Result<()> {
        for lease in self.active_newest_first() {
            write!(writer, "{} ", lease.expires.unwrap_or(0) as u64)?;
            let identity = &lease.identity;
            if identity.hardware_type != 1 || identity.hardware_address.is_empty() {
                write!(writer, "{:02x}-", identity.hardware_type)?;
            }
            write_hex(&mut writer, &identity.hardware_address)?;
            write!(writer, " {} ", lease.address)?;
            writer.write_all(lease.hostname.as_deref().unwrap_or(b"*"))?;
            writer.write_all(b" ")?;
            if let Some(clid) = &identity.client_id {
                write_hex(&mut writer, clid)?;
            } else {
                writer.write_all(b"*")?;
            }
            writer.write_all(b"\n")?;
        }
        Ok(())
    }

    /// Includes leasequery's extension rows after all basic records, exactly
    /// the section ordering in lease.c:373-412. Successful return means the
    /// supplied writer accepted bytes; callers still must flush/fsync and only
    /// then call file_written().
    pub fn write_leases(&self, mut writer: impl Write) -> io::Result<()> {
        self.write_basic_leases(&mut writer)?;
        for lease in self.active_newest_first() {
            for (name, value) in [
                ("agent-info", &lease.agent_id),
                ("vendorclass", &lease.vendor_class),
            ] {
                if let Some(value) = value {
                    write!(writer, "{name} {} ", lease.address)?;
                    write_hex(&mut writer, value)?;
                    writer.write_all(b"\n")?;
                }
            }
        }
        Ok(())
    }
}

/// Exact image musl difftime subtracts time_t before conversion to double.
/// Preserve its 64-bit wrapping difference for restored out-of-range values.
pub fn lease_expired(expires: i64, now: i64) -> bool {
    now.wrapping_sub(expires) >= 0
}

/// The image's AArch64 unsigned conversion of difftime saturates at each
/// endpoint of u32. Helper and INFORM/LEASEQUERY share this C conversion.
pub fn remaining_seconds(expires: i64, now: i64) -> u32 {
    expires.wrapping_sub(now).clamp(0, i64::from(u32::MAX)) as u32
}

pub fn expiry_time(length: u32, now: i64) -> Option<i64> {
    if length == u32::MAX {
        None
    } else {
        now.checked_add(i64::from(length))
            .filter(|&expires| expires > now && expires != 0)
    }
}

fn take_name(lease: &mut Lease, lost: &mut Vec<NameLost>) {
    let name = lease.fqdn.take().or_else(|| lease.hostname.clone());
    lease.hostname = None;
    if let Some(name) = name {
        lease.old_hostname = Some(name.clone());
        lost.push(NameLost {
            address: lease.address,
            name,
        });
    }
}

fn write_hex(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // Lease files contain this encoding for every hardware/client ID. Encode
    // bounded chunks directly instead of invoking fmt for every byte. The
    // same bound also handles arbitrary-length leasequery extension fields.
    let mut output = [0; 192];
    for (chunk_index, chunk) in bytes.chunks(64).enumerate() {
        let mut length = 0;
        for (index, &byte) in chunk.iter().enumerate() {
            if chunk_index != 0 || index != 0 {
                output[length] = b':';
                length += 1;
            }
            output[length] = HEX[usize::from(byte >> 4)];
            output[length + 1] = HEX[usize::from(byte & 15)];
            length += 2;
        }
        writer.write_all(&output[..length])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_chunks_preserve_all_bytes_and_partial_write_failures() {
        struct Limited {
            bytes: Vec<u8>,
            limit: usize,
        }
        impl Write for Limited {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let count = bytes.len().min(self.limit - self.bytes.len());
                if count == 0 {
                    return Err(io::ErrorKind::StorageFull.into());
                }
                self.bytes.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        for length in [0, 1, 6, 16, 63, 64, 65, 255, 256, 1025] {
            let input: Vec<_> = (0..length).map(|byte| byte as u8).collect();
            let expected = input
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":")
                .into_bytes();
            let mut actual = Vec::new();
            write_hex(&mut actual, &input).unwrap();
            assert_eq!(actual, expected);
            for limit in [0, 1, 190, 191, 192, 193, expected.len()] {
                let mut writer = Limited {
                    bytes: Vec::new(),
                    limit,
                };
                let result = write_hex(&mut writer, &input);
                assert_eq!(writer.bytes, expected[..limit.min(expected.len())]);
                assert_eq!(result.is_ok(), limit >= expected.len());
            }
        }
    }

    fn address(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, last)
    }
    fn client(mac: u8, id: Option<u8>) -> ClientIdentity {
        ClientIdentity {
            hardware_type: 1,
            hardware_address: vec![0, 1, 2, 3, 4, mac],
            client_id: id.map(|id| vec![id]),
        }
    }

    #[test]
    fn client_id_and_missing_id_follow_c_precedence() {
        let mut store = LeaseStore::new(4);
        store.allocate(address(1), client(1, Some(7))).unwrap();
        store.allocate(address(2), client(1, Some(8))).unwrap();
        assert_eq!(
            store.find_client(&client(99, Some(7))).unwrap().address,
            address(1)
        );
        assert_eq!(
            store.find_client(&client(1, None)).unwrap().address,
            address(2)
        );
        assert!(store.find_client(&client(1, Some(9))).is_none());
        store.allocate(address(3), client(1, None)).unwrap();
        assert_eq!(
            store.find_client(&client(1, Some(9))).unwrap().address,
            address(3)
        );
        store.set_identity(address(2), &client(1, None)).unwrap();
        assert_eq!(
            store.get(address(2)).unwrap().identity.client_id,
            Some(vec![8])
        );
    }

    #[test]
    fn renewal_has_one_expiry_entry_and_old_deadlines_cannot_expire_it() {
        let mut store = LeaseStore::new(1);
        store.allocate(address(1), client(1, None)).unwrap();
        for now in 1..10_000 {
            store.set_expires(address(1), 120, now).unwrap();
            assert_eq!(store.expiry.len(), 1);
        }
        assert_eq!(store.next_expiry(), Some(10119));
        assert!(store.prune(None, 10118).is_empty());
        assert_eq!(store.prune(None, 10119).len(), 1);
        assert_eq!(store.next_expiry(), None);
        assert!(store.is_empty());
    }

    #[test]
    fn finite_infinite_explicit_prune_and_capacity() {
        let mut store = LeaseStore::new(2);
        store.allocate(address(1), client(1, None)).unwrap();
        store.allocate(address(2), client(2, None)).unwrap();
        assert_eq!(
            store.allocate(address(3), client(3, None)),
            Err(LeaseError::Full)
        );
        assert_eq!(
            store.allocate(address(1), client(3, None)),
            Err(LeaseError::AddressInUse)
        );
        store.set_expires(address(1), 20, 100).unwrap();
        store.set_expires(address(2), u32::MAX, 100).unwrap();
        let removed = store.prune(Some(address(2)), 120);
        assert_eq!(
            removed
                .iter()
                .map(|lease| lease.address)
                .collect::<Vec<_>>(),
            [address(1), address(2)]
        );
        assert!(store.expiry.is_empty());
        store.allocate(address(3), client(3, None)).unwrap();
        assert_eq!(expiry_time(0, 100), None);
        assert_eq!(expiry_time(1, i64::MAX), None);
    }

    #[test]
    fn stalled_script_bounds_churn_and_delivers_every_admitted_delete() {
        let mut store = LeaseStore::new(1);
        let mut queue = ScriptQueue::default();
        for _ in 0..64 {
            store.set_script_backlog(Some(queue.pending_deletions()));
            store.allocate(address(1), client(1, None)).unwrap();
            queue.add_pruned(store.prune(Some(address(1)), 0));
        }
        for _ in 0..1024 {
            store.set_script_backlog(Some(queue.pending_deletions()));
            assert_eq!(
                store.allocate(address(1), client(1, None)),
                Err(LeaseError::Full)
            );
        }
        assert!(store.is_empty());
        assert_eq!(queue.pending_deletions(), 64);
        let mut delivered = 0;
        while let Some(event) = queue.next(&mut store, ScriptOptions::default()) {
            assert_eq!(event.action, ScriptAction::Delete);
            delivered += 1;
        }
        assert_eq!(delivered, 64);
        store.set_script_backlog(Some(queue.pending_deletions()));
        store.allocate(address(1), client(1, None)).unwrap();
    }

    #[test]
    fn stalled_script_keeps_renewal_and_prune_but_cannot_recycle_transaction_credit() {
        let mut store = LeaseStore::new(2);
        store.allocate(address(1), client(1, None)).unwrap();
        store.set_script_backlog(Some(63));
        store.set_expires(address(1), 120, 100).unwrap();
        assert_eq!(store.get(address(1)).unwrap().expires, Some(220));
        let removed = store.prune(Some(address(1)), 100);
        assert_eq!(removed.len(), 1);
        assert_eq!(
            store.allocate(address(2), client(1, None)),
            Err(LeaseError::Full)
        );
        store.set_script_backlog(Some(63));
        store.allocate(address(2), client(1, None)).unwrap();
        store.prune(Some(address(2)), 100);
        assert_eq!(
            store.allocate(address(1), client(1, None)),
            Err(LeaseError::Full)
        );
        store.set_script_backlog(None);
        store.allocate(address(1), client(1, None)).unwrap();
    }

    #[test]
    fn script_backlog_budget_scales_with_configured_lease_capacity() {
        let mut store = LeaseStore::new(150);
        store.set_script_backlog(Some(299));
        store.allocate(address(1), client(1, None)).unwrap();
        assert_eq!(
            store.allocate(address(2), client(2, None)),
            Err(LeaseError::Full)
        );
        store.set_script_backlog(Some(298));
        store.allocate(address(2), client(2, None)).unwrap();
        store.set_script_backlog(Some(usize::MAX));
        assert_eq!(
            store.allocate(address(3), client(3, None)),
            Err(LeaseError::Full)
        );
        let mut largest = LeaseStore::new(usize::MAX);
        largest.set_script_backlog(Some(usize::MAX - 1));
        largest.allocate(address(1), client(1, None)).unwrap();
        assert_eq!(
            largest.allocate(address(2), client(2, None)),
            Err(LeaseError::Full)
        );
    }

    #[test]
    fn expiry_of_full_active_table_preserves_all_deleted_records_at_backlog_limit() {
        let mut store = LeaseStore::new(2);
        let mut queue = ScriptQueue::default();
        for _ in 0..62 {
            store.set_script_backlog(Some(queue.pending_deletions()));
            store.allocate(address(1), client(1, None)).unwrap();
            queue.add_pruned(store.prune(Some(address(1)), 0));
        }
        store.set_script_backlog(Some(queue.pending_deletions()));
        for last in [1, 2] {
            store.allocate(address(last), client(last, None)).unwrap();
            store.set_expires(address(last), 120, 100).unwrap();
        }
        store.set_script_backlog(Some(queue.pending_deletions()));
        queue.add_pruned(store.prune(None, 220));
        assert!(store.is_empty());
        assert_eq!(queue.pending_deletions(), 64);
        assert_eq!(
            store.allocate(address(1), client(1, None)),
            Err(LeaseError::Full)
        );
        let mut delivered = BTreeSet::new();
        while let Some(event) = queue.next(&mut store, ScriptOptions::default()) {
            assert_eq!(event.action, ScriptAction::Delete);
            assert!(delivered.insert(event.lease.id()));
        }
        assert_eq!(delivered.len(), 64);
    }

    #[test]
    fn configured_name_cannot_be_stolen_by_client() {
        let mut store = LeaseStore::new(2);
        store.allocate(address(1), client(1, None)).unwrap();
        store.allocate(address(2), client(2, None)).unwrap();
        store
            .set_hostname(address(1), Some(b"server"), true, Some(b"test"), false)
            .unwrap();
        assert!(store
            .set_hostname(address(2), Some(b"SERVER"), false, Some(b"test"), false)
            .unwrap()
            .is_empty());
        assert!(store.get(address(2)).unwrap().hostname.is_none());
        let lost = store
            .set_hostname(address(2), Some(b"server"), true, Some(b"test"), false)
            .unwrap();
        assert_eq!(
            lost,
            [NameLost {
                address: address(1),
                name: b"server.test".to_vec()
            }]
        );
        assert!(store.get(address(1)).unwrap().hostname.is_none());
    }

    #[test]
    fn fqdn_mode_allows_same_short_name_in_different_domains() {
        let mut store = LeaseStore::new(2);
        store.allocate(address(1), client(1, None)).unwrap();
        store.allocate(address(2), client(2, None)).unwrap();
        store
            .set_hostname(address(1), Some(b"host"), false, Some(b"a.test"), true)
            .unwrap();
        store
            .set_hostname(address(2), Some(b"host"), false, Some(b"b.test"), true)
            .unwrap();
        assert!(store.get(address(1)).unwrap().hostname.is_some());
        assert!(store.get(address(2)).unwrap().hostname.is_some());
    }

    #[test]
    fn restored_fqdn_survives_same_configured_name_without_file_change() {
        let records = super::super::lease_file::parse(
            b"0 02:00:00:00:00:01 192.0.2.7 Fixed *\n0 02:00:00:00:00:02 192.0.2.8 * *\n",
        );
        let mut store = LeaseStore::new(2);
        store.restore(records.records, 100).unwrap();
        let before = store.changes();
        let mut looked_up = Vec::new();
        store.initialize_fqdns(|address| {
            looked_up.push(address);
            Some(b"pool.test".as_slice())
        });
        assert_eq!(looked_up, [address(7)]);
        assert_eq!(store.changes(), before);
        assert!(store
            .set_hostname(address(7), Some(b"fixed"), true, Some(b"pool.test"), false)
            .unwrap()
            .is_empty());
        let lease = store.get(address(7)).unwrap();
        assert_eq!(lease.fqdn.as_deref(), Some(b"Fixed.pool.test".as_slice()));
        assert!(lease.authoritative_name);
        assert!(!lease.script.changed && !lease.script.new && !lease.script.expiry);
        assert_eq!(store.changes(), before);
        assert!(store.get(address(8)).unwrap().fqdn.is_none());
    }

    #[test]
    fn basic_lease_file_matches_c_format() {
        let mut store = LeaseStore::new(1);
        store.allocate(address(7), client(5, Some(9))).unwrap();
        store.set_expires(address(7), 100, 100).unwrap();
        store
            .set_hostname(address(7), Some(b"test"), false, None, false)
            .unwrap();
        let mut output = Vec::new();
        store.write_basic_leases(&mut output).unwrap();
        assert_eq!(output, b"200 00:01:02:03:04:05 192.0.2.7 test 09\n");
    }

    #[test]
    fn recovery_prunes_expired_and_preserves_extensions_and_order() {
        let file = super::super::lease_file::parse(b"200 00:01:02:03:04:05 192.0.2.7 host 01:02\n0 06-aa:bb:cc 192.0.2.8 * *\n100 01:02:03:04:05:06 192.0.2.9 gone *\nagent-info 192.0.2.7 01:02:03\nvendorclass 192.0.2.7 74:65:73:74\n");
        let mut store = LeaseStore::new(3);
        let expired = store.restore(file.records, 100).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].address, address(9));
        assert_eq!(
            store.changes(),
            Changes {
                file: true,
                dns: true
            }
        );
        assert_eq!(store.next_expiry(), Some(200));
        let mut output = Vec::new();
        store.write_leases(&mut output).unwrap();
        assert_eq!(output, b"0 06-aa:bb:cc 192.0.2.8 * *\n200 00:01:02:03:04:05 192.0.2.7 host 01:02\nagent-info 192.0.2.7 01:02:03\nvendorclass 192.0.2.7 74:65:73:74\n");
    }

    #[test]
    fn failed_writer_does_not_clear_dirty_state() {
        struct Failed;
        impl Write for Failed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::StorageFull.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut store = LeaseStore::new(1);
        store.allocate(address(1), client(1, None)).unwrap();
        assert_eq!(
            store.write_leases(Failed).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert!(store.changes().file);
    }

    #[test]
    fn duplicate_address_recovery_keeps_independent_identity_and_expiry() {
        let file = super::super::lease_file::parse(
            b"200 01 192.0.2.1 first 01\n300 02 192.0.2.1 second 02\n",
        );
        let mut store = LeaseStore::new(2);
        assert!(store.restore(file.records, 100).unwrap().is_empty());
        assert_eq!(store.len(), 2);
        assert_eq!(
            store.get(address(1)).unwrap().identity.hardware_address,
            [2]
        );
        let first = store
            .find_client(&ClientIdentity {
                hardware_type: 1,
                hardware_address: vec![1],
                client_id: Some(vec![1]),
            })
            .unwrap()
            .id();
        store.set_expires_by_id(first, 150, 100).unwrap();
        assert_eq!(store.get(address(1)).unwrap().expires, Some(300));
        assert_eq!(store.get_by_id(first).unwrap().expires, Some(250));
        let removed = store.prune_lease(Some(first), 100);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].hostname.as_deref(), Some(b"first".as_slice()));
        assert_eq!(store.len(), 1);
        assert_eq!(store.next_expiry(), Some(300));
        assert_eq!(store.prune(None, 300).len(), 1);
    }

    #[test]
    fn duplicate_expiry_preserves_the_other_lease_and_each_script_event() {
        let file = super::super::lease_file::parse(
            b"200 01 192.0.2.1 first *\n150 02 192.0.2.1 second *\n",
        );
        let mut store = LeaseStore::new(2);
        store.restore(file.records, 100).unwrap();
        store.rerun_scripts();
        let mut scripts = ScriptQueue::default();
        let newest = scripts.next(&mut store, ScriptOptions::default()).unwrap();
        let oldest = scripts.next(&mut store, ScriptOptions::default()).unwrap();
        assert_eq!(newest.name.as_deref(), Some(b"second".as_slice()));
        assert_eq!(oldest.name.as_deref(), Some(b"first".as_slice()));
        assert!(scripts.next(&mut store, ScriptOptions::default()).is_none());
        let removed = store.prune(None, 150);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].id(), newest.lease.id());
        assert_eq!(store.get(address(1)).unwrap().id(), oldest.lease.id());
        assert_eq!(store.next_expiry(), Some(200));
        scripts.add_pruned(removed);
        let deleted = scripts.next(&mut store, ScriptOptions::default()).unwrap();
        assert_eq!(deleted.action, ScriptAction::Delete);
        assert_eq!(deleted.lease.id(), newest.lease.id());
        assert_eq!(store.counters().allocated4, 2);
        assert_eq!(store.counters().pruned4, 1);
    }

    #[test]
    fn restore_checks_capacity_before_pruning_expired_duplicate_records() {
        let file =
            super::super::lease_file::parse(b"50 01 192.0.2.1 first *\n50 02 192.0.2.1 second *\n");
        let mut store = LeaseStore::new(1);
        assert_eq!(
            store.restore(file.records, 100).unwrap_err(),
            RestoreError::Lease(LeaseError::Full)
        );
        assert_eq!(store.len(), 1);
        assert_eq!(store.counters().allocated4, 1);
    }

    #[test]
    fn exact_image_wrapped_timestamps_survive_and_write_unsigned_bits() {
        let file = super::super::lease_file::parse(
            b"9223372036854775808 01 192.0.2.1 low *\n-9223372036854775809 02 192.0.2.2 high *\n-1 03 192.0.2.3 expired *\n",
        );
        let mut store = LeaseStore::new(3);
        let removed = store.restore(file.records, 100).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].address, address(3));
        assert_eq!(store.get(address(1)).unwrap().expires, Some(i64::MIN));
        assert_eq!(store.get(address(2)).unwrap().expires, Some(i64::MAX));
        assert_eq!(store.next_expiry(), Some(i64::MAX));
        assert!(store.prune(None, 100).is_empty());
        let mut output = Vec::new();
        store.write_leases(&mut output).unwrap();
        assert_eq!(
            output,
            b"9223372036854775807 02 192.0.2.2 high *\n9223372036854775808 01 192.0.2.1 low *\n"
        );
        assert_eq!(remaining_seconds(i64::MIN, 100), u32::MAX);
        assert_eq!(remaining_seconds(i64::MAX, 100), u32::MAX);
        assert_eq!(remaining_seconds(-1, 100), 0);
    }

    #[test]
    fn fqdn_only_restore_preserves_short_names_until_domains_are_calculated() {
        let input = b"200 01 192.0.2.1 host *\n200 02 192.0.2.2 host *\n";
        for fqdn_only in [false, true] {
            let mut store = LeaseStore::new(2);
            store
                .restore_with_name_policy(
                    super::super::lease_file::parse(input).records,
                    100,
                    fqdn_only,
                )
                .unwrap();
            assert_eq!(store.get(address(1)).unwrap().hostname.is_some(), fqdn_only);
            assert!(store.get(address(2)).unwrap().hostname.is_some());
            store.initialize_fqdns(|ip| {
                Some(if ip == address(1) {
                    b"one.test"
                } else {
                    b"two.test"
                })
            });
            assert_eq!(store.get(address(1)).unwrap().fqdn.is_some(), fqdn_only);
            assert_eq!(
                store.get(address(2)).unwrap().fqdn.as_deref(),
                Some(b"host.two.test".as_slice())
            );
        }
    }

    #[test]
    fn recovery_preserves_non_utf8_name_and_full_c_hardware_type() {
        let input = b"200 1234-aa:bb:cc 192.0.2.7 h\xffst *\n";
        let mut store = LeaseStore::new(1);
        store
            .restore(super::super::lease_file::parse(input).records, 100)
            .unwrap();
        assert_eq!(
            store.get(address(7)).unwrap().identity.hardware_type,
            0x1234
        );
        assert_eq!(
            store.get(address(7)).unwrap().hostname.as_deref(),
            Some(&b"h\xffst"[..])
        );
        let mut bytes = Vec::new();
        store.write_leases(&mut bytes).unwrap();
        assert_eq!(bytes, input);
    }

    #[test]
    fn script_old_name_precedes_new_location_and_delete_releases_ownership() {
        let mut store = LeaseStore::new(2);
        let mut queue = ScriptQueue::default();
        let options = ScriptOptions::default();
        store.allocate(address(1), client(1, None)).unwrap();
        store.set_expires(address(1), u32::MAX, 100).unwrap();
        store
            .set_hostname(address(1), Some(b"host"), false, Some(b"test"), false)
            .unwrap();
        assert_eq!(
            queue.next(&mut store, options).unwrap().action,
            ScriptAction::Add
        );
        store.allocate(address(2), client(2, None)).unwrap();
        store.set_expires(address(2), u32::MAX, 100).unwrap();
        store
            .set_hostname(address(2), Some(b"host"), false, Some(b"test"), false)
            .unwrap();
        let lost = queue.next(&mut store, options).unwrap();
        assert_eq!(lost.action, ScriptAction::OldHostname);
        assert_eq!(lost.lease.address, address(1));
        assert_eq!(lost.name.as_deref(), Some(&b"host.test"[..]));
        assert_eq!(
            queue.next(&mut store, options).unwrap().action,
            ScriptAction::Add
        );
        assert_eq!(
            queue.next(&mut store, options).unwrap().action,
            ScriptAction::Old
        );
        assert!(queue.next(&mut store, options).is_none());
        store
            .set_hostname(address(2), Some(b"new"), false, None, false)
            .unwrap();
        queue.add_pruned(store.prune(Some(address(2)), 100));
        assert_eq!(queue.pending_deletions(), 1);
        assert_eq!(
            queue.next(&mut store, options).unwrap().action,
            ScriptAction::OldHostname
        );
        assert_eq!(queue.pending_deletions(), 1);
        let deleted = queue.next(&mut store, options).unwrap();
        assert_eq!(deleted.action, ScriptAction::Delete);
        assert_eq!(deleted.name.as_deref(), Some(&b"new"[..]));
        assert_eq!(queue.pending_deletions(), 0);
    }

    #[test]
    fn operation_counters_wrap_and_failed_allocations_do_not_count() {
        let mut store = LeaseStore::new(1);
        store.counters = LeaseCounters {
            allocated4: u32::MAX,
            pruned4: u32::MAX,
            pruned6: u32::MAX,
        };
        store.allocate(address(1), client(1, None)).unwrap();
        store.set_expires(address(1), 120, 100).unwrap();
        assert_eq!(store.counters.allocated4, 0);
        assert_eq!(
            store.allocate(address(2), client(2, None)),
            Err(LeaseError::Full)
        );
        assert_eq!(
            store.allocate(address(1), client(1, None)),
            Err(LeaseError::AddressInUse)
        );
        assert_eq!(store.counters.allocated4, 0);
        store.prune(None, 220);
        store.prune(Some(address(1)), 220);
        assert_eq!(store.counters.pruned4, 0);
        store
            .allocate(Ipv4Addr::UNSPECIFIED, client(2, None))
            .unwrap();
        store.prune(Some(Ipv4Addr::UNSPECIFIED), 0);
        assert_eq!(
            store.counters,
            LeaseCounters {
                allocated4: 1,
                pruned4: 0,
                pruned6: 0,
            }
        );
    }

    #[test]
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn helper_context_stays_with_lease_and_extradata_is_one_shot() {
        let mut store = LeaseStore::new(2);
        let mut queue = ScriptQueue::default();
        for index in 1..=2 {
            store.allocate(address(index), client(index, None)).unwrap();
            store
                .set_helper_context(
                    address(index),
                    crate::helper::LeaseEventContext {
                        interface: format!("eth{index}").into_bytes(),
                        extra: Some(Box::new(crate::helper::ExtraData {
                            vendor_class: vec![index],
                            ..Default::default()
                        })),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        for index in (1..=2).rev() {
            let event = queue.next(&mut store, ScriptOptions::default()).unwrap();
            let context = event.lease.helper_context.unwrap();
            assert_eq!(context.interface, format!("eth{index}").as_bytes());
            assert_eq!(context.extra.unwrap().vendor_class, vec![index]);
            assert!(store
                .get(address(index))
                .unwrap()
                .helper_context
                .as_ref()
                .unwrap()
                .extra
                .is_none());
        }
        store.rerun_scripts();
        let event = queue.next(&mut store, ScriptOptions::default()).unwrap();
        assert_eq!(
            event.lease.helper_context.as_ref().unwrap().interface,
            b"eth2"
        );
        assert!(event.lease.helper_context.unwrap().extra.is_none());
    }

    #[test]
    fn renewal_notifications_are_opt_in_and_hup_marks_existing_records_old() {
        let mut store = LeaseStore::new(1);
        let mut queue = ScriptQueue::default();
        store.allocate(address(1), client(1, None)).unwrap();
        store.set_expires(address(1), 100, 100).unwrap();
        assert_eq!(
            queue
                .next(&mut store, ScriptOptions::default())
                .unwrap()
                .action,
            ScriptAction::Add
        );
        store.set_expires(address(1), 100, 150).unwrap();
        assert!(queue.next(&mut store, ScriptOptions::default()).is_none());
        let renewal = ScriptOptions {
            notify_renewals: true,
            ..ScriptOptions::default()
        };
        assert_eq!(
            queue.next(&mut store, renewal).unwrap().action,
            ScriptAction::Old
        );
        assert!(queue.next(&mut store, renewal).is_none());
        store.rerun_scripts();
        assert_eq!(
            queue
                .next(&mut store, ScriptOptions::default())
                .unwrap()
                .action,
            ScriptAction::Old
        );
    }
}

//! Runtime domain selection traced to dnsmasq 2.93 domain-match.c.
//!
//! Callers establish configured/cache/hosts ownership before this lookup.
//! Upstream address families do not constrain the query type: an IPv4 server
//! may answer AAAA and an IPv6 server may answer A. Family priority applies to
//! local `address=` literals only.

use super::files::{ServerSources, Source, SourceRule};
use super::forward::{GroupId, Server, ServerGroup, ServerId};
use super::upstream::source_sockets::SourceSpec;
use super::wire::Name;
use crate::config::dns::{
    DnsConfig, DomainPattern, RuleTarget, ServerEndpoint, ServerHost, ServerRule,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_DS: u16 = 43;
const TYPE_DNSKEY: u16 = 48;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryFamily {
    V4,
    V6,
    Any,
    Other,
}

impl QueryFamily {
    pub fn for_qtype(qtype: u16) -> Self {
        match qtype {
            TYPE_A => Self::V4,
            TYPE_AAAA => Self::V6,
            TYPE_ANY => Self::Any,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteReason {
    LocalRecord,
    LocalAddress {
        addresses: Vec<IpAddr>,
    },
    LocalOnly,
    Upstream {
        group: GroupId,
        pattern: DomainPattern,
        family: QueryFamily,
    },
    NoMatchingRule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSelection {
    pub group: Option<GroupId>,
    pub reason: RouteReason,
}

impl RouteSelection {
    pub fn upstream_group(&self) -> Option<GroupId> {
        match &self.reason {
            RouteReason::Upstream { group, .. } => Some(*group),
            _ => None,
        }
    }

    fn local(reason: RouteReason) -> Self {
        Self {
            group: None,
            reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    UnresolvedHostname(Vec<u8>),
    UnresolvedScope(Vec<u8>),
    UnresolvedSource,
    MissingDefaultResolvers,
}

#[derive(Debug, Clone)]
struct RuleBucket {
    /// C keeps exact and wildcard rules in separate server tiers, including
    /// the empty wildcard suffix produced by `/*./`.
    pattern: DomainPattern,
    literals: Vec<IpAddr>,
    zeros: usize,
    local_only: bool,
    use_defaults: bool,
    servers: Vec<Server>,
    group: Option<GroupId>,
}

impl RuleBucket {
    fn new(pattern: DomainPattern) -> Self {
        Self {
            pattern,
            literals: Vec::new(),
            zeros: 0,
            local_only: false,
            use_defaults: false,
            servers: Vec::new(),
            group: None,
        }
    }

    fn representative(&self) -> &DomainPattern {
        &self.pattern
    }

    fn matched_pattern<'a>(&'a self, query: &[u8]) -> Option<&'a DomainPattern> {
        matches_domain(query, &self.pattern).then_some(&self.pattern)
    }
}

/// Groups retain configuration order, including mixed IPv4/IPv6 servers.
/// Group and server identities are stable for this table's lifetime.
pub struct RoutingTable {
    rules: Vec<RuleBucket>,
    groups: HashMap<GroupId, ServerGroup>,
    default_group: Option<GroupId>,
    next_group: u64,
    source_endpoints: HashMap<ServerId, ServerEndpoint>,
}

impl RoutingTable {
    /// Build the daemon's runtime routes, including the implicit resolver-file
    /// default shared by UDP and TCP callers. Inputs are already finalized and
    /// resolver-file I/O remains the caller's responsibility.
    pub fn from_runtime_config(
        config: &DnsConfig,
        default_resolvers: &[SocketAddr],
    ) -> Result<Self, RoutingError> {
        Self::from_config(config, default_resolvers)
    }

    /// Publish the active resolver-file default tier to the local-answer
    /// view too. In particular, this tier precedes an empty wildcard (`/*./`)
    /// but shares the ordinary empty suffix with `address=/#/` literals.
    pub fn add_default_resolver_rule(config: &mut DnsConfig, default_resolvers: &[SocketAddr]) {
        if !config.no_resolv
            && !default_resolvers.is_empty()
            && !config.rules.iter().any(|rule| {
                matches!(rule.target, RuleTarget::DefaultResolvers)
                    && rule.domain.suffix.is_empty()
                    && !rule.domain.dotless
                    && !rule.domain.wildcard
            })
        {
            config.rules.push(ServerRule {
                domain: DomainPattern {
                    suffix: Vec::new(),
                    wildcard: false,
                    wildcard_dot: false,
                    dotless: false,
                },
                target: RuleTarget::DefaultResolvers,
            });
        }
    }

    /// File selection belongs to the caller. Empty resolver input is legal:
    /// the service can start and later receive its first nameserver via inotify.
    pub fn from_config(
        config: &DnsConfig,
        default_resolvers: &[SocketAddr],
    ) -> Result<Self, RoutingError> {
        let mut sources = ServerSources::new(&config.rules);
        if !config.no_resolv {
            sources.replace(
                Source::Resolv,
                default_resolvers
                    .iter()
                    .copied()
                    .map(|address| SourceRule::resolver(address, 0))
                    .collect(),
            );
        }
        Self::from_sources(config, &sources, None)
    }

    /// Preserve live server IDs supplied by mark/reuse source state, and the
    /// group IDs of surviving domain tiers. Rebuild only route metadata; the
    /// owner reconciles the existing forwarding engine with dispatcher_groups.
    pub fn from_sources(
        config: &DnsConfig,
        sources: &ServerSources,
        previous: Option<&Self>,
    ) -> Result<Self, RoutingError> {
        Self::from_sources_except(config, sources, previous, &[])
    }

    pub(crate) fn from_sources_except(
        config: &DnsConfig,
        sources: &ServerSources,
        previous: Option<&Self>,
        excluded: &[ServerId],
    ) -> Result<Self, RoutingError> {
        let mut buckets: Vec<RuleBucket> = Vec::new();
        let mut source_endpoints = HashMap::new();
        for entry in sources.rules() {
            if entry.server.is_some_and(|id| excluded.contains(&id)) {
                continue;
            }
            let rule = &entry.value.rule;
            let mut pattern = rule.domain.clone();
            pattern.suffix.make_ascii_lowercase();
            let bucket = match buckets
                .iter()
                .position(|bucket| bucket.representative() == &pattern)
            {
                Some(index) => &mut buckets[index],
                None => {
                    buckets.push(RuleBucket::new(pattern));
                    buckets.last_mut().unwrap()
                }
            };
            match &rule.target {
                RuleTarget::Literal(address) => bucket.literals.insert(0, *address),
                RuleTarget::ZeroAddresses => bucket.zeros += 1,
                RuleTarget::LocalOnly => bucket.local_only = true,
                RuleTarget::DefaultResolvers => bucket.use_defaults = true,
                RuleTarget::Upstream(endpoint) => {
                    let address = match entry.value.address {
                        Some(address) => address,
                        None => validate_endpoint(endpoint)?,
                    };
                    source_endpoints
                        .insert(entry.server.expect("upstream identity"), endpoint.clone());
                    bucket.servers.push(Server {
                        id: entry
                            .server
                            .expect("upstream source owns a server identity"),
                        address,
                        bound_socket: None,
                    });
                }
            }
        }
        let mut groups = HashMap::new();
        let mut next_group = previous.map_or(0, |table| table.next_group);
        let mut default_group = None;
        for bucket in &mut buckets {
            if bucket.servers.is_empty() {
                continue;
            }
            let existing = previous
                .and_then(|table| table.rules.iter().find(|old| old.pattern == bucket.pattern))
                .and_then(|old| old.group);
            let id = existing.unwrap_or_else(|| {
                next_group += 1;
                GroupId(next_group)
            });
            groups.insert(
                id,
                ServerGroup::new(
                    id,
                    std::mem::take(&mut bucket.servers),
                    config.strict_order,
                    config.all_servers,
                ),
            );
            bucket.group = Some(id);
            if bucket.pattern.suffix.is_empty()
                && !bucket.pattern.wildcard
                && !bucket.pattern.dotless
            {
                default_group = Some(id);
            }
        }
        // Dotless routes override only the empty-domain/default route. A
        // nonempty domain rule still wins for a matching single-label name.
        crate::sorting::sort_by(&mut buckets, |left, right| {
            right
                .representative()
                .suffix
                .len()
                .cmp(&left.representative().suffix.len())
                .then_with(|| {
                    right
                        .representative()
                        .dotless
                        .cmp(&left.representative().dotless)
                })
                .then_with(|| {
                    left.representative()
                        .wildcard
                        .cmp(&right.representative().wildcard)
                })
        });
        Ok(Self {
            rules: buckets,
            groups,
            default_group,
            next_group,
            source_endpoints,
        })
    }

    /// `local_owned` is established before domain matching by the caller's
    /// configured/cache/hosts/CNAME lookup, not inferred from a missing route.
    pub fn select(&self, name: &Name, qtype: u16, class: u16, local_owned: bool) -> RouteSelection {
        if local_owned {
            return RouteSelection::local(RouteReason::LocalRecord);
        }
        let family = QueryFamily::for_qtype(qtype);
        let mut query = dotted_name(name);
        // extract_request marks DS/DNSKEY independently of validation support.
        if qtype == TYPE_DS {
            let start = query
                .iter()
                .position(|&c| c == b'.')
                .map_or(query.len(), |i| i + 1);
            query.drain(..start);
        }
        let allow_dotless = !matches!(qtype, TYPE_DS | TYPE_DNSKEY);
        for bucket in &self.rules {
            if bucket.representative().dotless && !allow_dotless {
                continue;
            }
            let Some(pattern) = bucket.matched_pattern(&query) else {
                continue;
            };
            if class == CLASS_IN {
                let addresses = local_addresses(&bucket.literals, bucket.zeros, family);
                if !addresses.is_empty() {
                    return RouteSelection::local(RouteReason::LocalAddress { addresses });
                }
            }
            if bucket.local_only {
                return RouteSelection::local(RouteReason::LocalOnly);
            }
            // SERV_USE_RESOLV restarts at the ordinary global-server tier
            // with F_SERVER, so default literals are skipped. These are all
            // global upstreams, including inline and servers-file origins.
            let group = if bucket.use_defaults {
                self.default_group
            } else {
                bucket.group
            };
            if let Some(group) = group {
                return RouteSelection {
                    group: Some(group),
                    reason: RouteReason::Upstream {
                        group,
                        pattern: pattern.clone(),
                        family,
                    },
                };
            }
            if bucket.use_defaults {
                return RouteSelection::local(RouteReason::NoMatchingRule);
            }
            // C's late NODOTS override also overrides an existing default
            // route with no match if its local address family is inapplicable.
            if bucket.representative().dotless {
                break;
            }
        }
        RouteSelection::local(RouteReason::NoMatchingRule)
    }

    /// lookup_domain(F_DOMAINSRV) skips literal/local-only answers and
    /// excludes an ordinary default server from the private-PTR exception.
    pub(super) fn has_domain_server(&self, name: &Name) -> bool {
        let query = dotted_name(name);
        self.rules.iter().any(|bucket| {
            !bucket.use_defaults
                && bucket.group.is_some()
                && (!bucket.representative().suffix.is_empty() || bucket.representative().dotless)
                && bucket.matched_pattern(&query).is_some()
        })
    }

    pub fn group(&self, id: GroupId) -> Option<&ServerGroup> {
        self.groups.get(&id)
    }

    /// lookup_domain(F_CONFIG): look past upstream/local-only tiers for a
    /// configured address RR, while retaining the late dotless override.
    pub(super) fn has_configured_address(&self, name: &Name) -> bool {
        let query = dotted_name(name);
        let selected = self.rules.iter().find(|bucket| {
            !bucket.representative().dotless
                && (!bucket.literals.is_empty() || bucket.zeros != 0)
                && bucket.matched_pattern(&query).is_some()
        });
        if !query.is_empty()
            && !query.contains(&b'.')
            && selected.is_none_or(|bucket| bucket.representative().suffix.is_empty())
        {
            if let Some(dotless) = self
                .rules
                .iter()
                .find(|bucket| bucket.representative().dotless)
            {
                return !dotless.literals.is_empty() || dotless.zeros != 0;
            }
        }
        selected.is_some()
    }

    pub fn groups(&self) -> impl Iterator<Item = &ServerGroup> {
        self.groups.values()
    }

    /// Per-connection fork-equivalent metadata, including resolved scope IDs.
    /// Reloading the parent later cannot mutate an existing TCP connection.
    pub fn snapshot(&self) -> Self {
        Self {
            rules: self.rules.clone(),
            groups: self
                .dispatcher_groups()
                .into_iter()
                .map(|group| (group.id, group))
                .collect(),
            default_group: self.default_group,
            next_group: self.next_group,
            source_endpoints: self.source_endpoints.clone(),
        }
    }

    pub fn server_label(&self, id: ServerId) -> String {
        let Some(endpoint) = self.source_endpoints.get(&id) else {
            return String::new();
        };
        let ServerHost::Address(address) = endpoint.host else {
            return String::new();
        };
        let mut label = address.to_string();
        if address.is_ipv6() && endpoint.scope_id.is_some_and(|index| index != 0) {
            if let Some(scope) = &endpoint.scope {
                label.push('%');
                label.push_str(&String::from_utf8_lossy(scope));
            }
        }
        label
    }

    pub fn source_bindings(&self, query_port: u16) -> HashMap<ServerId, SourceSpec> {
        self.source_endpoints
            .iter()
            .map(|(id, endpoint)| (*id, SourceSpec::endpoint(endpoint, query_port)))
            .collect()
    }

    /// Move groups to a dispatcher. Clone route metadata first if further
    /// selection is required; the current isolated adapter has no I/O owner.
    pub fn into_groups(self) -> Vec<ServerGroup> {
        let mut groups: Vec<_> = self.groups.into_values().collect();
        crate::sorting::sort_by(&mut groups, |a, b| a.id.0.cmp(&b.id.0));
        groups
    }

    /// Copy the immutable server configuration into a dispatcher while
    /// retaining this table for subsequent query selection.  Forwarding
    /// health counters intentionally start fresh in the dispatcher.
    pub fn dispatcher_groups(&self) -> Vec<ServerGroup> {
        let mut groups: Vec<_> = self
            .groups
            .values()
            .map(|group| {
                ServerGroup::new(
                    group.id,
                    group.servers.clone(),
                    group.strict_order,
                    group.all_servers,
                )
            })
            .collect();
        crate::sorting::sort_by(&mut groups, |a, b| a.id.0.cmp(&b.id.0));
        groups
    }
}

pub(super) fn validate_endpoint(endpoint: &ServerEndpoint) -> Result<SocketAddr, RoutingError> {
    let address = match &endpoint.host {
        ServerHost::Address(address) => *address,
        ServerHost::Name(name) => return Err(RoutingError::UnresolvedHostname(name.clone())),
    };
    if let Some(scope) = &endpoint.scope {
        if address.is_ipv6() && endpoint.scope_id.is_none() {
            return Err(RoutingError::UnresolvedScope(scope.clone()));
        }
    }
    Ok(match address {
        IpAddr::V4(address) => SocketAddr::new(IpAddr::V4(address), endpoint.port),
        IpAddr::V6(address) => {
            std::net::SocketAddrV6::new(address, endpoint.port, 0, endpoint.scope_id.unwrap_or(0))
                .into()
        }
    })
}

fn local_addresses(literals: &[IpAddr], zeros: usize, family: QueryFamily) -> Vec<IpAddr> {
    let v6 = || {
        literals
            .iter()
            .copied()
            .filter(IpAddr::is_ipv6)
            .collect::<Vec<_>>()
    };
    let v4 = || {
        literals
            .iter()
            .copied()
            .filter(IpAddr::is_ipv4)
            .collect::<Vec<_>>()
    };
    let selected = match family {
        QueryFamily::V4 => v4(),
        QueryFamily::V6 => v6(),
        QueryFamily::Any => {
            let addresses = v6();
            if addresses.is_empty() {
                v4()
            } else {
                addresses
            }
        }
        QueryFamily::Other => return Vec::new(),
    };
    if !selected.is_empty() {
        return selected;
    }
    let mut selected = Vec::new();
    if matches!(family, QueryFamily::V4 | QueryFamily::Any) {
        selected.extend(std::iter::repeat_n(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            zeros,
        ));
    }
    if matches!(family, QueryFamily::V6 | QueryFamily::Any) {
        selected.extend(std::iter::repeat_n(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            zeros,
        ));
    }
    selected
}

fn dotted_name(name: &Name) -> Vec<u8> {
    let mut dotted = Vec::with_capacity(name.as_wire().len());
    let mut offset = 0;
    let wire = name.as_wire();
    while wire[offset] != 0 {
        let length = wire[offset] as usize;
        if !dotted.is_empty() {
            dotted.push(b'.');
        }
        dotted.extend_from_slice(&wire[offset + 1..offset + 1 + length]);
        offset += length + 1;
    }
    dotted.make_ascii_lowercase();
    dotted
}

fn matches_domain(query: &[u8], pattern: &DomainPattern) -> bool {
    if pattern.dotless && (query.is_empty() || query.contains(&b'.')) {
        return false;
    }
    let suffix = &pattern.suffix;
    if suffix.is_empty() {
        return true;
    }
    if pattern.wildcard {
        query.len() >= suffix.len()
            && query.ends_with(suffix)
            && (!pattern.wildcard_dot || query.len() > suffix.len())
    } else {
        query == suffix
            || (query.len() > suffix.len()
                && query.ends_with(suffix)
                && query[query.len() - suffix.len() - 1] == b'.')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;

    fn table(lines: &[&str]) -> RoutingTable {
        let mut config = DnsConfig::default();
        for line in lines {
            config
                .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
                .unwrap();
        }
        RoutingTable::from_config(&config, &[]).unwrap()
    }
    fn route(table: &RoutingTable, name: &str, qtype: u16) -> RouteSelection {
        table.select(&Name::from_ascii(name).unwrap(), qtype, CLASS_IN, false)
    }
    fn endpoints(table: &RoutingTable, route: RouteSelection) -> Vec<SocketAddr> {
        table
            .group(route.group.unwrap())
            .unwrap()
            .servers
            .iter()
            .map(|server| server.address)
            .collect()
    }
    fn addresses(route: RouteSelection) -> Vec<IpAddr> {
        match route.reason {
            RouteReason::LocalAddress { addresses } => addresses,
            other => panic!("expected local addresses, got {other:?}"),
        }
    }

    #[test]
    fn local_ownership_precedes_domain_rules() {
        let table = table(&["server=/test/192.0.2.53"]);
        assert_eq!(
            table
                .select(&Name::from_ascii("a.test").unwrap(), TYPE_A, CLASS_IN, true)
                .reason,
            RouteReason::LocalRecord
        );
    }

    #[test]
    fn default_redirect_shares_all_global_servers_and_preserves_reload_identities() {
        let mut config = DnsConfig::default();
        for line in [
            "server=192.0.2.1",
            "server=/redirect.test/#",
            "address=/#/192.0.2.77",
        ] {
            config
                .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
                .unwrap();
        }
        let mut sources = ServerSources::new(&config.rules);
        sources.replace(
            Source::Resolv,
            vec![SourceRule::resolver("192.0.2.2:53".parse().unwrap(), 1)],
        );
        let first = RoutingTable::from_sources(&config, &sources, None).unwrap();
        let redirected = route(&first, "x.redirect.test", 1);
        let group = first.group(redirected.group.unwrap()).unwrap();
        let ids: Vec<_> = group.servers.iter().map(|server| server.id).collect();
        assert_eq!(
            endpoints(&first, redirected),
            vec![
                "192.0.2.1:53".parse().unwrap(),
                "192.0.2.2:53".parse().unwrap()
            ]
        );
        assert_eq!(
            addresses(route(&first, "ordinary.test", 1)),
            vec!["192.0.2.77".parse::<IpAddr>().unwrap()]
        );
        assert!(sources
            .replace(
                Source::Resolv,
                vec![SourceRule::resolver("192.0.2.9:53".parse().unwrap(), 1)]
            )
            .is_empty());
        let next = RoutingTable::from_sources(&config, &sources, Some(&first)).unwrap();
        let selected = next
            .group(route(&next, "x.redirect.test", 1).group.unwrap())
            .unwrap();
        assert_eq!(selected.id, group.id);
        assert_eq!(
            selected
                .servers
                .iter()
                .map(|server| server.id)
                .collect::<Vec<_>>(),
            ids
        );
        assert_eq!(selected.servers[1].address, "192.0.2.9:53".parse().unwrap());
    }

    #[test]
    fn local_family_priority_and_shorter_suffix_fallback() {
        let table = table(&[
            "address=/example.test/192.0.2.7",
            "address=/example.test/2001:db8::7",
            "address=/example.test/#",
            "server=/test/192.0.2.53",
        ]);
        assert_eq!(
            addresses(route(&table, "x.example.test", TYPE_A)),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            addresses(route(&table, "x.example.test", TYPE_AAAA)),
            vec!["2001:db8::7".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            addresses(route(&table, "x.example.test", TYPE_ANY)),
            vec!["2001:db8::7".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            endpoints(&table, route(&table, "x.example.test", 16)),
            vec!["192.0.2.53:53".parse().unwrap()]
        );
        let fallback = table_for_fallback();
        let selection = route(&fallback, "x.example.test", TYPE_AAAA);
        assert!(
            matches!(&selection.reason, RouteReason::Upstream { pattern, .. } if pattern.suffix == b"test")
        );
        assert_eq!(
            endpoints(&fallback, selection),
            vec!["192.0.2.53:53".parse().unwrap()]
        );
    }
    fn table_for_fallback() -> RoutingTable {
        table(&["address=/example.test/192.0.2.7", "server=/test/192.0.2.53"])
    }

    #[test]
    fn family_mismatch_uses_upstream_in_the_same_domain_tier() {
        let table = table(&[
            "address=/child.example.test/2001:db8::9",
            "server=/child.example.test/192.0.2.53",
            "address=/example.test/192.0.2.7",
        ]);
        assert_eq!(
            endpoints(&table, route(&table, "child.example.test", TYPE_A)),
            vec!["192.0.2.53:53".parse().unwrap()]
        );
    }

    #[test]
    fn empty_wildcard_is_after_the_ordinary_default_tier() {
        let literal = "address=/*./192.0.2.77";
        let alone = table(&[literal]);
        assert_eq!(
            addresses(route(&alone, "example.test", TYPE_A)),
            vec!["192.0.2.77".parse::<IpAddr>().unwrap()]
        );
        for rules in [
            vec![literal, "server=192.0.2.53"],
            vec!["server=192.0.2.53", literal],
        ] {
            let with_default = table(&rules);
            assert_eq!(
                endpoints(&with_default, route(&with_default, "example.test", TYPE_A)),
                vec!["192.0.2.53:53".parse().unwrap()]
            );
        }
    }

    #[test]
    fn upstream_transport_family_is_independent_and_order_is_preserved() {
        let table = table(&[
            "strict-order",
            "all-servers",
            "server=/test/192.0.2.53#5300",
            "server=/test/2001:db8::53#5301",
        ]);
        for qtype in [TYPE_A, TYPE_AAAA, TYPE_ANY, 16] {
            let selection = route(&table, "a.test", qtype);
            let group = table.group(selection.group.unwrap()).unwrap();
            assert!(group.strict_order && group.all_servers);
            assert_eq!(
                endpoints(&table, selection),
                vec![
                    "192.0.2.53:5300".parse().unwrap(),
                    "[2001:db8::53]:5301".parse().unwrap()
                ]
            );
        }
        assert_eq!(table.groups().count(), 1);
        assert_eq!(table.into_groups().len(), 1);
    }

    #[test]
    fn nonwildcard_priority_and_character_wildcards() {
        let table = table(&[
            "server=/*example.test/192.0.2.54",
            "server=/example.test/192.0.2.53",
        ]);
        let exact = route(&table, "X.Example.Test", TYPE_A);
        assert!(
            matches!(&exact.reason, RouteReason::Upstream { pattern, .. } if !pattern.wildcard)
        );
        assert_eq!(
            endpoints(&table, exact),
            vec!["192.0.2.53:53".parse().unwrap()]
        );
        assert_eq!(
            endpoints(&table, route(&table, "badexample.test", TYPE_A)),
            vec!["192.0.2.54:53".parse().unwrap()]
        );
        let fallback = table_for_fallback();
        assert!(
            matches!(route(&fallback, "badexample.test", TYPE_A).reason, RouteReason::Upstream { pattern, .. } if pattern.suffix == b"test")
        );
    }

    #[test]
    fn wildcard_dot_preserves_label_boundary() {
        let table = table(&["server=/*.example.test/192.0.2.53"]);
        assert!(route(&table, "x.example.test", TYPE_A).group.is_some());
        for name in ["example.test", "badexample.test"] {
            assert_eq!(
                route(&table, name, TYPE_A).reason,
                RouteReason::NoMatchingRule
            );
        }
    }

    #[test]
    fn local_only_and_zero_tiers_precede_upstream() {
        let table = table(&[
            "server=/local.test/192.0.2.53",
            "local=/local.test/",
            "address=/zero.test/#",
            "server=/zero.test/192.0.2.53",
        ]);
        assert_eq!(
            route(&table, "a.local.test", TYPE_A).reason,
            RouteReason::LocalOnly
        );
        assert_eq!(
            table
                .select(&Name::from_ascii("a.local.test").unwrap(), TYPE_A, 3, false)
                .reason,
            RouteReason::LocalOnly
        );
        assert_eq!(
            addresses(route(&table, "zero.test", TYPE_ANY)),
            vec![
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            ]
        );
        assert!(route(&table, "zero.test", 16).group.is_some());
    }

    #[test]
    fn local_default_precedes_upstream_and_default_resolver_rule_uses_input() {
        let mut config = DnsConfig::default();
        for line in [
            "server=192.0.2.53",
            "address=/#/192.0.2.7",
            "server=/test/192.0.2.54",
            "server=/test/#",
        ] {
            config
                .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
                .unwrap();
        }
        let table =
            RoutingTable::from_config(&config, &["192.0.2.9:5353".parse().unwrap()]).unwrap();
        assert_eq!(
            addresses(route(&table, "other", TYPE_A)),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            endpoints(&table, route(&table, "a.test", TYPE_AAAA)),
            vec![
                "192.0.2.53:53".parse().unwrap(),
                "192.0.2.9:5353".parse().unwrap()
            ]
        );
    }

    #[test]
    fn dotless_overrides_default_but_not_specific_domain() {
        let table = table(&[
            "server=192.0.2.53",
            "server=//192.0.2.54",
            "server=/router/192.0.2.55",
        ]);
        assert_eq!(
            endpoints(&table, route(&table, "other", TYPE_A)),
            vec!["192.0.2.54:53".parse().unwrap()]
        );
        assert_eq!(
            endpoints(&table, route(&table, "router", TYPE_A)),
            vec!["192.0.2.55:53".parse().unwrap()]
        );
        for name in ["other.test", ""] {
            assert_eq!(
                endpoints(&table, route(&table, name, TYPE_A)),
                vec!["192.0.2.53:53".parse().unwrap()]
            );
        }
    }

    #[test]
    fn ds_parent_and_dnskey_skip_dotless() {
        let table = table(&[
            "server=192.0.2.53",
            "server=//192.0.2.54",
            "server=/child.test/192.0.2.55",
            "server=/test/192.0.2.56",
        ]);
        assert_eq!(
            endpoints(&table, route(&table, "child.test", TYPE_DS)),
            vec!["192.0.2.56:53".parse().unwrap()]
        );
        assert_eq!(
            endpoints(&table, route(&table, "child.test", TYPE_DNSKEY)),
            vec!["192.0.2.55:53".parse().unwrap()]
        );
        for qtype in [TYPE_DS, TYPE_DNSKEY] {
            assert_eq!(
                endpoints(&table, route(&table, "single", qtype)),
                vec!["192.0.2.53:53".parse().unwrap()]
            );
        }
    }

    #[test]
    fn unresolved_platform_inputs_are_rejected_and_resolved_defaults_are_used() {
        for (line, expected) in [
            (
                "server=/test/resolver.example",
                RoutingError::UnresolvedHostname(b"resolver.example".to_vec()),
            ),
            (
                "server=/test/fe80::1%wan",
                RoutingError::UnresolvedScope(b"wan".to_vec()),
            ),
        ] {
            let mut config = DnsConfig::default();
            config
                .apply(&lex_line(line.as_bytes()).unwrap().unwrap())
                .unwrap();
            assert!(
                matches!(RoutingTable::from_config(&config, &[]), Err(error) if error == expected)
            );
        }
        let mut bound = DnsConfig::default();
        bound
            .apply(
                &lex_line(b"server=/bound/192.0.2.53@lo@127.0.0.9#34004")
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
        bound
            .apply(&lex_line(b"server=/implicit/192.0.2.54").unwrap().unwrap())
            .unwrap();
        bound
            .apply(&lex_line(b"server=/scoped/fe80::53%lo").unwrap().unwrap())
            .unwrap();
        let RuleTarget::Upstream(scoped) = &mut bound.rules[2].target else {
            unreachable!()
        };
        scoped.scope_id = Some(17);
        let bound_table = RoutingTable::from_config(&bound, &[]).unwrap();
        let bindings = bound_table.source_bindings(34003);
        let explicit = &bindings[&ServerId(1)];
        assert_eq!(explicit.address, "127.0.0.9:34004".parse().unwrap());
        assert_eq!(explicit.interface, b"lo");
        assert_eq!(
            explicit.ifindex,
            crate::config::dns::endpoints::scope_index(b"lo").unwrap_or(0)
        );
        assert_eq!(
            bindings[&ServerId(2)].address,
            "0.0.0.0:34003".parse().unwrap()
        );
        assert_eq!(
            endpoints(&bound_table, route(&bound_table, "x.scoped", TYPE_A)),
            vec![std::net::SocketAddrV6::new("fe80::53".parse().unwrap(), 53, 0, 17).into()]
        );
        let mut config = DnsConfig::default();
        config
            .apply(&lex_line(b"server=/test/#").unwrap().unwrap())
            .unwrap();
        let table =
            RoutingTable::from_config(&config, &["192.0.2.53:53".parse().unwrap()]).unwrap();
        assert_eq!(
            endpoints(&table, route(&table, "a.test", TYPE_AAAA)),
            vec!["192.0.2.53:53".parse().unwrap()]
        );
    }
}

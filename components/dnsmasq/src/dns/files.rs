//! Resolver and servers-file state from dnsmasq.c::poll_resolv and option.c.
//! File readiness and publication belong to the single service owner. These
//! parsers perform no I/O and keep file-origin rows separate from inline rules.

use super::forward::ServerId;
use crate::config::dns::{
    DnsConfig, DomainPattern, RuleTarget, ServerEndpoint, ServerHost, ServerRule,
};
use crate::config::{lex_line, validate_directive, Error};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::PathBuf;

#[cfg(target_os = "linux")]
#[path = "files_runtime.rs"]
mod runtime;
#[cfg(target_os = "linux")]
pub use runtime::{DnsFiles, FileDiagnostic, FileStep, ReloadReason, SourceUpdate};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileStamp {
    /// stat.st_mtime, in whole seconds, as used by the exact image.
    pub modified: i64,
    pub inode: u64,
}

#[derive(Debug)]
struct ResolverFile {
    path: PathBuf,
    stamp: FileStamp,
    logged: bool,
}

#[derive(Debug, Default)]
pub struct ResolverSelection {
    files: Vec<ResolverFile>,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Selection {
    pub selected: Option<usize>,
    /// Missing-file warnings are suppressed until that path exists again.
    pub warn_missing: Vec<usize>,
}

impl ResolverSelection {
    /// Input paths already have C's newest-option-first list order.
    pub fn new(paths: &[PathBuf]) -> Self {
        Self {
            files: paths
                .iter()
                .map(|path| ResolverFile {
                    path: path.clone(),
                    stamp: FileStamp {
                        modified: 0,
                        inode: 0,
                    },
                    logged: false,
                })
                .collect(),
        }
    }

    pub fn paths(&self) -> impl Iterator<Item = &std::path::Path> {
        self.files.iter().map(|file| file.path.as_path())
    }

    pub fn path(&self, index: usize) -> &std::path::Path {
        &self.files[index].path
    }

    /// All metadata is captured by the owner before this pure selection.
    /// A forced event considers every file, not just the changed basename.
    pub fn select(&mut self, force: bool, stamps: &[Option<FileStamp>]) -> Selection {
        assert_eq!(self.files.len(), stamps.len());
        let mut result = Selection::default();
        let mut latest = 0;
        for (index, (file, stamp)) in self.files.iter_mut().zip(stamps).enumerate() {
            let Some(stamp) = stamp else {
                if force {
                    file.stamp.modified = 0;
                    continue;
                }
                if !file.logged {
                    result.warn_missing.push(index);
                }
                file.logged = true;
                if file.stamp.modified != 0 {
                    let mut forced = self.select(true, stamps);
                    forced.warn_missing = result.warn_missing;
                    return forced;
                }
                continue;
            };
            file.logged = false;
            if force || *stamp != file.stamp {
                file.stamp = *stamp;
                if stamp.modified > latest {
                    latest = stamp.modified;
                    result.selected = Some(index);
                }
            }
        }
        result
    }

    /// Failed/empty reads arrange a retry on the next actual poll trigger.
    /// HAVE_INOTIFY does not install a periodic retry timer.
    pub fn retry_on_next_trigger(&mut self, index: usize) {
        self.files[index].stamp.modified = 0;
    }
}

/// network.c::reload_servers uses strtok, not the config-file lexer. An
/// adjacent '#' is part of an address token; trailing tokens are ignored.
pub fn resolver_line(
    line: &[u8],
    interface_index: impl FnOnce(&[u8]) -> u32,
) -> Option<SocketAddr> {
    let line = line.split(|byte| *byte == 0).next()?;
    let mut fields = line
        .split(|byte| b" \t\n\r".contains(byte))
        .filter(|field| !field.is_empty());
    if !matches!(fields.next()?, b"nameserver" | b"server") {
        return None;
    }
    let token = fields.next()?;
    if let Ok(address) = std::str::from_utf8(token).ok()?.parse::<Ipv4Addr>() {
        return Some(SocketAddr::new(IpAddr::V4(address), 53));
    }
    let mut parts = token.splitn(2, |byte| *byte == b'%');
    let address = std::str::from_utf8(parts.next()?)
        .ok()?
        .parse::<Ipv6Addr>()
        .ok()?;
    let scope = parts.next().map_or(0, interface_index);
    Some(SocketAddr::V6(SocketAddrV6::new(address, 53, 0, scope)))
}

/// Hard-option parsing logs errors per line and continues. Retain unresolved
/// endpoint syntax for its owning resolver, never turn it into a skipped row.
pub fn server_line_with_origin(line: &[u8]) -> Result<(Vec<ServerRule>, bool), Error> {
    let Some(directive) = lex_line(line)? else {
        return Ok((Vec::new(), false));
    };
    validate_directive(&directive)?;
    if !matches!(directive.name.as_slice(), b"server" | b"rev-server") {
        return Err(Error("illegal option"));
    }
    let reverse = directive.name == b"rev-server";
    let mut config = DnsConfig::default();
    config.apply(&directive)?;
    Ok((config.rules, reverse))
}

pub fn server_line(line: &[u8]) -> Result<Vec<ServerRule>, Error> {
    Ok(server_line_with_origin(line)?.0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    Inline,
    Resolv,
    ServersFile,
}

#[derive(Clone, Debug)]
pub struct SourceRule {
    pub rule: ServerRule,
    pub reverse: bool,
    /// Includes the resolved IPv6 scope from a resolver file. Configured
    /// server endpoints may remain unresolved until endpoint preparation.
    pub address: Option<SocketAddr>,
    pub line: usize,
}

impl SourceRule {
    pub fn resolver(address: SocketAddr, line: usize) -> Self {
        Self {
            rule: ServerRule {
                domain: DomainPattern {
                    suffix: Vec::new(),
                    wildcard: false,
                    wildcard_dot: false,
                    dotless: false,
                },
                target: RuleTarget::Upstream(ServerEndpoint {
                    host: ServerHost::Address(address.ip()),
                    port: address.port(),
                    scope: None,
                    scope_id: None,
                    source: None,
                }),
            },
            reverse: false,
            address: Some(address),
            line,
        }
    }

    pub fn configured(rule: ServerRule, line: usize) -> Self {
        Self::configured_reverse(rule, line, false)
    }

    pub fn configured_reverse(rule: ServerRule, line: usize, reverse: bool) -> Self {
        Self {
            rule,
            reverse,
            address: None,
            line,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SourcedRule {
    pub source: Source,
    /// Only actual upstream servers own a transport identity. Local-only
    /// and USE_RESOLV markers live on C's separate local_domains list.
    pub server: Option<ServerId>,
    pub value: SourceRule,
}

/// C mark_servers/add_update_server/cleanup_servers ordering. A reused
/// marked slot is selected by domain alone, even if its endpoint changed.
/// Keep the resulting ServerIds when reconciling the live forwarding table.
#[derive(Default, Debug)]
pub struct ServerSources {
    rules: Vec<SourcedRule>,
    next_server: u64,
}

impl ServerSources {
    pub fn new(inline: &[ServerRule]) -> Self {
        let mut sources = Self::default();
        sources.replace(
            Source::Inline,
            inline
                .iter()
                .cloned()
                .map(|rule| SourceRule::configured(rule, 0))
                .collect(),
        );
        sources
    }

    pub fn rules(&self) -> &[SourcedRule] {
        &self.rules
    }

    /// Local answers and newly accepted TCP clients see the same active rule
    /// sources. Original inline configuration remains immutable in the owner.
    pub fn effective_config(&self, base: &DnsConfig) -> DnsConfig {
        let mut config = base.clone();
        config.rules = self
            .rules
            .iter()
            .map(|entry| entry.value.rule.clone())
            .collect();
        config
    }

    /// check_servers removes unusable upstream rows from their owning list;
    /// local-only/default/address rules are never affected by that scan.
    pub fn remove_server_ids(&mut self, ids: &[ServerId]) {
        self.rules
            .retain(|entry| !entry.server.is_some_and(|id| ids.contains(&id)));
    }

    pub fn retain_servers(&mut self, mut keep: impl FnMut(&SourceRule) -> bool) -> Vec<ServerId> {
        let mut removed = Vec::new();
        self.rules.retain(|entry| {
            if let Some(server) = entry.server {
                if !keep(&entry.value) {
                    removed.push(server);
                    return false;
                }
            }
            true
        });
        removed
    }

    /// Call only after a successful source open; even zero valid rows must
    /// replace the old bank. Returned IDs are genuinely retired C slots.
    pub fn replace(&mut self, source: Source, rows: Vec<SourceRule>) -> Vec<ServerId> {
        let mut marked = Vec::new();
        self.rules.retain(|entry| {
            if entry.source != source {
                return true;
            }
            if entry.server.is_some() {
                marked.push(entry.clone());
            }
            false
        });
        for value in rows {
            let server = if matches!(value.rule.target, RuleTarget::Upstream(_)) {
                let reusable = marked.iter().position(|entry| {
                    entry
                        .value
                        .rule
                        .domain
                        .suffix
                        .eq_ignore_ascii_case(&value.rule.domain.suffix)
                });
                match reusable {
                    Some(index) => marked.remove(index).server,
                    None => {
                        self.next_server += 1;
                        Some(ServerId(self.next_server))
                    }
                }
            } else {
                None
            };
            self.rules.push(SourcedRule {
                source,
                server,
                value,
            });
        }
        marked
            .into_iter()
            .filter_map(|entry| entry.server)
            .collect()
    }
}

#[cfg(feature = "process-test-support")]
#[doc(hidden)]
pub use runtime::run_process_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(modified: i64, inode: u64) -> Option<FileStamp> {
        Some(FileStamp { modified, inode })
    }

    #[test]
    fn resolver_selection_is_latest_changed_with_strict_ties_and_missing_fallback() {
        let mut files = ResolverSelection::new(&["newest-option".into(), "earlier-option".into()]);
        assert_eq!(
            files.select(true, &[stamp(10, 1), stamp(10, 2)]).selected,
            Some(0)
        );
        assert_eq!(
            files.select(false, &[stamp(10, 1), stamp(10, 2)]).selected,
            None
        );
        assert_eq!(
            files.select(false, &[stamp(10, 1), stamp(11, 2)]).selected,
            Some(1)
        );
        // A close-write to the older file still forces consideration of all.
        assert_eq!(
            files.select(true, &[stamp(10, 3), stamp(11, 2)]).selected,
            Some(1)
        );
        let fallback = files.select(false, &[stamp(10, 3), None]);
        assert_eq!(
            fallback,
            Selection {
                selected: Some(0),
                warn_missing: vec![1]
            }
        );
        assert_eq!(
            files.select(false, &[stamp(10, 3), None]).warn_missing,
            Vec::<usize>::new()
        );
        files.retry_on_next_trigger(0);
        assert_eq!(files.select(false, &[stamp(10, 3), None]).selected, Some(0));
        assert_eq!(
            files.select(true, &[stamp(0, 4), stamp(-1, 5)]).selected,
            None
        );
    }

    #[test]
    fn resolver_tokens_are_not_config_lexing_and_keep_scope() {
        for line in [
            b"nameserver 192.0.2.1 # comment".as_slice(),
            b"server\t192.0.2.1\r\n",
        ] {
            assert_eq!(
                resolver_line(line, |_| 0),
                Some("192.0.2.1:53".parse().unwrap())
            );
        }
        for line in [
            "nameserver 192.0.2.1#comment",
            "nameserver 192.0.2.1%eth0",
            "Nameserver 192.0.2.1",
            "nameserver resolver.test",
            "search 192.0.2.1",
        ] {
            assert_eq!(resolver_line(line.as_bytes(), |_| 9), None);
        }
        assert_eq!(
            resolver_line(b"nameserver fe80::1%eth0", |name| {
                assert_eq!(name, b"eth0");
                9
            }),
            Some("[fe80::1%9]:53".parse().unwrap())
        );
        assert_eq!(
            resolver_line(b"nameserver fe80::1%unknown", |_| 0),
            Some("[fe80::1]:53".parse().unwrap())
        );
    }

    #[test]
    fn restricted_server_rows_keep_endpoint_dependencies_and_line_errors() {
        assert_eq!(
            server_line(b"local=/test/").unwrap_err(),
            Error("illegal option")
        );
        assert_eq!(
            server_line(b"conf-file=/must-not-open").unwrap_err(),
            Error("illegal option")
        );
        assert_eq!(
            server_line(b"server").unwrap_err(),
            Error("missing parameter")
        );
        assert_eq!(
            server_line(b"bogus-option=x").unwrap_err(),
            Error("bad option")
        );
        assert!(server_line(b"server=/test/host.example@eth0").is_ok());
        assert_eq!(
            server_line(b"rev-server=192.0.2.0/24,192.0.2.53")
                .unwrap()
                .len(),
            1
        );
        assert!(server_line(b"  # comment").unwrap().is_empty());
    }

    #[test]
    fn source_update_reuses_domain_slots_and_moves_bank_after_other_sources() {
        let inline = server_line(b"server=192.0.2.1").unwrap();
        let mut sources = ServerSources::new(&inline);
        let a = |ip: &str| SourceRule::resolver(ip.parse().unwrap(), 1);
        assert!(sources
            .replace(Source::Resolv, vec![a("192.0.2.2:53"), a("192.0.2.3:53")])
            .is_empty());
        let old_ids: Vec<_> = sources.rules().iter().map(|entry| entry.server).collect();
        sources.replace(Source::ServersFile, vec![a("192.0.2.4:53")]);
        assert_eq!(
            sources.replace(Source::Resolv, vec![a("192.0.2.9:53")]),
            vec![old_ids[2].unwrap()]
        );
        let rules = sources.rules();
        assert_eq!(
            rules.iter().map(|entry| entry.source).collect::<Vec<_>>(),
            vec![Source::Inline, Source::ServersFile, Source::Resolv]
        );
        assert_eq!(rules[2].server, old_ids[1]);
        assert_eq!(sources.replace(Source::ServersFile, Vec::new()).len(), 1);
        assert_eq!(sources.rules()[0].server, old_ids[0]);
    }
}

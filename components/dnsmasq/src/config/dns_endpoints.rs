//! Exact option.c hostname expansion. Only startup or the isolated resolver
//! child may call the blocking libc resolver; live file parsing stays pure.
use super::{Error, RuleTarget, ServerEndpoint, ServerHost, ServerRule};
use std::net::IpAddr;
#[cfg(test)]
use std::net::Ipv4Addr;

pub fn addresses(name: &[u8]) -> Result<Vec<IpAddr>, Error> {
    dnsmasq_platform::resolver::addresses(name).map_err(Error)
}

pub fn scope_index(name: &[u8]) -> Result<u32, Error> {
    let index = dnsmasq_platform::interfaces::interface_index(name);
    if index == 0 {
        Err(Error("bad interface name"))
    } else {
        Ok(index)
    }
}

/// Partial results matter for runtime servers-file: a later bad expansion
/// logs its error while already accepted address rows remain in the bank.
#[derive(Default)]
pub struct Expansion {
    pub rules: Vec<ServerRule>,
    /// Index in this directive, independent of duplicate domain spellings.
    pub origins: Vec<usize>,
    pub error: Option<Error>,
}

pub fn resolve_rules(rules: &[ServerRule], reverse: bool) -> Expansion {
    resolve_with(rules, reverse, addresses, scope_index)
}

fn resolve_with(
    rules: &[ServerRule],
    reverse: bool,
    resolve: impl FnOnce(&[u8]) -> Result<Vec<IpAddr>, Error>,
    scope: impl Fn(&[u8]) -> Result<u32, Error>,
) -> Expansion {
    let mut result = Expansion::default();
    let Some(RuleTarget::Upstream(endpoint)) = rules.first().map(|rule| &rule.target) else {
        result.rules.extend_from_slice(rules);
        result.origins.extend(0..rules.len());
        return result;
    };
    let named = matches!(endpoint.host, ServerHost::Name(_));
    let addresses = match &endpoint.host {
        ServerHost::Address(address) => Ok(vec![*address]),
        ServerHost::Name(name) => resolve(name),
    };
    let addresses = match addresses {
        Ok(addresses) => addresses,
        Err(error) => {
            result.error = Some(error);
            return result;
        }
    };
    // Regular server/local use address-outer/domain-inner iteration. Reverse
    // expansion is domain-outer. C frees its addrinfo list after the first
    // reverse variant, then reuses the last resolved address for later ones;
    // preserve those rule bytes without reproducing its repeated free.
    let mut pairs = Vec::new();
    if reverse {
        for (index, rule) in rules.iter().enumerate() {
            let selected = if named && index > 0 {
                &addresses[addresses.len().saturating_sub(1)..]
            } else {
                &addresses[..]
            };
            pairs.extend(selected.iter().map(|address| (*address, index, rule)));
        }
    } else {
        for address in &addresses {
            pairs.extend(
                rules
                    .iter()
                    .enumerate()
                    .map(|(index, rule)| (*address, index, rule)),
            );
        }
    }
    for (address, index, rule) in pairs {
        let mut resolved: ServerEndpoint = endpoint.clone();
        resolved.host = ServerHost::Address(address);
        resolved.scope_id = if address.is_ipv6() {
            match endpoint.scope.as_ref().map(|name| scope(name)).transpose() {
                Ok(value) => value,
                Err(error) => {
                    result.error = Some(error);
                    break;
                }
            }
        } else {
            None
        };
        if !reverse
            && named
            && endpoint
                .source
                .as_ref()
                .and_then(|source| source.address)
                .is_some_and(|source| source.is_ipv4() != address.is_ipv4())
        {
            continue;
        }
        result.origins.push(index);
        result.rules.push(ServerRule {
            domain: rule.domain.clone(),
            target: RuleTarget::Upstream(resolved),
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{dns::parse_rules, EncodedArg};
    #[test]
    fn expansion_preserves_address_then_domain_order_and_filters_named_source_family() {
        let rules = parse_rules(
            b"server",
            &EncodedArg::command_line(b"/a.test/b.test/upstream.test@192.0.2.1"),
        )
        .unwrap();
        let v4: IpAddr = "192.0.2.53".parse().unwrap();
        let v6: IpAddr = "2001:db8::53".parse().unwrap();
        let result = resolve_with(&rules, false, |_| Ok(vec![v6, v4, v4]), |_| unreachable!());
        assert!(result.error.is_none());
        assert_eq!(
            result
                .rules
                .iter()
                .map(|r| r.domain.suffix.as_slice())
                .collect::<Vec<_>>(),
            [b"a.test", b"b.test", b"a.test", b"b.test"]
        );
        assert!(result.rules.iter().all(
            |r| matches!(&r.target, RuleTarget::Upstream(e) if e.host == ServerHost::Address(v4))
        ));
    }
    #[test]
    fn bad_later_scope_retains_earlier_ipv4_rows_for_file_errors() {
        let rules =
            parse_rules(b"server", &EncodedArg::command_line(b"host.test%missing")).unwrap();
        let result = resolve_with(
            &rules,
            false,
            |_| {
                Ok(vec![
                    "192.0.2.53".parse().unwrap(),
                    "2001:db8::53".parse().unwrap(),
                ])
            },
            |_| Err(Error("bad interface name")),
        );
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.error, Some(Error("bad interface name")));
    }
    #[test]
    fn libc_numeric_name_uses_datagram_addresses_without_triplicates() {
        assert_eq!(
            addresses(b"127.0.0.1").unwrap(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }
}

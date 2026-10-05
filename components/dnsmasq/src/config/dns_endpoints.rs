//! Exact option.c hostname expansion. Only startup or the isolated resolver
//! child may call the blocking libc resolver; live file parsing stays pure.
use super::{Error, RuleTarget, ServerEndpoint, ServerHost, ServerRule};
use std::ffi::{c_char, c_int, CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

#[cfg(target_os = "linux")]
const AF_INET6: c_int = 10;
#[cfg(target_os = "macos")]
const AF_INET6: c_int = 30;
#[cfg(target_os = "linux")]
const AI_ADDRCONFIG: c_int = 0x20;
#[cfg(target_os = "macos")]
const AI_ADDRCONFIG: c_int = 0x400;
#[cfg(target_os = "linux")]
const EAI_AGAIN: c_int = -3;
#[cfg(target_os = "macos")]
const EAI_AGAIN: c_int = 2;

#[repr(C)]
struct AddrInfo {
    flags: c_int,
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    address_length: u32,
    #[cfg(target_os = "macos")]
    canonical: *mut c_char,
    address: *mut u8,
    #[cfg(target_os = "linux")]
    canonical: *mut c_char,
    next: *mut AddrInfo,
}

unsafe extern "C" {
    fn getaddrinfo(
        node: *const c_char,
        service: *const c_char,
        hints: *const AddrInfo,
        result: *mut *mut AddrInfo,
    ) -> c_int;
    fn freeaddrinfo(result: *mut AddrInfo);
    fn gai_strerror(error: c_int) -> *const c_char;
    fn if_nametoindex(name: *const c_char) -> u32;
}

/// Preserve libc ordering and duplicates: option.c iterates every SOCK_DGRAM
/// result once. AI_ADDRCONFIG belongs to the image libc, not a Rust guess at
/// which interface addresses should count.
pub fn addresses(name: &[u8]) -> Result<Vec<IpAddr>, Error> {
    let name = CString::new(name).map_err(|_| Error("Name does not resolve"))?;
    let hints = AddrInfo {
        flags: AI_ADDRCONFIG,
        family: 0,
        socktype: 2,
        protocol: 0,
        address_length: 0,
        address: ptr::null_mut(),
        canonical: ptr::null_mut(),
        next: ptr::null_mut(),
    };
    let mut head = ptr::null_mut();
    // SAFETY: all pointers reference live initialized storage; libc owns the
    // returned list until the matching freeaddrinfo below.
    let code = unsafe { getaddrinfo(name.as_ptr(), ptr::null(), &hints, &mut head) };
    if code != 0 {
        if code == EAI_AGAIN {
            return Err(Error("Cannot resolve server name"));
        }
        // musl (the deployment libc) and Darwin return static error strings.
        // No DNS input is retained in these strings.
        // SAFETY: supported libcs return a non-null immutable static string
        // for the getaddrinfo error code; no caller buffer is involved.
        let message: &'static CStr = unsafe { CStr::from_ptr(gai_strerror(code)) };
        return Err(Error(message.to_str().unwrap_or("Unknown error")));
    }
    struct List(*mut AddrInfo);
    impl Drop for List {
        fn drop(&mut self) {
            // SAFETY: this guard exclusively owns the successful result list.
            unsafe { freeaddrinfo(self.0) };
        }
    }
    let _list = List(head);
    let mut result = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: cursor walks only links in the live libc result list.
        let entry = unsafe { &*cursor };
        if !entry.address.is_null() && entry.family == 2 && entry.address_length >= 16 {
            // SAFETY: non-null sockaddr_in has at least 16 bytes; its address
            // starts at byte four on both supported ABIs and the list is live.
            let bytes = unsafe { std::slice::from_raw_parts(entry.address.add(4), 4) };
            result.push(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )));
        } else if !entry.address.is_null() && entry.family == AF_INET6 && entry.address_length >= 28
        {
            // SAFETY: the preceding family/length guard proves all 16 IPv6
            // bytes at offset eight are within the live libc-owned sockaddr.
            let bytes = unsafe { std::slice::from_raw_parts(entry.address.add(8), 16) };
            let mut address = [0; 16];
            address.copy_from_slice(bytes);
            result.push(IpAddr::V6(Ipv6Addr::from(address)));
        }
        cursor = entry.next;
    }
    Ok(result)
}

pub fn scope_index(name: &[u8]) -> Result<u32, Error> {
    let name = CString::new(name).map_err(|_| Error("bad interface name"))?;
    // SAFETY: the kernel lookup receives a valid NUL-terminated name.
    let index = unsafe { if_nametoindex(name.as_ptr()) };
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

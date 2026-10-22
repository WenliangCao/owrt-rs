//! PXE boot-item/UEFI/menu primitives from rfc2131.c:877-1055,2394-2557.
//! The caller still owns proxy port dispatch, option filtering/encapsulation,
//! filename option-overload policy and metrics. Names/tags remain byte strings.

use super::allocation::{match_tags, AddressRange, RangeKind};
use super::packet::{find_option, Packet};
use crate::config::dhcp::BootConfig;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Service {
    pub architecture: u16,
    pub service_type: u16,
    pub menu: Vec<u8>,
    pub basename: Option<Vec<u8>>,
    pub server: Ipv4Addr,
    pub server_name: Option<Vec<u8>>,
    pub filter: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootTarget {
    pub next_server: Ipv4Addr,
    pub filename: Vec<u8>,
    pub server_name: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootItemReply {
    pub target: BootTarget,
    pub assigned_address: Ipv4Addr,
    pub server_identifier: Ipv4Addr,
    pub boot_item: [u8; 4],
    pub uuid: Option<[u8; 17]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Client {
    /// The matching configured prefix, not the whole incoming option60.
    pub vendor: Vec<u8>,
    pub architecture: Option<u16>,
    pub uuid: Option<[u8; 17]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Continue the ordinary allocator/leasequery path. PXE metadata only
    /// augments do_options when architecture is Some.
    Continue(Option<Client>),
    Ignore,
    /// A recognized boot-item request selects the unsupported BIS layer.
    UnsupportedBis,
    BootItem {
        client: Client,
        reply: BootItemReply,
    },
    /// Proxy attempts count PXE even when ignored; they never allocate.
    Proxy {
        client: Client,
        context: usize,
        ignored: bool,
    },
}

/// C's pre-allocation PXE branch. The provider has already completed its
/// interface/context/tag/host policy. This decision owns no leases or sockets.
#[allow(clippy::too_many_arguments)]
pub fn decide(
    packet: Packet<'_>,
    pxe_listener: bool,
    enabled: bool,
    vendors: &[Vec<u8>],
    services: &[Service],
    ranges: &[AddressRange],
    tags: &[&[u8]],
    ignored: bool,
    resolve: impl FnMut(&[u8]) -> Ipv4Addr,
) -> Decision {
    if packet.message_type() == 10 || (packet.message_type() == 0 && !pxe_listener) {
        return Decision::Continue(None);
    }
    if ranges.is_empty() {
        return Decision::Ignore;
    }
    let client = enabled
        .then(|| {
            let incoming = packet.option(60, 0)?;
            let vendor = vendors.iter().find(|prefix| incoming.starts_with(prefix))?;
            Some(Client {
                vendor: vendor.clone(),
                architecture: packet
                    .option(93, 2)
                    .map(|value| u16::from_be_bytes([value[0], value[1]])),
                uuid: packet
                    .option(97, 17)
                    .map(|value| value[..17].try_into().unwrap()),
            })
        })
        .flatten();
    if let Some(client) = client {
        let boot_request = matches!(packet.message_type(), 3 | 8)
            .then(|| {
                packet
                    .option(43, 1)
                    .and_then(|options| find_option(options, 71, 4))
            })
            .flatten();
        if let Some(item) = boot_request {
            if !ignored && u16::from_be_bytes([item.value[2], item.value[3]]) & 0x8000 != 0 {
                return Decision::UnsupportedBis;
            }
            return match boot_item(packet, services, ranges, tags, ignored, resolve) {
                Some(reply) => Decision::BootItem { client, reply },
                None => Decision::Ignore,
            };
        }
        if client.architecture.is_some()
            && (packet.message_type() == 1 || (pxe_listener && packet.message_type() == 3))
        {
            if let Some(context) = ranges.iter().position(|range| {
                range.kind == RangeKind::Proxy && match_tags(&range.filter, tags, true)
            }) {
                return Decision::Proxy {
                    client,
                    context,
                    ignored,
                };
            }
        }
        if !pxe_listener && ranges[0].kind != RangeKind::Proxy {
            return Decision::Continue(Some(client));
        }
    } else if !pxe_listener && ranges[0].kind != RangeKind::Proxy {
        return Decision::Continue(None);
    }
    Decision::Ignore
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplyFields {
    pub message_type: u8,
    pub server_identifier: Ipv4Addr,
    pub client_address: Ipv4Addr,
    pub assigned_address: Ipv4Addr,
    pub flags: u16,
    pub target: BootTarget,
}

impl BootItemReply {
    pub fn fields(&self, packet: Packet<'_>) -> ReplyFields {
        ReplyFields {
            message_type: 5,
            server_identifier: self.server_identifier,
            client_address: Ipv4Addr::UNSPECIFIED,
            assigned_address: self.assigned_address,
            flags: packet.flags(),
            target: self.target.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyReply {
    pub fields: ReplyFields,
    pub include_menu: bool,
}

/// The caller supplies tags after option_filter's mode2 context-tag pass.
#[allow(clippy::too_many_arguments)]
pub fn proxy_reply(
    packet: Packet<'_>,
    architecture: u16,
    pxe_listener: bool,
    services: &[Service],
    tags: &[&[u8]],
    local: Ipv4Addr,
    boot: Option<&BootConfig>,
    mut resolve: impl FnMut(&[u8]) -> Ipv4Addr,
) -> ProxyReply {
    let redirect = architecture >= 6;
    let single = single_uefi_service(architecture, services, tags);
    let mut target = BootTarget {
        next_server: if redirect {
            local
        } else {
            Ipv4Addr::UNSPECIFIED
        },
        filename: Vec::new(),
        server_name: Vec::new(),
    };
    if let Some(service) = single {
        if pxe_listener {
            target = uefi_target(service, local, &mut resolve);
        }
    } else if let Some(boot) = boot {
        if !boot.next_server.is_unspecified() {
            target.next_server = boot.next_server;
        } else if let Some(name) = &boot.next_server_name {
            target.next_server = resolve(name);
        }
        if let Some(filename) = &boot.filename {
            target.filename = filename[..filename.len().min(127)].to_vec();
        }
        // The proxy branch intentionally does not copy dhcp-boot sname.
    }
    let discover = packet.message_type() == 1;
    let mut client_address = packet.effective_ciaddr();
    let mut flags = packet.flags();
    if discover || client_address.is_unspecified() {
        client_address = Ipv4Addr::UNSPECIFIED;
        flags |= 0x8000;
    }
    ProxyReply {
        fields: ReplyFields {
            message_type: if discover { 2 } else { 5 },
            server_identifier: local,
            client_address,
            assigned_address: Ipv4Addr::UNSPECIFIED,
            flags,
            target,
        },
        include_menu: (pxe_listener && single.is_none()) || !redirect,
    }
}

/// Generated vendor suboptions in exact C prepend order. The caller appends
/// its already tag/vendor-pruned shared option bank after these values.
pub fn generated_suboptions(
    architecture: u16,
    services: &[Service],
    tags: &[&[u8]],
    local: Ipv4Addr,
    custom_prompt: bool,
    resolve: impl FnMut(&[u8]) -> Ipv4Addr,
) -> Result<Vec<(u8, Vec<u8>)>, MenuTooLarge> {
    let menu = menu_options(architecture, services, tags, local, custom_prompt, resolve)?;
    let mut result = vec![(6, vec![menu.discovery_control])];
    if let Some(prompt) = menu.prompt {
        result.push((10, prompt.to_vec()));
    }
    if !menu.servers.is_empty() {
        result.push((8, menu.servers));
    }
    if !menu.menu.is_empty() {
        result.push((9, menu.menu));
    }
    Ok(result)
}

/// Called only for an enabled, vendor-matched PXE client. A boot-item request
/// chooses by service type; C does not re-filter that service by architecture.
pub fn boot_item(
    packet: Packet<'_>,
    services: &[Service],
    ranges: &[AddressRange],
    tags: &[&[u8]],
    ignored: bool,
    mut resolve: impl FnMut(&[u8]) -> Ipv4Addr,
) -> Option<BootItemReply> {
    if ignored || !matches!(packet.message_type(), 3 | 8) {
        return None;
    }
    let boot_item: [u8; 4] = find_option(packet.option(43, 1)?, 71, 4)?.value[..4]
        .try_into()
        .unwrap();
    let service_type = u16::from_be_bytes([boot_item[0], boot_item[1]]);
    let layer = u16::from_be_bytes([boot_item[2], boot_item[3]]);
    if layer & 0x8000 != 0 {
        return None;
    }
    let service = services
        .iter()
        .find(|service| service.service_type == service_type)?;
    let basename = service.basename.as_deref()?;
    let context = ranges.iter().find(|context| {
        match_tags(&context.filter, tags, true) && context.same_subnet(packet.effective_ciaddr())
    })?;
    let next_server = if let Some(name) = &service.server_name {
        resolve(name)
    } else if !service.server.is_unspecified() {
        service.server
    } else {
        context.local
    };
    Some(BootItemReply {
        target: BootTarget {
            next_server,
            filename: filename(basename, layer),
            server_name: Vec::new(),
        },
        assigned_address: packet.effective_ciaddr(),
        server_identifier: context.local,
        boot_item,
        uuid: packet
            .option(97, 17)
            .map(|value| value[..17].try_into().unwrap()),
    })
}

pub fn single_uefi_service<'a>(
    architecture: u16,
    services: &'a [Service],
    tags: &[&[u8]],
) -> Option<&'a Service> {
    if architecture < 6 {
        return None;
    }
    let mut matching = services.iter().filter(|service| {
        service.architecture == architecture
            && service.basename.is_some()
            && match_tags(&service.filter, tags, true)
    });
    let service = matching.next()?;
    matching.next().is_none().then_some(service)
}

/// On port 67 a unique UEFI service only selects the workaround; these actual
/// filename/server fields are inserted on port 4011 (rfc2131.c:2415-2434).
pub fn uefi_target(
    service: &Service,
    local: Ipv4Addr,
    mut resolve: impl FnMut(&[u8]) -> Ipv4Addr,
) -> BootTarget {
    let (next_server, server_name) = if let Some(name) = &service.server_name {
        (resolve(name), name[..name.len().min(63)].to_vec())
    } else {
        let address = if service.server.is_unspecified() {
            local
        } else {
            service.server
        };
        (address, address.to_string().into_bytes())
    };
    BootTarget {
        next_server,
        server_name,
        filename: service
            .basename
            .as_deref()
            .map_or_else(Vec::new, |base| filename(base, 0)),
    }
}

fn filename(basename: &[u8], layer: u16) -> Vec<u8> {
    let mut result = basename.to_vec();
    if !basename.contains(&b'.') {
        result.extend_from_slice(format!(".{layer}").as_bytes());
    }
    result.truncate(127);
    result
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MenuOptions {
    pub discovery_control: u8,
    pub prompt: Option<[u8; 4]>,
    pub servers: Vec<u8>,
    pub menu: Vec<u8>,
}

/// A generated PXE menu cannot fit in the vendor option's wire length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuTooLarge;

impl std::fmt::Display for MenuTooLarge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("generated PXE menu exceeds the vendor option length")
    }
}

impl std::error::Error for MenuTooLarge {}

/// Generated suboption order: discovery (6), default prompt (10), servers (8),
/// menu (9), then configured options. On MenuTooLarge use configured options
/// only, matching C's fallback without sending a partially truncated menu.
pub fn menu_options(
    architecture: u16,
    services: &[Service],
    tags: &[&[u8]],
    local: Ipv4Addr,
    custom_prompt: bool,
    mut resolve: impl FnMut(&[u8]) -> Ipv4Addr,
) -> Result<MenuOptions, MenuTooLarge> {
    let mut result = MenuOptions {
        discovery_control: 3,
        prompt: None,
        servers: Vec::new(),
        menu: Vec::new(),
    };
    let mut count = 0;
    for service in services.iter().filter(|service| {
        service.architecture == architecture && match_tags(&service.filter, tags, true)
    }) {
        if result
            .menu
            .len()
            .saturating_add(service.menu.len())
            .saturating_add(3)
            >= 253
        {
            return Err(MenuTooLarge);
        }
        result
            .menu
            .extend_from_slice(&service.service_type.to_be_bytes());
        result.menu.push(service.menu.len() as u8);
        result.menu.extend_from_slice(&service.menu);
        count += 1;
        let server = if service.basename.is_some() {
            local
        } else if let Some(name) = &service.server_name {
            resolve(name)
        } else {
            service.server
        };
        if !server.is_unspecified() {
            if result.servers.len() + 7 >= 253 {
                return Err(MenuTooLarge);
            }
            result
                .servers
                .extend_from_slice(&service.service_type.to_be_bytes());
            result.servers.push(1);
            result.servers.extend_from_slice(&server.octets());
        } else if service.service_type != 0 {
            result.discovery_control = 2;
        }
    }
    if count == 0 {
        result.discovery_control = 8;
    }
    if !custom_prompt {
        result.prompt = Some([if count > 1 { 255 } else { 0 }, b'P', b'X', b'E']);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(kind: u8, architecture: Option<u16>, extra: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 240];
        bytes[..3].copy_from_slice(&[1, 1, 6]);
        bytes[12..16].copy_from_slice(&[192, 0, 2, 20]);
        bytes[236..240].copy_from_slice(&super::super::packet::COOKIE);
        if kind != 0 {
            bytes.extend_from_slice(&[53, 1, kind]);
        }
        bytes.extend_from_slice(b"\x3c\x09PXEClient");
        if let Some(value) = architecture {
            bytes.extend_from_slice(&[93, 2, (value >> 8) as u8, value as u8]);
        }
        bytes.extend_from_slice(extra);
        bytes.push(255);
        bytes
    }
    fn range(kind: RangeKind) -> AddressRange {
        AddressRange {
            start: "192.0.2.10".parse().unwrap(),
            end: "192.0.2.30".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
            router: "192.0.2.1".parse().unwrap(),
            local: "192.0.2.1".parse().unwrap(),
            lease_time: 600,
            kind,
            filter: vec![],
            epoch: 0,
        }
    }
    fn service() -> Service {
        Service {
            architecture: 7,
            service_type: 32768,
            menu: b"boot".to_vec(),
            basename: Some(b"efi".to_vec()),
            server: Ipv4Addr::UNSPECIFIED,
            server_name: None,
            filter: vec![],
        }
    }

    #[test]
    fn uefi_requires_exactly_one_matching_boot_service() {
        let services = [service()];
        assert!(single_uefi_service(5, &services, &[]).is_none());
        assert!(single_uefi_service(7, &services, &[]).is_some());
        assert!(single_uefi_service(7, &[service(), service()], &[]).is_none());
        let target = uefi_target(
            &services[0],
            Ipv4Addr::new(192, 0, 2, 1),
            |_| unreachable!(),
        );
        assert_eq!(target.filename, b"efi.0");
        assert_eq!(target.server_name, b"192.0.2.1");
        assert_eq!(filename(b"boot.efi", 9), b"boot.efi");
        assert_eq!(filename(&[b'a'; 200], 9).len(), 127);
    }

    #[test]
    fn menu_bytes_and_discovery_modes_follow_c() {
        let local = Ipv4Addr::new(192, 0, 2, 1);
        let options = menu_options(7, &[service()], &[], local, false, |_| unreachable!()).unwrap();
        assert_eq!(options.discovery_control, 3);
        assert_eq!(options.menu, [0x80, 0, 4, b'b', b'o', b'o', b't']);
        assert_eq!(options.servers, [0x80, 0, 1, 192, 0, 2, 1]);
        assert_eq!(options.prompt, Some([0, b'P', b'X', b'E']));
        let mut unknown = service();
        unknown.basename = None;
        assert_eq!(
            menu_options(7, &[unknown], &[], local, true, |_| unreachable!())
                .unwrap()
                .discovery_control,
            2
        );
        assert_eq!(
            menu_options(8, &[], &[], local, false, |_| unreachable!())
                .unwrap()
                .discovery_control,
            8
        );
    }

    #[test]
    fn exact_menu_limit_is_not_silently_truncated() {
        let mut item = service();
        item.menu = vec![b'a'; 249];
        assert!(menu_options(
            7,
            &[item.clone()],
            &[],
            Ipv4Addr::LOCALHOST,
            false,
            |_| unreachable!()
        )
        .is_ok());
        item.menu.push(b'a');
        assert_eq!(
            menu_options(
                7,
                &[item],
                &[],
                Ipv4Addr::LOCALHOST,
                false,
                |_| unreachable!()
            ),
            Err(MenuTooLarge)
        );
    }

    #[test]
    fn normal_pxe_continues_allocator_but_proxy_and_4011_do_not() {
        let vendors = vec![b"PXEClient".to_vec()];
        let mut bytes = request(1, Some(7), &[]);
        let packet = Packet::parse(&bytes).unwrap();
        assert!(matches!(
            decide(
                packet,
                false,
                true,
                &vendors,
                &[],
                &[range(RangeKind::Dynamic)],
                &[],
                false,
                |_| unreachable!()
            ),
            Decision::Continue(Some(Client {
                architecture: Some(7),
                ..
            }))
        ));
        assert!(matches!(
            decide(
                packet,
                false,
                true,
                &vendors,
                &[],
                &[range(RangeKind::Proxy)],
                &[],
                true,
                |_| unreachable!()
            ),
            Decision::Proxy { ignored: true, .. }
        ));
        bytes = request(3, Some(7), &[]);
        let packet = Packet::parse(&bytes).unwrap();
        assert_eq!(
            decide(
                packet,
                false,
                true,
                &vendors,
                &[],
                &[range(RangeKind::Proxy)],
                &[],
                false,
                |_| unreachable!()
            ),
            Decision::Ignore
        );
        assert!(matches!(
            decide(
                packet,
                true,
                true,
                &vendors,
                &[],
                &[range(RangeKind::Proxy)],
                &[],
                false,
                |_| unreachable!()
            ),
            Decision::Proxy { .. }
        ));
        bytes = request(10, Some(7), &[]);
        assert_eq!(
            decide(
                Packet::parse(&bytes).unwrap(),
                true,
                true,
                &vendors,
                &[],
                &[],
                &[],
                false,
                |_| unreachable!()
            ),
            Decision::Continue(None)
        );
    }

    #[test]
    fn boot_item_type_selection_precedes_architecture_and_service_tag_filter() {
        let mut configured = service();
        configured.filter.push(b"unmatched".to_vec());
        let bytes = request(3, Some(9), &[43, 6, 71, 4, 128, 0, 0, 2]);
        let packet = Packet::parse(&bytes).unwrap();
        let decision = decide(
            packet,
            true,
            true,
            &[b"PXEClient".to_vec()],
            &[configured],
            &[range(RangeKind::Static)],
            &[],
            false,
            |_| unreachable!(),
        );
        let Decision::BootItem { reply, .. } = decision else {
            panic!("boot item not selected")
        };
        assert_eq!(reply.target.filename, b"efi.2");
        assert_eq!(reply.fields(packet).client_address, Ipv4Addr::UNSPECIFIED);
        assert_eq!(reply.assigned_address, Ipv4Addr::new(192, 0, 2, 20));
    }

    #[test]
    fn proxy_uefi_redirect_and_boot_fallback_obey_listener_phase() {
        let bytes = request(1, Some(7), &[]);
        let packet = Packet::parse(&bytes).unwrap();
        let local = Ipv4Addr::new(192, 0, 2, 1);
        let services = [service()];
        let normal = proxy_reply(
            packet,
            7,
            false,
            &services,
            &[],
            local,
            None,
            |_| unreachable!(),
        );
        assert!(!normal.include_menu);
        assert_eq!(normal.fields.target.next_server, local);
        assert!(normal.fields.target.filename.is_empty());
        assert_eq!(normal.fields.flags & 0x8000, 0x8000);
        let followup = proxy_reply(
            packet,
            7,
            true,
            &services,
            &[],
            local,
            None,
            |_| unreachable!(),
        );
        assert_eq!(followup.fields.target.filename, b"efi.0");
        assert!(!followup.include_menu);
        let boot = BootConfig {
            filename: Some(b"fallback".to_vec()),
            server_name: Some(b"not-copied".to_vec()),
            next_server: Ipv4Addr::new(192, 0, 2, 8),
            next_server_name: None,
        };
        let legacy = proxy_reply(
            packet,
            0,
            false,
            &services,
            &[],
            local,
            Some(&boot),
            |_| unreachable!(),
        );
        assert!(legacy.include_menu);
        assert_eq!(legacy.fields.target.filename, b"fallback");
        assert!(legacy.fields.target.server_name.is_empty());
    }
}

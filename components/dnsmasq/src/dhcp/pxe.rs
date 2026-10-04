//! PXE boot-item/UEFI/menu primitives from rfc2131.c:877-1055,2394-2557.
//! The caller still owns proxy port dispatch, option filtering/encapsulation,
//! filename option-overload policy and metrics. Names/tags remain byte strings.

use super::allocation::{match_tags, AddressRange};
use super::packet::{find_option, Packet};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuTooLarge;

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
}

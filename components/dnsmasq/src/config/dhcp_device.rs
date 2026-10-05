//! dhcp-common.c:558-593 whichdevice after the owner enumerates interfaces.
//! Selection is independent of socket creation and binding policy.

pub struct DeclaredInterface<'a> {
    /// NULL names do not block selection; an absent declaration list does.
    pub name: Option<&'a [u8]>,
    /// network.c iface_check marks all label matches before exclusion vetoes.
    pub used: bool,
}

pub struct DeviceInterface<'a> {
    /// irec.name is the actual link name, rather than its IPv4 address label.
    pub name: &'a [u8],
    pub dhcp4_ok: bool,
    /// C retains and tests this flag even in its no-DHCPv6 image build.
    pub dhcp6_ok: bool,
}

pub fn which_device<'a>(
    names: &[DeclaredInterface<'_>],
    interfaces: &[DeviceInterface<'a>],
) -> Option<&'a [u8]> {
    if names.is_empty()
        || names.iter().any(|entry| {
            entry
                .name
                .is_some_and(|name| !entry.used || name.contains(&b'*'))
        })
    {
        return None;
    }
    let mut found = None;
    for interface in interfaces {
        if interface.dhcp4_ok || interface.dhcp6_ok {
            if found.is_some_and(|name| name != interface.name) {
                return None;
            }
            found = Some(interface.name);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarations_must_exist_and_all_nonnull_names_be_used_and_literal() {
        let rows = [DeviceInterface {
            name: b"lan",
            dhcp4_ok: true,
            dhcp6_ok: true,
        }];
        assert!(which_device(&[], &rows).is_none());
        assert!(which_device(
            &[DeclaredInterface {
                name: Some(b"missing"),
                used: false
            }],
            &rows
        )
        .is_none());
        assert!(which_device(
            &[DeclaredInterface {
                name: Some(b"lan*"),
                used: true
            }],
            &rows
        )
        .is_none());
        assert_eq!(
            which_device(
                &[DeclaredInterface {
                    name: None,
                    used: false
                }],
                &rows
            ),
            Some(b"lan".as_slice())
        );
    }

    #[test]
    fn alias_rows_collapse_by_actual_name_and_v4_only_veto_keeps_v6_candidate() {
        let names = [DeclaredInterface {
            name: Some(b"lan:1"),
            used: true,
        }];
        let rows = [
            DeviceInterface {
                name: b"lo",
                dhcp4_ok: false,
                dhcp6_ok: false,
            },
            DeviceInterface {
                name: b"lan",
                dhcp4_ok: true,
                dhcp6_ok: true,
            },
            DeviceInterface {
                name: b"lan",
                dhcp4_ok: false,
                dhcp6_ok: true,
            },
        ];
        assert_eq!(which_device(&names, &rows), Some(b"lan".as_slice()));
        let second = DeviceInterface {
            name: b"wan",
            dhcp4_ok: false,
            dhcp6_ok: true,
        };
        let rows = [rows.into_iter().nth(1).unwrap(), second];
        assert!(which_device(&names, &rows).is_none());
    }
}

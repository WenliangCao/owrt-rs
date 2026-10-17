//! Delegated prefixes and how they are carved up between interfaces.
//!
//! This is `interface_update_prefix_assignments` and `interface_prefix_assign`
//! from interface-ip.c. The algorithm is a first-fit walk over a list kept in
//! ascending order of the assigned offset, with a sentinel entry marking the
//! end of the prefix. Both the resulting offsets and the order the assignments
//! are reported in come out of that list, so the list discipline is
//! reproduced rather than replaced with a sort.

use std::net::Ipv6Addr;

/// A prefix netifd can assign out of: the ULA from `globals`, or one
/// delegated to an interface by DHCPv6-PD.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevicePrefix {
    pub addr: Ipv6Addr,
    pub length: u8,
    pub preferred_until: Option<u32>,
    pub valid_until: Option<u32>,
    /// The excluded prefix (RFC 6603), if the upstream sent one.
    pub excl: Option<(Ipv6Addr, u8)>,
    /// `pclass`: the uplink interface's name, or `local` for the ULA.
    pub class: String,
    /// The uplink, or `None` for the ULA.
    pub iface: Option<String>,
}

impl DevicePrefix {
    /// `interface_ip_add_device_prefix` clears the host part below `length`
    /// before storing the prefix.
    pub fn new(addr: Ipv6Addr, length: u8, class: &str, iface: Option<&str>) -> Self {
        Self {
            addr: clear_if_addr(addr, length),
            length,
            preferred_until: None,
            valid_until: None,
            excl: None,
            class: class.to_string(),
            iface: iface.map(|s| s.to_string()),
        }
    }
}

/// Replace one owner's prefixes in protocol callback order. The reference
/// `interface_update_prefix` unlinks the old node and uses list_add at the
/// head even on renewal. This order is observable: network_get_ipaddr6 uses
/// the first prefix assignment when the interface has no explicit address.
pub fn replace_prefixes(
    prefixes: &mut Vec<DevicePrefix>,
    iface: Option<&str>,
    fresh: Vec<DevicePrefix>,
) -> usize {
    let before = prefixes.len();
    prefixes.retain(|p| p.iface.as_deref() != iface);
    let removed = before - prefixes.len();
    for prefix in fresh {
        prefixes.insert(0, prefix);
    }
    removed
}

/// `clear_if_addr`: zero every bit below the prefix length.
pub fn clear_if_addr(addr: Ipv6Addr, length: u8) -> Ipv6Addr {
    let mut o = addr.octets();
    let len = length.min(128) as usize;
    for (i, b) in o.iter_mut().enumerate() {
        let bit = i * 8;
        if bit >= len {
            *b = 0;
        } else if bit + 8 > len {
            let keep = len - bit;
            *b &= !0u8 << (8 - keep);
        }
    }
    Ipv6Addr::from(o)
}

/// What an interface asks for out of a prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignRequest {
    pub name: String,
    /// `ip6assign`; only 48..=64 takes part in assignment at all.
    pub length: u8,
    /// `ip6hint`, already shifted the way netifd stores it; `None` is the
    /// "anywhere" request the C spells as -1.
    pub hint: Option<u32>,
    /// `ip6weight`.
    pub weight: i32,
    /// `ip6class`: when non-empty, the prefix's class must be in it.
    pub classes: Vec<String>,
}

/// One placed assignment. `assigned` is the offset within the prefix, in units
/// of the 32 bits that follow the first 32 — the C stores it in
/// `addr.s6_addr32[1]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub name: String,
    pub length: u8,
    pub assigned: u32,
}

/// A list entry during placement: the real assignments plus the two synthetic
/// entries (the end sentinel and the excluded prefix).
#[derive(Clone, Debug)]
struct Entry {
    name: String,
    length: u8,
    /// `int32_t` in the C: -1 means "not yet placed".
    assigned: i64,
}

/// `interface_prefix_assign`: first fit. With `assigned` already chosen the
/// entry has to land in a hole that contains it; with `assigned == -1` the
/// next aligned hole is taken. Returns the index the entry was inserted at.
fn prefix_assign(list: &mut Vec<Entry>, e: &mut Entry) -> bool {
    let asize: i64 = (1i64 << (64 - e.length)) - 1;
    let mut current: i64 = 0;
    for i in 0..list.len() {
        let c_assigned = list[i].assigned;
        if e.assigned != -1 {
            if e.assigned >= current && e.assigned + asize < c_assigned {
                list.insert(i, e.clone());
                return true;
            }
        } else {
            current = (current + asize) & !asize;
            if current + asize < c_assigned {
                e.assigned = current;
                list.insert(i, e.clone());
                return true;
            }
        }
        current = list[i].assigned + (1i64 << (64 - list[i].length));
    }
    false
}

/// `prefix_assignment_cmp`: shortest assignment first, then highest weight,
/// then interface name.
fn later_order(a: &(AssignRequest, Entry), b: &(AssignRequest, Entry)) -> std::cmp::Ordering {
    a.1.length
        .cmp(&b.1.length)
        .then(b.0.weight.cmp(&a.0.weight))
        .then(a.0.name.cmp(&b.0.name))
}

/// `interface_update_prefix_assignments`.
///
/// `requests` must be in netifd's interface order, which is its vlist order:
/// by interface name. The returned assignments are in the list's own order,
/// which is what `ipv6-prefix-assignment` and the `assigned` table report.
pub fn assign(prefix: &DevicePrefix, requests: &[AssignRequest]) -> Vec<Assignment> {
    // the end-of-assignment sentinel
    let mut list = vec![Entry {
        name: String::new(),
        length: 64,
        assigned: 1i64 << (64 - prefix.length),
    }];

    // the excluded prefix, inserted at the head as the C's list_add does
    if let Some((excl_addr, excl_length)) = prefix.excl {
        let o = excl_addr.octets();
        let word1 = u32::from_be_bytes([o[4], o[5], o[6], o[7]]) as i64;
        list.insert(
            0,
            Entry {
                name: "!excluded".to_string(),
                length: excl_length,
                assigned: word1 & ((1i64 << (64 - prefix.length)) - 1),
            },
        );
    }

    let mut later: Vec<(AssignRequest, Entry)> = Vec::new();
    for r in requests {
        if r.length < 48 || r.length > 64 {
            continue;
        }
        if !r.classes.is_empty() && !r.classes.contains(&prefix.class) {
            continue;
        }
        let mut e = Entry {
            name: r.name.clone(),
            length: r.length,
            assigned: r.hint.map(|h| h as i64).unwrap_or(-1),
        };
        if e.assigned == -1 || !prefix_assign(&mut list, &mut e) {
            // a hint that would not fit is downgraded to "anywhere", exactly
            // as the C does after warning about it
            e.assigned = -1;
            later.push((r.clone(), e));
        }
    }

    later.sort_by(later_order);
    for (_, mut e) in later {
        loop {
            if prefix_assign(&mut list, &mut e) {
                break;
            }
            e.length += 1;
            if e.length > 64 {
                break;
            }
            e.assigned = -1;
        }
    }

    list.into_iter()
        .filter(|e| !e.name.is_empty() && e.name != "!excluded")
        .map(|e| Assignment {
            name: e.name,
            length: e.length,
            assigned: e.assigned.max(0) as u32,
        })
        .collect()
}

/// The address an assignment covers: the prefix with the offset OR-ed into the
/// second 32-bit word, as `interface_ip_dump_prefix_assignment_list` computes.
pub fn assignment_address(prefix: &DevicePrefix, assigned: u32) -> Ipv6Addr {
    let mut o = prefix.addr.octets();
    let word1 = u32::from_be_bytes([o[4], o[5], o[6], o[7]]) | assigned;
    o[4..8].copy_from_slice(&word1.to_be_bytes());
    Ipv6Addr::from(o)
}

/// `generate_ifaceid` with the default `IFID_FIXED` selection, whose fixed id
/// is `::1`: keep the prefix and set the low 64 bits from the fixed id.
pub fn local_address(prefix_addr: Ipv6Addr, fixed_iface_id: Ipv6Addr) -> Ipv6Addr {
    let mut o = prefix_addr.octets();
    o[8..16].copy_from_slice(&fixed_iface_id.octets()[8..16]);
    Ipv6Addr::from(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(name: &str, length: u8) -> AssignRequest {
        AssignRequest { name: name.into(), length, hint: None, weight: 0, classes: vec![] }
    }

    #[test]
    fn delegated_prefix_precedes_ula_in_the_address_selected_by_network_sh() {
        let ula = DevicePrefix::new("fd00:1234::".parse().unwrap(), 48, "local", None);
        let pd = DevicePrefix::new("2001:db8:1::".parse().unwrap(), 64, "wan6", Some("wan6"));
        let mut prefixes = Vec::new();
        replace_prefixes(&mut prefixes, None, vec![ula]);
        replace_prefixes(&mut prefixes, Some("wan6"), vec![pd]);

        // Project the assignments through the real status encoder. On this
        // LAN ipv6-address is empty and network.sh selects assignment[0].
        let mut lan = crate::interface::Interface::new("lan");
        lan.state = crate::interface::State::Up;
        for p in &prefixes {
            for assignment in assign(p, &[req("lan", 60)]) {
                let addr = assignment_address(p, assignment.assigned);
                lan.prefix_assignments.push(crate::interface::PrefixAssignment {
                    addr,
                    length: assignment.length,
                    preferred_until: None,
                    valid_until: None,
                    local: Some((local_address(addr, "::1".parse().unwrap()), assignment.length)),
                    owner: Some((p.iface.clone(), p.addr, p.length)),
                });
            }
        }
        let mut buf = owrt_ubus::BlobBuf::new();
        lan.dump_status_with(&mut buf, 0, &lan.proto_ip.prefixes);
        let status = owrt_ubus::convert::fields_to_json(buf.payload());
        let owrt_ubus::json::Json::Array(addresses) = status.get("ipv6-address").unwrap() else { panic!() };
        assert!(addresses.is_empty());
        let owrt_ubus::json::Json::Array(assignments) = status.get("ipv6-prefix-assignment").unwrap() else { panic!() };
        assert_eq!(assignments.len(), 2);
        let first = assignments[0].get("local-address").unwrap();
        assert_eq!(first.get("address").and_then(owrt_ubus::json::Json::as_str), Some("2001:db8:1::1"));
    }

    #[test]
    fn renewal_ula_replacement_and_withdrawal_follow_c_list_add_order() {
        let prefix = |addr: &str, iface: Option<&str>| {
            DevicePrefix::new(addr.parse().unwrap(), 64, iface.unwrap_or("local"), iface)
        };
        let ula = prefix("fd00::", None);
        let wan = prefix("2001:db8:1::", Some("wan6"));
        let other = prefix("2001:db8:2::", Some("other6"));
        let mut prefixes = Vec::new();
        replace_prefixes(&mut prefixes, None, vec![ula.clone()]);
        replace_prefixes(&mut prefixes, Some("wan6"), vec![wan.clone()]);
        replace_prefixes(&mut prefixes, Some("other6"), vec![other.clone()]);
        assert_eq!(prefixes, vec![other.clone(), wan.clone(), ula.clone()]);
        // Even an unchanged PD renewal moves that owner's node to the head.
        assert_eq!(replace_prefixes(&mut prefixes, Some("wan6"), vec![wan.clone()]), 1);
        assert_eq!(prefixes, vec![wan.clone(), other.clone(), ula]);
        let new_ula = prefix("fd01::", None);
        replace_prefixes(&mut prefixes, None, vec![new_ula.clone()]);
        assert_eq!(prefixes, vec![new_ula.clone(), wan, other.clone()]);
        assert_eq!(replace_prefixes(&mut prefixes, Some("wan6"), vec![]), 1);
        assert_eq!(prefixes, vec![new_ula, other]);
    }

    #[test]
    fn multiple_pd_callbacks_are_prepended_in_notification_order() {
        let first = DevicePrefix::new("2001:db8:1::".parse().unwrap(), 64, "wan6", Some("wan6"));
        let last = DevicePrefix::new("2001:db8:2::".parse().unwrap(), 64, "wan6", Some("wan6"));
        let mut prefixes = Vec::new();
        replace_prefixes(&mut prefixes, Some("wan6"), vec![first.clone(), last.clone()]);
        assert_eq!(prefixes, vec![last, first]);
    }

    #[test]
    fn clearing_a_prefix_zeroes_below_the_length() {
        let a: Ipv6Addr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        assert_eq!(clear_if_addr(a, 48), "2001:db8:1::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(clear_if_addr(a, 60), "2001:db8:1::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(clear_if_addr(a, 64), "2001:db8:1:2::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(clear_if_addr(a, 0), Ipv6Addr::UNSPECIFIED);
    }

    #[test]
    fn a_lone_60_out_of_a_48_lands_at_offset_zero() {
        let p = DevicePrefix::new("fd11:2233:4455::".parse().unwrap(), 48, "local", None);
        let got = assign(&p, &[req("lan", 60)]);
        assert_eq!(got, vec![Assignment { name: "lan".into(), length: 60, assigned: 0 }]);
        assert_eq!(assignment_address(&p, 0), "fd11:2233:4455::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            local_address(assignment_address(&p, 0), "::1".parse().unwrap()),
            "fd11:2233:4455::1".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn a_60_request_out_of_a_64_is_widened_to_a_64() {
        // the device's real case: ip6assign 60 on lan, but wan6 delegates a /64
        let p = DevicePrefix::new("2001:db8:1:2::".parse().unwrap(), 64, "wan6", Some("wan6"));
        let got = assign(&p, &[req("lan", 60)]);
        assert_eq!(got, vec![Assignment { name: "lan".into(), length: 64, assigned: 0 }]);
    }

    #[test]
    fn two_interfaces_get_adjacent_blocks() {
        let p = DevicePrefix::new("fd00::".parse().unwrap(), 48, "local", None);
        let got = assign(&p, &[req("guest", 60), req("lan", 60)]);
        // both are /60 out of a /48, so the offsets step by 1 << (64-60) = 16
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].assigned, 0);
        assert_eq!(got[1].assigned, 16);
        // sorted by name, so `guest` is placed first and lands lower
        assert_eq!(got[0].name, "guest");
        assert_eq!(got[1].name, "lan");
    }

    #[test]
    fn the_shortest_request_is_placed_first() {
        let p = DevicePrefix::new("fd00::".parse().unwrap(), 48, "local", None);
        // `wide` asks for a /56, `narrow` for a /64; the /56 sorts first
        let got = assign(&p, &[req("narrow", 64), req("wide", 56)]);
        let wide = got.iter().find(|a| a.name == "wide").unwrap();
        let narrow = got.iter().find(|a| a.name == "narrow").unwrap();
        assert_eq!(wide.assigned, 0);
        assert!(narrow.assigned >= 1 << (64 - 56));
    }

    #[test]
    fn a_weight_breaks_a_length_tie_before_the_name_does() {
        let p = DevicePrefix::new("fd00::".parse().unwrap(), 48, "local", None);
        let mut a = req("aaa", 60);
        let mut b = req("bbb", 60);
        b.weight = 10;
        a.weight = 0;
        let got = assign(&p, &[a, b]);
        // higher weight is placed first, so `bbb` gets the lower offset even
        // though `aaa` sorts earlier by name
        assert_eq!(got[0].name, "bbb");
        assert_eq!(got[0].assigned, 0);
    }

    #[test]
    fn a_hint_is_honoured_when_it_fits() {
        let p = DevicePrefix::new("fd00::".parse().unwrap(), 48, "local", None);
        let mut r = req("lan", 60);
        r.hint = Some(0x20);
        let got = assign(&p, &[r]);
        assert_eq!(got[0].assigned, 0x20);
    }

    #[test]
    fn an_unfittable_hint_falls_back_to_first_fit() {
        let p = DevicePrefix::new("fd00::".parse().unwrap(), 60, "local", None);
        let mut r = req("lan", 60);
        // way past the end of a /60 prefix
        r.hint = Some(0xffff);
        let got = assign(&p, &[r]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].assigned, 0);
    }

    #[test]
    fn a_request_outside_48_to_64_takes_no_part() {
        let p = DevicePrefix::new("fd00::".parse().unwrap(), 48, "local", None);
        assert!(assign(&p, &[req("lan", 47)]).is_empty());
        assert!(assign(&p, &[req("lan", 65)]).is_empty());
    }

    #[test]
    fn a_class_that_does_not_match_is_skipped() {
        let p = DevicePrefix::new("fd00::".parse().unwrap(), 48, "local", None);
        let mut r = req("lan", 60);
        r.classes = vec!["wan6".into()];
        assert!(assign(&p, &[r.clone()]).is_empty());
        r.classes = vec!["local".into(), "wan6".into()];
        assert_eq!(assign(&p, &[r]).len(), 1);
    }

    #[test]
    fn an_excluded_prefix_pushes_the_assignment_past_it() {
        let mut p = DevicePrefix::new("2001:db8::".parse().unwrap(), 48, "wan6", Some("wan6"));
        // exclude the first /60 of the prefix
        p.excl = Some(("2001:db8::".parse().unwrap(), 60));
        let got = assign(&p, &[req("lan", 60)]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "lan");
        assert!(got[0].assigned >= 16, "{got:?}");
    }

    #[test]
    fn assignment_address_ors_into_the_second_word() {
        let p = DevicePrefix::new("fd00::".parse().unwrap(), 48, "local", None);
        assert_eq!(assignment_address(&p, 0x10), "fd00:0:0:10::".parse::<Ipv6Addr>().unwrap());
    }
}

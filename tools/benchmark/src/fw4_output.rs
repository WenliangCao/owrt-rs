//! fw4 print comparison: only the order of plain subnet-set members is ignored.
//! Rules, chains, duplicate members and subnet membership remain significant.
use std::net::IpAddr;

pub fn normalize(bytes: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return bytes.to_vec();
    };
    let mut result = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if let Some(canonical) = subnet_definition(line) {
            result.push_str(&canonical);
        } else {
            result.push_str(line);
        }
    }
    result.into_bytes()
}

fn subnet_definition(line: &str) -> Option<String> {
    let definition = line.trim_start().strip_prefix("define ")?;
    let (name, _) = definition.split_once(" = { ")?;
    if !name.ends_with("_subnets") || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return None;
    }
    let open = line.find("{ ")? + 2;
    let close = line[open..].find(" }")? + open;
    if !line[close + 2..].trim().is_empty() {
        return None;
    }
    let mut members: Vec<_> = line[open..close].split(',').map(str::trim).collect();
    for member in &members {
        let (address, mask) = member.split_once('/')?;
        let address: IpAddr = address.parse().ok()?;
        let mask: u8 = mask.parse().ok()?;
        if mask > if address.is_ipv4() { 32 } else { 128 } {
            return None;
        }
    }
    // Keep duplicates: silently dropping one could hide a generator bug.
    members.sort_unstable();
    Some(format!(
        "{}{}{}",
        &line[..open],
        members.join(", "),
        &line[close..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_and_ipv6_subnet_permutations_compare_equal() {
        let c = b"\tdefine lan_subnets = { 192.0.2.0/24, 2001:db8::/64, fd00::/60 }\n";
        let rs = b"\tdefine lan_subnets = { fd00::/60, 192.0.2.0/24, 2001:db8::/64 }\n";
        assert_eq!(normalize(c), normalize(rs));
        assert_eq!(normalize(&normalize(c)), normalize(c));
    }

    #[test]
    fn changed_missing_or_duplicate_subnets_remain_different() {
        let reference = b"define wan_subnets = { 192.0.2.0/24, 2001:db8::/64 }\n";
        for other in [
            "define wan_subnets = { 192.0.2.0/24 }\n",
            "define wan_subnets = { 192.0.2.0/24, 2001:db8::/60 }\n",
            "define wan_subnets = { 192.0.2.0/24, 2001:db8::/64, 2001:db8::/64 }\n",
        ] {
            assert_ne!(normalize(reference), normalize(other.as_bytes()));
        }
    }

    #[test]
    fn rule_order_and_non_subnet_expressions_are_not_normalized() {
        for text in [
            "ip saddr { 192.0.2.1, 192.0.2.2 } accept\n",
            "define ports = { 443, 80 }\n",
            "define lan_subnets = { 192.0.2.0/24, jump accept }\n",
            "define lan_subnets = { 192.0.2.0/33, 198.51.100.0/24 }\n",
            "define lan_subnets = { 192.0.2.0/24 } extra\n",
        ] {
            assert_eq!(normalize(text.as_bytes()), text.as_bytes());
        }
        assert_ne!(normalize(b"accept\ndrop\n"), normalize(b"drop\naccept\n"));
        assert_eq!(normalize(b"\xff\n"), b"\xff\n");
    }
}

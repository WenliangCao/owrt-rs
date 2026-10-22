//! `system_resolve_rt_table` / `_type` / `_proto`: the routing-table, route
//! type and route protocol names netifd accepts, shared by the proto-shell
//! notify parser and the `config route` parser. No dependencies, so the
//! probe examples that include `config.rs` can include this too.

/// `RT_TABLE_MAIN`
pub const RT_TABLE_MAIN: u32 = 254;

/// `strtoul(s, &e, base)` as the C resolvers call it: leading whitespace and
/// sign, base 0 auto-detects `0x`/leading-0 octal, saturates at u64::MAX,
/// `-` negates in unsigned arithmetic. Returns (value, consumed_any,
/// consumed_all) -- the callers' `e != s` and `!*e` tests. (R73: the old
/// `parse::<u32>()` rejected "0x10", so a hex table number in uci fell
/// through to the rt_tables file instead of being used.)
fn strtoul_c(s: &str, base: u32) -> (u64, bool, bool) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i] as char).is_ascii_whitespace() {
        i += 1;
    }
    let neg = i < b.len() && b[i] == b'-';
    if i < b.len() && (b[i] == b'-' || b[i] == b'+') {
        i += 1;
    }
    let mut base = base;
    if base == 0 {
        if b[i..].len() >= 2 && b[i] == b'0' && (b[i + 1] | 0x20) == b'x' {
            base = 16;
            i += 2;
        } else if b.get(i) == Some(&b'0') {
            base = 8;
        } else {
            base = 10;
        }
    } else if base == 16 && b[i..].len() >= 2 && b[i] == b'0' && (b[i + 1] | 0x20) == b'x' {
        i += 2;
    }
    let start = i;
    let mut val: u64 = 0;
    let mut sat = false;
    while i < b.len() {
        let Some(d) = (b[i] as char).to_digit(base) else {
            break;
        };
        match val
            .checked_mul(base as u64)
            .and_then(|v| v.checked_add(d as u64))
        {
            Some(v) => val = v,
            None => sat = true,
        }
        i += 1;
    }
    if sat {
        val = u64::MAX;
    }
    if i == start {
        // Nothing consumed: strtoul leaves e at the start, so the callers'
        // `e != s` test is false whatever `!*e` says.
        return (0, false, false);
    }
    if neg {
        val = val.wrapping_neg();
    }
    (val, true, i == b.len())
}

/// `system_resolve_rt_table`: a number FIRST (strtoul base 0, truncated to
/// unsigned int, and 0 does not count), then the three aliases, then
/// /etc/iproute2/rt_tables; RT_TABLE_UNSPEC (0) at the end is failure.
pub(crate) fn resolve_rt_table(s: &str) -> Option<u32> {
    let mut table: u32 = 0;
    let (v, any, all) = strtoul_c(s, 0);
    let n = v as u32;
    if any && all && n > 0 {
        table = n;
    } else if s == "default" {
        table = 253;
    } else if s == "main" {
        table = RT_TABLE_MAIN;
    } else if s == "local" {
        table = 255;
    } else if let Ok(text) = std::fs::read_to_string("/etc/iproute2/rt_tables") {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let (Some(id), Some(name)) = (it.next(), it.next()) else {
                continue;
            };
            if id.starts_with('#') {
                continue;
            }
            if name == s {
                table = strtoul_c(id, 10).0 as u32;
                break;
            }
        }
    }
    (table != 0).then_some(table)
}

/// `system_resolve_rt_type`, the subset the kernel names.
pub(crate) fn resolve_rt_type(s: &str) -> Option<u32> {
    Some(match s {
        "unspec" => 0,
        "unicast" => 1,
        "local" => 2,
        "broadcast" => 3,
        "anycast" => 4,
        "multicast" => 5,
        "blackhole" => 6,
        "unreachable" => 7,
        "prohibit" => 8,
        "throw" => 9,
        "nat" => 10,
        "xresolve" => 11,
        _ => return None,
    })
}

/// `system_resolve_rt_proto`: a number (strtoul base 0, 0 allowed), a name,
/// or a lookup in /etc/iproute2/rt_protos; anything above 255 is failure.
pub(crate) fn resolve_rt_proto(s: &str) -> Option<u32> {
    let mut proto: u32 = 256;
    let (v, any, all) = strtoul_c(s, 0);
    if any && all {
        proto = v as u32;
    } else if s == "unspec" {
        proto = 0;
    } else if s == "kernel" {
        proto = 2;
    } else if s == "boot" {
        proto = 3;
    } else if s == "static" {
        proto = 4;
    } else if let Ok(text) = std::fs::read_to_string("/etc/iproute2/rt_protos") {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let (Some(id), Some(name)) = (it.next(), it.next()) else {
                continue;
            };
            if id.starts_with('#') {
                continue;
            }
            if name == s {
                proto = strtoul_c(id, 10).0 as u32;
                break;
            }
        }
    }
    (proto <= 255).then_some(proto)
}

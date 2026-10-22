//! Output formatting helpers used by the templates (quote, cidr, set, ...).

use crate::ip::{self, Mask};
use crate::parse::Fw4;
use crate::state::*;
use crate::val::Num;

pub fn quote(s: &str, force: bool) -> String {
    // /^([0-9A-Fa-f:.\/-]+)( \. [0-9A-Fa-f:.\/-]+)*$/
    let plain = |t: &str| {
        !t.is_empty()
            && t.chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '/' | '-'))
    };
    let matches = s.split(" . ").all(plain);
    if force || !matches {
        format!("\"{}\"", s.replace('"', "'"))
    } else {
        s.to_owned()
    }
}

fn opt_str<T: ToString>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "null".into())
}

pub fn cidr(a: &Addr) -> String {
    if a.range {
        return format!("{}-{}", a.addr, opt_str(a.addr2.as_ref()));
    }
    if (a.family == 4 && a.bits == Some(32)) || (a.family == 6 && a.bits == Some(128)) {
        return a.addr.clone();
    }
    // ucode `a.bits >= 0` is true for null
    let bits = a.bits.unwrap_or(0);
    if a.bits.is_none() || bits >= 0 {
        return format!(
            "{}/{}",
            opt_str(ip::apply_mask(&a.addr, Mask::Bits(bits))),
            opt_str(a.bits)
        );
    }
    format!("{}/{}", a.addr, opt_str(a.mask.as_ref()))
}

pub fn host(a: &Addr, v6brackets: bool) -> String {
    if a.range {
        return format!("{}-{}", a.addr, opt_str(a.addr2.as_ref()));
    }
    let masked = opt_str(ip::apply_mask(&a.addr, Mask::Bits(a.bits.unwrap_or(0))));
    if a.family == 6 && v6brackets {
        format!("[{masked}]")
    } else {
        masked
    }
}

pub fn port(p: &Port) -> String {
    if p.min == p.max {
        p.min.to_string()
    } else {
        format!("{}-{}", p.min, p.max)
    }
}

pub fn set(v: &[String], force: bool) -> String {
    // first occurrence of each item, in order (ucode `uniq`)
    let mut seen: Vec<&String> = Vec::with_capacity(v.len());
    for item in v {
        if !seen.contains(&item) {
            seen.push(item);
        }
    }
    if force || seen.len() != 1 {
        let mut out = String::from("{ ");
        for (i, item) in seen.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&quote(item, false));
        }
        out.push_str(" }");
        out
    } else {
        quote(seen[0], false)
    }
}

pub fn set_i64(v: &[i64], force: bool) -> String {
    let strs: Vec<String> = v.iter().map(|n| n.to_string()).collect();
    set(&strs, force)
}

pub fn concat(v: &[String]) -> String {
    v.join(" . ")
}

/// `{{ fw4.ipproto(family) }}`: expression tags print nothing for null.
pub fn ipproto(family: i64) -> &'static str {
    match family {
        4 => "ip",
        6 => "ip6",
        _ => "",
    }
}

pub fn nfproto(family: i64, human: bool) -> String {
    match family {
        4 => if human { "IPv4" } else { "ipv4" }.into(),
        6 => if human { "IPv6" } else { "ipv6" }.into(),
        _ => if human { "IPv4/IPv6" } else { "" }.into(),
    }
}

pub fn l4proto(family: i64, proto: &Proto) -> String {
    match proto.name() {
        "icmp" => match family {
            0 => set(&["icmp".into(), "ipv6-icmp".into()], false),
            6 => "ipv6-icmp".into(),
            _ => "icmp".into(),
        },
        other => other.to_owned(),
    }
}

pub fn datetime(d: &DateTime) -> String {
    format!(
        "\"{:04}-{:02}-{:02} {:02}:{:02}:{:02}\"",
        d.year, d.month, d.day, d.hour, d.min, d.sec
    )
}

/// `datestamp`: dates always carry a time in fw4 (parse_date merges parse_time).
pub fn datestamp(d: &DateTime) -> String {
    datetime(d)
}

pub fn time(t: &Time) -> String {
    format!("\"{:02}:{:02}:{:02}\"", t.hour, t.min, t.sec)
}

pub fn hex(n: i64) -> String {
    format!("0x{:x}", n)
}

pub fn num(n: Num) -> String {
    n.to_ucode_string()
}

impl Fw4 {
    pub fn is_loopback_dev(&self, dev: &str) -> bool {
        let flags = self.inputs.readfile(&format!("/sys/class/net/{dev}/flags"));
        let n = match flags {
            Some(s) => crate::val::parse_num_str(&s),
            None => Num::Int(0),
        };
        (n.as_i64() & 0x8) != 0
    }

    pub fn is_loopback_addr(&self, addr: &str) -> bool {
        addr.starts_with("127.") || addr == "::1" || addr == "::1/128"
    }

    pub fn filter_loopback_devs(
        &self,
        devs: Option<&Vec<String>>,
        invert: bool,
    ) -> Option<Vec<String>> {
        let out: Vec<String> = devs?
            .iter()
            .filter(|d| self.is_loopback_dev(d) == invert)
            .cloned()
            .collect();
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    pub fn filter_loopback_addrs(
        &self,
        addrs: Option<&Vec<String>>,
        invert: bool,
    ) -> Option<Vec<String>> {
        let out: Vec<String> = addrs?
            .iter()
            .filter(|a| self.is_loopback_addr(a) == invert)
            .cloned()
            .collect();
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    pub fn defaults(&self) -> &Defaults {
        static EMPTY: Defaults = Defaults {
            input: None,
            output: None,
            forward: None,
            drop_invalid: None,
            tcp_reject_code: None,
            any_reject_code: None,
            synflood_protect: None,
            synflood_rate: None,
            synflood_burst: None,
            auto_helper: None,
            flow_offloading: None,
            flow_offloading_hw: None,
            auto_includes: None,
        };
        self.state.defaults.as_ref().unwrap_or(&EMPTY)
    }

    fn policy(&self, which: &str, reject_as_drop: bool) -> String {
        let d = self.defaults();
        let p = match which {
            "input" => &d.input,
            "output" => &d.output,
            _ => &d.forward,
        };
        match p.as_deref() {
            Some(p) if reject_as_drop && p == "reject" => "drop".into(),
            Some(p) => p.to_owned(),
            None => "null".into(),
        }
    }

    pub fn input_policy(&self, reject_as_drop: bool) -> String {
        self.policy("input", reject_as_drop)
    }
    pub fn output_policy(&self, reject_as_drop: bool) -> String {
        self.policy("output", reject_as_drop)
    }
    pub fn forward_policy(&self, reject_as_drop: bool) -> String {
        self.policy("forward", reject_as_drop)
    }

    pub fn rules<'a>(&'a self, chain: &'a str) -> impl Iterator<Item = &'a Rule> + 'a {
        self.state.rules.iter().filter(move |r| r.chain == chain)
    }

    pub fn redirects<'a>(&'a self, chain: &'a str) -> impl Iterator<Item = &'a Redirect> + 'a {
        self.state
            .redirects
            .iter()
            .filter(move |r| r.chain == chain)
    }

    /// `fw4.includes(position, chain)` output, appended to `out`: the leading
    /// separator only when at least one include matches.
    pub fn write_includes(&self, position: &str, chain: Option<&str>, out: &mut String) {
        let (pad, pre) = match position {
            "table-prepend" | "table-append" => ("\t", "\n"),
            "chain-prepend" | "chain-append" => ("\t\t", ""),
            _ => ("", "\n"),
        };
        let mut any = false;
        for inc in &self.state.includes {
            if inc.ty == "nftables"
                && inc.position == position
                && (chain.is_none() || inc.chain.as_deref() == chain)
            {
                if !any {
                    out.push_str(pre);
                    any = true;
                }
                out.push_str(pad);
                out.push_str("include \"");
                out.push_str(&inc.path);
                out.push_str("\"\n");
            }
        }
    }

    /// `parse_setfile(set, cb)`: entries from `loadfile`.
    pub fn parse_setfile(&self, set: &Ipset, cb: &mut dyn FnMut(&[String])) -> Option<usize> {
        let path = set.loadfile.as_deref()?;
        let data = match self.inputs.read_open(path) {
            Ok(data) => data,
            Err(error) => {
                self.raw_warn(&format!(
                    "Unable to load file '{}' for set '{}': {}\n",
                    path,
                    set.name,
                    crate::input::fs_error(&error)
                ));
                return None;
            }
        };
        let mut count = 0;
        for line in data.split_inclusive('\n') {
            let line = crate::val::trim(line);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match self.parse_ipsetentry(line, set) {
                Some(v) => {
                    cb(&v);
                    count += 1;
                }
                None => self.warn(&format!(
                    "Skipping invalid entry '{}' in file '{}' for set '{}'",
                    line, path, set.name
                )),
            }
        }
        Some(count)
    }

    pub fn print_setentries(&self, set: &Ipset, out: &mut String) {
        let mut first = true;
        let mut printer = |entry: &[String], out: &mut String| {
            if first {
                out.push_str("\t\telements = {\n");
                first = false;
            }
            out.push_str(&format!("\t\t\t{},\n", entry.join(" . ")));
        };
        for e in &set.entries {
            printer(e, out);
        }
        if set.loadfile.is_some() {
            let mut buf = String::new();
            self.parse_setfile(set, &mut |e| printer(e, &mut buf));
            out.push_str(&buf);
        }
        if !first {
            out.push_str("\t\t}\n");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting() {
        assert_eq!(quote("br-lan", false), "\"br-lan\"");
        assert_eq!(quote("10.0.0.0/24", false), "10.0.0.0/24");
        assert_eq!(quote("ff", false), "ff");
        assert_eq!(quote("1 . 2", false), "1 . 2");
        assert_eq!(quote("a\"b", true), "\"a'b\"");
        assert_eq!(set(&["a".into(), "a".into()], false), "a");
        assert_eq!(set(&["lan".into(), "lan".into()], false), "\"lan\"");
        assert_eq!(set(&["a".into(), "b".into()], false), "{ a, b }");
        assert_eq!(
            set(&["lan".into(), "wan".into()], false),
            "{ \"lan\", \"wan\" }"
        );
        assert_eq!(set(&["eth0".into()], true), "{ \"eth0\" }");
        assert_eq!(set(&[], true), "{  }");
        let a = Addr {
            family: 4,
            addr: "10.0.0.5".into(),
            mask: Some("255.255.255.0".into()),
            bits: Some(24),
            addr2: None,
            range: false,
            invert: false,
        };
        assert_eq!(cidr(&a), "10.0.0.0/24");
        let a = Addr {
            family: 4,
            addr: "10.0.0.0".into(),
            mask: Some("255.0.255.0".into()),
            bits: Some(-1),
            addr2: None,
            range: false,
            invert: false,
        };
        assert_eq!(cidr(&a), "10.0.0.0/255.0.255.0");
        assert_eq!(nfproto(0, true), "IPv4/IPv6");
        assert_eq!(hex(4294967290), "0xfffffffa");
    }
}

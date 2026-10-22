//! The nftables ruleset renderer: a line-exact port of `templates/ruleset.uc`
//! and the fragment templates it includes (rule.uc, redirect.uc, zone-*.uc),
//! honouring ucode's template whitespace rules.

use crate::emit::*;
use crate::parse::Fw4;
use crate::state::*;
use owrt_ubus::json::Json;
use std::fmt::Write;

fn opt_set(v: Option<&Vec<String>>) -> String {
    set(v.map(|x| x.as_slice()).unwrap_or(&[]), false)
}

fn optional(v: Option<&Vec<String>>) -> bool {
    v.is_some()
}

fn masked_frag(family: i64, which: &str, a: &Addr) -> String {
    format!(
        "{} {} & {} {} {} ",
        ipproto(family),
        which,
        a.mask.as_deref().unwrap_or(""),
        if a.invert { "!=" } else { "==" },
        a.addr
    )
}

fn limit_frag(l: &Limit, burst: Option<crate::val::Num>) -> String {
    let mut s = format!("limit rate {}/{}", num(l.rate), l.unit);
    if let Some(b) = burst {
        if b.as_f64() != 0.0 {
            s.push_str(&format!(" burst {} packets", num(b)));
        }
    }
    s.push(' ');
    s
}

fn time_frags(
    start_date: Option<&DateTime>,
    stop_date: Option<&DateTime>,
    start_time: Option<&Time>,
    stop_time: Option<&Time>,
    weekdays: Option<&Weekdays>,
    out: &mut String,
) {
    match (start_date, stop_date) {
        (Some(a), Some(b)) => write!(out, "meta time {}-{} ", datestamp(a), datestamp(b))
            .expect("writing to String cannot fail"),
        (Some(a), None) => {
            write!(out, "meta time >= {} ", datestamp(a)).expect("writing to String cannot fail")
        }
        (None, Some(b)) => {
            write!(out, "meta time <= {} ", datestamp(b)).expect("writing to String cannot fail")
        }
        _ => {}
    }
    match (start_time, stop_time) {
        (Some(a), Some(b)) => write!(out, "meta hour {}-{} ", time(a), time(b))
            .expect("writing to String cannot fail"),
        (Some(a), None) => {
            write!(out, "meta hour >= {} ", time(a)).expect("writing to String cannot fail")
        }
        (None, Some(b)) => {
            write!(out, "meta hour <= {} ", time(b)).expect("writing to String cannot fail")
        }
        _ => {}
    }
    if let Some(w) = weekdays {
        write!(
            out,
            "meta day{} {} ",
            if w.invert { " !=" } else { "" },
            set(&w.days, false)
        )
        .expect("writing to String cannot fail");
    }
}

fn mark_frag(m: &Mark, out: &mut String) {
    if m.mask < 0xFFFF_FFFF {
        write!(
            out,
            "meta mark and {} {} {} ",
            hex(m.mask),
            if m.invert { "!=" } else { "==" },
            hex(m.mark)
        )
        .expect("writing to String cannot fail");
    } else {
        write!(
            out,
            "meta mark{} {} ",
            if m.invert { " !=" } else { "" },
            hex(m.mark)
        )
        .expect("writing to String cannot fail");
    }
}

fn setmatch_frag(sm: &SetMatch, out: &mut String) {
    write!(
        out,
        "{}{} @{} ",
        concat(sm.fields.as_deref().unwrap_or(&[])),
        if sm.invert { " !=" } else { "" },
        sm.name
    )
    .expect("writing to String cannot fail");
}

fn xmark_expr(x: &Mark) -> String {
    if x.mask == 0xFFFF_FFFF {
        hex(x.mark)
    } else if x.mark == 0 {
        format!("mark and {}", hex(!x.mask & 0xFFFF_FFFF))
    } else if x.mark == x.mask {
        format!("mark or {}", hex(x.mark))
    } else if x.mask == 0 {
        format!("mark xor {}", hex(x.mark))
    } else {
        format!(
            "mark and {} xor {}",
            hex(!x.mask & 0xFFFF_FFFF),
            hex(x.mark)
        )
    }
}

/// `{% fw4.includes(...) %}` on its own line.
fn inc(fw: &Fw4, position: &str, chain: Option<&str>, out: &mut String) {
    fw.write_includes(position, chain, out);
}

impl Fw4 {
    fn zone(&self, i: Option<usize>) -> Option<&Zone> {
        i.and_then(|i| self.state.zones.get(i))
    }

    // ------------------------------------------------------------ rule.uc

    pub fn render_rule(&self, zone: Option<usize>, rule: &Rule, out: &mut String) {
        if rule.family != 0 && !rule.has_addrs {
            write!(out, "meta nfproto {} ", nfproto(rule.family, false))
                .expect("writing to String cannot fail");
        }
        if !rule.proto.any
            && !rule.has_ports
            && rule.icmp_types.is_none()
            && rule.icmp_codes.is_none()
        {
            write!(out, "meta l4proto {} ", l4proto(rule.family, &rule.proto))
                .expect("writing to String cannot fail");
        }
        if optional(rule.iifnames.as_ref()) {
            write!(out, "iifname {} ", opt_set(rule.iifnames.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(rule.oifnames.as_ref()) {
            write!(out, "oifname {} ", opt_set(rule.oifnames.as_ref()))
                .expect("writing to String cannot fail");
        }
        let ipp = ipproto(rule.family);
        if optional(rule.saddrs_pos.as_ref()) {
            write!(out, "{ipp} saddr {} ", opt_set(rule.saddrs_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(rule.saddrs_neg.as_ref()) {
            write!(out, "{ipp} saddr != {} ", opt_set(rule.saddrs_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        for a in rule.saddrs_masked.iter().flatten() {
            out.push_str(&masked_frag(rule.family, "saddr", a));
        }
        if optional(rule.daddrs_pos.as_ref()) {
            write!(out, "{ipp} daddr {} ", opt_set(rule.daddrs_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(rule.daddrs_neg.as_ref()) {
            write!(out, "{ipp} daddr != {} ", opt_set(rule.daddrs_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        for a in rule.daddrs_masked.iter().flatten() {
            out.push_str(&masked_frag(rule.family, "daddr", a));
        }
        let pn = rule.proto.name();
        if optional(rule.sports_pos.as_ref()) {
            write!(out, "{pn} sport {} ", opt_set(rule.sports_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(rule.sports_neg.as_ref()) {
            write!(out, "{pn} sport != {} ", opt_set(rule.sports_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(rule.dports_pos.as_ref()) {
            write!(out, "{pn} dport {} ", opt_set(rule.dports_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(rule.dports_neg.as_ref()) {
            write!(out, "{pn} dport != {} ", opt_set(rule.dports_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(rule.smacs_pos.as_ref()) {
            write!(out, "ether saddr {} ", opt_set(rule.smacs_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(rule.smacs_neg.as_ref()) {
            write!(out, "ether saddr != {} ", opt_set(rule.smacs_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        let icmp = if rule.family == 4 { "icmp" } else { "icmpv6" };
        if let Some(t) = &rule.icmp_types {
            write!(out, "{icmp} type {} ", set_i64(t, false))
                .expect("writing to String cannot fail");
        }
        if let Some(c) = &rule.icmp_codes {
            write!(out, "{icmp} type . {icmp} code {} ", set(c, true))
                .expect("writing to String cannot fail");
        }
        if let Some(h) = &rule.helper {
            write!(
                out,
                "ct helper{} {} ",
                if h.invert { " !=" } else { "" },
                quote(&h.helper.name, true)
            )
            .expect("writing to String cannot fail");
        }
        if let Some(l) = &rule.limit {
            out.push_str(&limit_frag(l, rule.limit_burst));
        }
        time_frags(
            rule.start_date.as_ref(),
            rule.stop_date.as_ref(),
            rule.start_time.as_ref(),
            rule.stop_time.as_ref(),
            rule.weekdays.as_ref(),
            out,
        );
        if let Some(m) = &rule.mark {
            mark_frag(m, out);
        }
        if let Some(d) = &rule.dscp {
            write!(
                out,
                "{ipp} dscp{} {} ",
                if d.invert { " !=" } else { "" },
                hex(d.dscp)
            )
            .expect("writing to String cannot fail");
        }
        if let Some(sm) = &rule.ipset {
            setmatch_frag(sm, out);
        }
        let zone_limit = self.zone(zone).and_then(|z| z.log_limit.as_ref());
        if let (Some(log), Some(ll)) = (&rule.log, &rule.log_limit) {
            write!(
                out,
                "limit rate {}/{} log prefix {}\n\t\t",
                num(ll.rate),
                ll.unit,
                quote(log, true)
            )
            .expect("writing to String cannot fail");
            let mut inner = rule.clone();
            inner.log = None;
            self.render_rule(zone, &inner, out);
        } else if let (Some(log), Some(z)) = (&rule.log, zone_limit.and(self.zone(zone))) {
            write!(
                out,
                "limit name \"{}.log_limit\" log prefix {}\n\t\t",
                z.name,
                quote(log, true)
            )
            .expect("writing to String cannot fail");
            let mut inner = rule.clone();
            inner.log = None;
            self.render_rule(zone, &inner, out);
        } else {
            if rule.counter {
                out.push_str("counter ");
            }
            if let Some(log) = &rule.log {
                write!(out, "log prefix {} ", quote(log, true))
                    .expect("writing to String cannot fail");
            }
            match rule.target.as_deref() {
                Some("mark") => {
                    let x = rule.set_xmark.clone().unwrap_or(Mark {
                        invert: false,
                        mark: 0,
                        mask: 0xFFFF_FFFF,
                    });
                    write!(out, "meta mark set {} ", xmark_expr(&x))
                        .expect("writing to String cannot fail");
                }
                Some("dscp") => write!(
                    out,
                    "{ipp} dscp set {} ",
                    hex(rule.set_dscp.as_ref().map(|d| d.dscp).unwrap_or(0))
                )
                .expect("writing to String cannot fail"),
                Some("notrack") => out.push_str("notrack "),
                Some("helper") => write!(
                    out,
                    "ct helper set {} ",
                    quote(
                        rule.set_helper
                            .as_ref()
                            .map(|h| h.helper.name.as_str())
                            .unwrap_or("null"),
                        true
                    )
                )
                .expect("writing to String cannot fail"),
                _ => {
                    if let Some(j) = &rule.jump_chain {
                        write!(out, "jump {j} ").expect("writing to String cannot fail");
                    } else if let Some(t) = &rule.target {
                        write!(out, "{t} ").expect("writing to String cannot fail");
                    }
                }
            }
            writeln!(
                out,
                "comment {}",
                quote(&format!("!fw4: {}", rule.name), true)
            )
            .expect("writing to String cannot fail");
        }
    }

    // ------------------------------------------------------------ redirect.uc

    pub fn render_redirect(&self, zone: Option<usize>, r: &Redirect, out: &mut String) {
        if r.family != 0 && !r.has_addrs {
            write!(out, "meta nfproto {} ", nfproto(r.family, false))
                .expect("writing to String cannot fail");
        }
        if !r.proto.any && !r.has_ports {
            let name = if r.proto.name() == "icmp" && r.family == 6 {
                "ipv6-icmp"
            } else {
                r.proto.name()
            };
            write!(out, "meta l4proto {name} ").expect("writing to String cannot fail");
        }
        if let Some(d) = &r.device {
            write!(out, "oifname {} ", quote(d, true)).expect("writing to String cannot fail");
        }
        let ipp = ipproto(r.family);
        if optional(r.saddrs_pos.as_ref()) {
            write!(out, "{ipp} saddr {} ", opt_set(r.saddrs_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(r.saddrs_neg.as_ref()) {
            write!(out, "{ipp} saddr != {} ", opt_set(r.saddrs_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        for a in r.saddrs_masked.iter().flatten() {
            out.push_str(&masked_frag(r.family, "saddr", a));
        }
        if optional(r.daddrs_pos.as_ref()) {
            write!(out, "{ipp} daddr {} ", opt_set(r.daddrs_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(r.daddrs_neg.as_ref()) {
            write!(out, "{ipp} daddr != {} ", opt_set(r.daddrs_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        for a in r.daddrs_masked.iter().flatten() {
            out.push_str(&masked_frag(r.family, "daddr", a));
        }
        let pn = r.proto.name();
        if optional(r.sports_pos.as_ref()) {
            write!(out, "{pn} sport {} ", opt_set(r.sports_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(r.sports_neg.as_ref()) {
            write!(out, "{pn} sport != {} ", opt_set(r.sports_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(r.dports_pos.as_ref()) {
            write!(out, "{pn} dport {} ", opt_set(r.dports_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(r.dports_neg.as_ref()) {
            write!(out, "{pn} dport != {} ", opt_set(r.dports_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(r.smacs_pos.as_ref()) {
            write!(out, "ether saddr {} ", opt_set(r.smacs_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(r.smacs_neg.as_ref()) {
            write!(out, "ether saddr != {} ", opt_set(r.smacs_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        if let Some(h) = &r.helper {
            write!(
                out,
                "ct helper{} {} ",
                if h.invert { " !=" } else { "" },
                quote(&h.helper.name, true)
            )
            .expect("writing to String cannot fail");
        }
        if let Some(l) = &r.limit {
            out.push_str(&limit_frag(l, r.limit_burst));
        }
        time_frags(
            r.start_date.as_ref(),
            r.stop_date.as_ref(),
            r.start_time.as_ref(),
            r.stop_time.as_ref(),
            r.weekdays.as_ref(),
            out,
        );
        if let Some(m) = &r.mark {
            mark_frag(m, out);
        }
        if let Some(sm) = &r.ipset {
            setmatch_frag(sm, out);
        }
        let zone_limit = self.zone(zone).and_then(|z| z.log_limit.as_ref());
        if let (Some(log), Some(ll)) = (&r.log, &r.log_limit) {
            write!(
                out,
                "limit rate {}/{} log prefix {}\n\t\t",
                num(ll.rate),
                ll.unit,
                quote(log, true)
            )
            .expect("writing to String cannot fail");
            let mut inner = r.clone();
            inner.log = None;
            self.render_redirect(zone, &inner, out);
        } else if let (Some(log), Some(z)) = (&r.log, zone_limit.and(self.zone(zone))) {
            write!(
                out,
                "limit name \"{}.log_limit\" log prefix {}\n\t\t",
                z.name,
                quote(log, true)
            )
            .expect("writing to String cannot fail");
            let mut inner = r.clone();
            inner.log = None;
            self.render_redirect(zone, &inner, out);
        } else {
            if r.counter {
                out.push_str("counter ");
            }
            if let Some(log) = &r.log {
                write!(out, "log prefix {} ", quote(log, true))
                    .expect("writing to String cannot fail");
            }
            match r.target.as_str() {
                "redirect" => {
                    out.push_str("redirect");
                    if let Some(p) = &r.rport {
                        write!(out, " to {}", port(p)).expect("writing to String cannot fail");
                    }
                }
                "accept" | "masquerade" => out.push_str(&r.target),
                _ => {
                    write!(
                        out,
                        "{} {}",
                        r.target,
                        r.raddr
                            .as_ref()
                            .map(|a| host(a, r.rport.is_some()))
                            .unwrap_or_default()
                    )
                    .expect("writing to String cannot fail");
                    if let Some(p) = &r.rport {
                        write!(out, ":{}", port(p)).expect("writing to String cannot fail");
                    }
                }
            }
            writeln!(
                out,
                " comment {}",
                quote(&format!("!fw4: {}", r.name), true)
            )
            .expect("writing to String cannot fail");
        }
    }

    // ------------------------------------------------------------ zone-*.uc

    fn render_zone_match(&self, egress: bool, mr: &MatchRule, out: &mut String) {
        let ifn = if egress { "oifname" } else { "iifname" };
        let dir = if egress { "daddr" } else { "saddr" };
        if optional(mr.devices_pos.as_ref()) {
            write!(out, "{ifn} {} ", opt_set(mr.devices_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(mr.devices_neg.as_ref()) {
            write!(out, "{ifn} != {} ", opt_set(mr.devices_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        for w in mr.devices_neg_wildcard.iter().flatten() {
            write!(out, "{ifn} != {} ", quote(w, false)).expect("writing to String cannot fail");
        }
        let ipp = ipproto(mr.family);
        if optional(mr.subnets_pos.as_ref()) {
            write!(out, "{ipp} {dir} {} ", opt_set(mr.subnets_pos.as_ref()))
                .expect("writing to String cannot fail");
        }
        if optional(mr.subnets_neg.as_ref()) {
            write!(out, "{ipp} {dir} != {} ", opt_set(mr.subnets_neg.as_ref()))
                .expect("writing to String cannot fail");
        }
        for a in mr.subnets_masked.iter().flatten() {
            out.push_str(&masked_frag(mr.family, dir, a));
        }
    }

    fn render_zone_jump(&self, zone: &Zone, mr: &MatchRule, direction: &str, out: &mut String) {
        if mr.family != 0 {
            write!(out, "meta nfproto {} ", nfproto(mr.family, false))
                .expect("writing to String cannot fail");
        }
        self.render_zone_match(direction == "output" || direction == "srcnat", mr, out);
        writeln!(
            out,
            "jump {direction}_{} comment \"!fw4: Handle {} {} {direction} {}\"",
            zone.name,
            zone.name,
            nfproto(mr.family, true),
            if direction == "helper" {
                "assignment"
            } else {
                "traffic"
            }
        )
        .expect("writing to String cannot fail");
    }

    fn render_zone_verdict(
        &self,
        zone: &Zone,
        log: i64,
        mr: &MatchRule,
        egress: bool,
        verdict: &str,
        out: &mut String,
    ) {
        if mr.family != 0 {
            write!(out, "meta nfproto {} ", nfproto(mr.family, false))
                .expect("writing to String cannot fail");
        }
        self.render_zone_match(egress, mr, out);
        let inout = if egress { "out" } else { "in" };
        if verdict != "accept" && (log & 1) != 0 && zone.log_limit.is_some() {
            write!(
                out,
                "limit name \"{}.log_limit\" log prefix \"{verdict} {} {inout}: \"\n\t\t",
                zone.name, zone.name
            )
            .expect("writing to String cannot fail");
            self.render_zone_verdict(zone, 0, mr, egress, verdict, out);
        } else {
            if zone.counter {
                out.push_str("counter ");
            }
            if verdict != "accept" && (log & 1) != 0 {
                write!(out, "log prefix \"{verdict} {} {inout}: \" ", zone.name)
                    .expect("writing to String cannot fail");
            }
            if verdict == "reject" {
                writeln!(
                    out,
                    "jump handle_reject comment \"!fw4: reject {} {} traffic\"",
                    zone.name,
                    nfproto(mr.family, true)
                )
                .expect("writing to String cannot fail");
            } else {
                writeln!(
                    out,
                    "{verdict} comment \"!fw4: {verdict} {} {} traffic\"",
                    zone.name,
                    nfproto(mr.family, true)
                )
                .expect("writing to String cannot fail");
            }
        }
    }

    fn render_zone_masq(
        &self,
        zone: &Zone,
        family: i64,
        saddrs: &SubnetGroup,
        daddrs: &SubnetGroup,
        out: &mut String,
    ) {
        write!(out, "meta nfproto {} ", nfproto(family, false))
            .expect("writing to String cannot fail");
        let ipp = ipproto(family);
        let cidrs = |v: &Vec<Addr>| -> Vec<String> { v.iter().map(cidr).collect() };
        if let Some(v) = &saddrs.0 {
            write!(out, "{ipp} saddr {} ", set(&cidrs(v), false))
                .expect("writing to String cannot fail");
        }
        if let Some(v) = &saddrs.1 {
            write!(out, "{ipp} saddr != {} ", set(&cidrs(v), false))
                .expect("writing to String cannot fail");
        }
        for a in saddrs.2.iter().flatten() {
            out.push_str(&masked_frag(family, "saddr", a));
        }
        if let Some(v) = &daddrs.0 {
            write!(out, "{ipp} daddr {} ", set(&cidrs(v), false))
                .expect("writing to String cannot fail");
        }
        if let Some(v) = &daddrs.1 {
            write!(out, "{ipp} daddr != {} ", set(&cidrs(v), false))
                .expect("writing to String cannot fail");
        }
        for a in daddrs.2.iter().flatten() {
            out.push_str(&masked_frag(family, "daddr", a));
        }
        writeln!(
            out,
            "masquerade comment \"!fw4: Masquerade {} {} traffic\"",
            nfproto(family, true),
            zone.name
        )
        .expect("writing to String cannot fail");
    }

    fn render_zone_drop_invalid(&self, zone: &Zone, log: i64, mr: &MatchRule, out: &mut String) {
        if zone.masq != zone.masq6 {
            write!(
                out,
                "meta nfproto {} ",
                nfproto(if zone.masq { 4 } else { 6 }, false)
            )
            .expect("writing to String cannot fail");
        }
        self.render_zone_match(true, mr, out);
        out.push_str("ct state invalid ");
        if (log & 1) != 0 && zone.log_limit.is_some() {
            write!(
                out,
                "limit name \"{}.log_limit\" log prefix \"drop {} invalid ct state: \"\n\t\t",
                zone.name, zone.name
            )
            .expect("writing to String cannot fail");
            self.render_zone_drop_invalid(zone, 0, mr, out);
        } else {
            if zone.counter {
                out.push_str("counter ");
            }
            if (log & 1) != 0 {
                write!(out, "log prefix \"drop {} invalid ct state: \" ", zone.name)
                    .expect("writing to String cannot fail");
            }
            out.push_str("drop comment \"!fw4: Prevent NAT leakage\"\n");
        }
    }

    fn render_zone_mssfix(&self, zone: &Zone, mr: &MatchRule, egress: bool, out: &mut String) {
        if mr.family != 0 {
            write!(out, "meta nfproto {} ", nfproto(mr.family, false))
                .expect("writing to String cannot fail");
        }
        self.render_zone_match(egress, mr, out);
        out.push_str("tcp flags syn / syn,fin,rst tcp option maxseg size set rt mtu ");
        if (zone.log_bits() & 2) != 0 {
            write!(out, "log prefix \"MSSFIX {} out: \" ", zone.name)
                .expect("writing to String cannot fail");
        }
        writeln!(
            out,
            "comment \"!fw4: Zone {} {} {} MTU fixing\"",
            zone.name,
            nfproto(mr.family, true),
            if egress { "egress" } else { "ingress" }
        )
        .expect("writing to String cannot fail");
    }

    // ------------------------------------------------------------ offload / nft state

    fn nft_json_command(&self, args: &str) -> Vec<Json> {
        let cmd = format!("/usr/sbin/nft --terse --json {args}");
        let text =
            match self.inputs.popen_read(&cmd) {
                Ok(text) => text,
                Err(error) => {
                    self.raw_warn(&format!(
                    "Unable to popen() [ \"/usr/sbin/nft\", \"--terse\", \"--json\", {} ]: {}\n",
                    args.split(' ').map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(", "),
                    crate::input::fs_error(&error)
                ));
                    return vec![];
                }
            };
        match owrt_ubus::json::parse(&text) {
            Ok(j) => j
                .get("nftables")
                .and_then(Json::as_array)
                .map(|a| {
                    a.iter()
                        .filter(|i| matches!(i, Json::Object(_)) && i.get("metainfo").is_none())
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
            Err(e) => {
                self.raw_warn(&format!("Unable to parse nftables JSON output: {e}\n"));
                vec![]
            }
        }
    }

    pub fn check_flowtable(&self) -> bool {
        // The kernel answers the predicate directly; the nft child stays the
        // fallback (and the only path under the mock backend's fixtures).
        if !self.inputs.is_mock() {
            if let Some(exists) = crate::flowtable::exists("fw4", "ft") {
                return exists;
            }
        }
        self.nft_json_command("list flowtables inet")
            .iter()
            .any(|item| {
                item.get("flowtable")
                    .map(|f| {
                        f.get("table").and_then(Json::as_str) == Some("fw4")
                            && f.get("name").and_then(Json::as_str) == Some("ft")
                    })
                    .unwrap_or(false)
            })
    }

    /// `check_set_types()`: set name -> nft type list for table fw4.
    pub fn check_set_types(&self) -> Vec<(String, Vec<String>)> {
        let mut sets = Vec::new();
        for item in self.nft_json_command("list sets inet") {
            let Some(set) = item.get("set") else { continue };
            if set.get("table").and_then(Json::as_str) != Some("fw4") {
                continue;
            }
            let name = set.get("name").map(crate::val::to_str).unwrap_or_default();
            let types = match set.get("type") {
                Some(Json::Array(a)) => a.iter().map(crate::val::to_str).collect(),
                Some(t) => vec![crate::val::to_str(t)],
                None => vec!["null".into()],
            };
            sets.push((name, types));
        }
        sets
    }

    fn resolve_lower_devices(&self, devstatus: &Json, devname: &str) -> Vec<String> {
        let mut devs = Vec::new();
        let Some(entries) = self.inputs.opendir(&format!("/sys/class/net/{devname}")) else {
            return devs;
        };
        let devtype = devstatus
            .get(devname)
            .and_then(|d| d.get("devtype"))
            .and_then(Json::as_str);
        match devtype {
            Some("vlan") | Some("bridge") => {
                for e in entries {
                    if let Some(lower) = e.strip_prefix("lower_") {
                        devs.extend(self.resolve_lower_devices(devstatus, lower));
                    }
                }
            }
            _ => devs.push(devname.to_owned()),
        }
        devs
    }

    fn nft_try_hw_offload(&self, devices: &[String]) -> bool {
        let test = format!(
            "\n\t\tadd table inet fw4-hw-offload-test;\n\t\tadd flowtable inet fw4-hw-offload-test ft {{\n\t\t\thook ingress priority 0;\n\t\t\tdevices = {{ \"{}\" }};\n\t\t\tflags offload;\n\t\t}}\n\t",
            devices.join("\", \"")
        );
        let cmd = format!(
            "/usr/sbin/nft -c '{}' 2>/dev/null",
            test.replace('\'', "'\\''")
        );
        self.inputs.system(&cmd) == 0
    }

    fn sort_uniq(mut v: Vec<String>) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        v.retain(|d| {
            if seen.contains(d) {
                false
            } else {
                seen.push(d.clone());
                true
            }
        });
        v.sort();
        v
    }

    fn resolve_hw_offload_devices(&mut self) -> Option<Vec<String>> {
        if !self.defaults().flow_offloading_hw.unwrap_or(false) {
            return None;
        }
        let devstatus = self
            .inputs
            .ubus_call("network.device", "status", None)
            .unwrap_or(Json::Object(vec![]));
        let mut devices: Option<Vec<String>> = None;
        let physdevs: Vec<String> = self
            .state
            .zones
            .iter()
            .flat_map(|z| z.related_physdevs.clone())
            .collect();
        for device in physdevs {
            devices
                .get_or_insert_with(Vec::new)
                .extend(self.resolve_lower_devices(&devstatus, &device));
        }
        let devices = Self::sort_uniq(devices?);
        if !self.nft_try_hw_offload(&devices) {
            self.warn("Hardware flow offloading unavailable, falling back to software offloading");
            if let Some(d) = self.state.defaults.as_mut() {
                d.flow_offloading_hw = Some(false);
            }
            return None;
        }
        Some(devices)
    }

    pub fn resolve_offload_devices(&mut self) -> Vec<String> {
        if !self.defaults().flow_offloading.unwrap_or(false) {
            return vec![];
        }
        if let Some(d) = self.resolve_hw_offload_devices() {
            return d;
        }
        let mut devices = Vec::new();
        for z in &self.state.zones {
            for device in &z.related_physdevs {
                if self.inputs.access(&format!("/sys/class/net/{device}")) {
                    devices.push(device.clone());
                }
            }
        }
        Self::sort_uniq(devices)
    }

    // ------------------------------------------------------------ ruleset.uc

    fn chain_rules(&self, chain: &str, zone: Option<usize>, out: &mut String) {
        for rule in self.rules(chain) {
            out.push_str("\t\t");
            self.render_rule(zone, rule, out);
        }
    }

    fn zone_jumps(&self, direction: &str, only_flag: Option<&str>, out: &mut String) {
        for zone in &self.state.zones {
            if let Some(f) = only_flag {
                if !zone.dflags.has(f) {
                    continue;
                }
            }
            for mr in &zone.match_rules {
                out.push_str("\t\t");
                self.render_zone_jump(zone, mr, direction, out);
            }
        }
    }

    fn loopback_filtered(&self, mr: &MatchRule, invert: bool) -> MatchRule {
        let mut m = mr.clone();
        m.devices_pos = self.filter_loopback_devs(mr.devices_pos.as_ref(), invert);
        m.subnets_pos = self.filter_loopback_addrs(mr.subnets_pos.as_ref(), invert);
        m
    }

    pub fn render_ruleset(&mut self) -> String {
        let flowtable_devices = self.resolve_offload_devices();
        let available_helpers: Vec<&Helper> =
            self.state.helpers.iter().filter(|h| h.available).collect();
        let defined_ipsets = &self.state.ipsets;
        let zones_with_limits: Vec<&Zone> = self
            .state
            .zones
            .iter()
            .filter(|z| z.log_limit.is_some())
            .collect();
        let d = self.defaults();
        let drop_invalid = d.drop_invalid.unwrap_or(false);
        let synflood = d.synflood_protect.unwrap_or(false) && d.synflood_rate.is_some();
        let mut out = String::new();

        out.push_str("table inet fw4\nflush table inet fw4\n");
        if self.check_flowtable() {
            out.push_str("delete flowtable inet fw4 ft\n");
        }
        inc(self, "ruleset-prepend", None, &mut out);
        out.push_str("\ntable inet fw4 {\n");
        if !flowtable_devices.is_empty() {
            out.push_str(
                "\t#\n\t# Flowtable\n\t#\n\n\tflowtable ft {\n\t\thook ingress priority 0;\n",
            );
            writeln!(
                out,
                "\t\tdevices = {};\n\t\tcounter;",
                set(&flowtable_devices, true)
            )
            .expect("writing to String cannot fail");
            if self.defaults().flow_offloading_hw.unwrap_or(false) {
                out.push_str("\t\tflags offload;\n");
            }
            out.push_str("\t}\n\n\n");
        }
        if !available_helpers.is_empty() {
            out.push_str("\t#\n\t# CT helper definitions\n\t#\n\n");
            for helper in &available_helpers {
                for proto in helper.proto.iter().flatten() {
                    writeln!(
                        out,
                        "\tct helper {} {{\n\t\ttype {} protocol {};\n\t}}\n",
                        helper.name,
                        quote(&helper.name, true),
                        proto.name()
                    )
                    .expect("writing to String cannot fail");
                }
            }
            out.push('\n');
        }
        if !defined_ipsets.is_empty() {
            out.push_str("\t#\n\t# Set definitions\n\t#\n\n");
            for set_ in defined_ipsets {
                writeln!(out, "\tset {} {{", set_.name).expect("writing to String cannot fail");
                if let Some(c) = set_.comment.as_deref().filter(|c| !c.is_empty()) {
                    writeln!(out, "\t\tcomment {}", quote(c, true))
                        .expect("writing to String cannot fail");
                }
                writeln!(out, "\t\ttype {}", concat(&set_.types))
                    .expect("writing to String cannot fail");
                if set_.maxelem.map(|m| m.as_f64() > 0.0).unwrap_or(false) {
                    writeln!(out, "\t\tsize {}", num(set_.maxelem.unwrap()))
                        .expect("writing to String cannot fail");
                }
                if set_.timeout.as_f64() > 0.0 {
                    writeln!(out, "\t\ttimeout {}s", num(set_.timeout))
                        .expect("writing to String cannot fail");
                }
                if set_.interval {
                    out.push_str("\t\tauto-merge\n");
                }
                if let Some(f) = &set_.flags {
                    writeln!(out, "\t\tflags {}", f.join(","))
                        .expect("writing to String cannot fail");
                }
                self.print_setentries(set_, &mut out);
                out.push_str("\t}\n\n");
            }
            out.push('\n');
        }
        out.push_str("\t#\n\t# Defines\n\t#\n\n");
        for zone in &self.state.zones {
            let n = if zone.name.starts_with(|c: char| c.is_ascii_digit()) {
                format!("_{}", zone.name)
            } else {
                zone.name.clone()
            };
            writeln!(
                out,
                "\tdefine {n}_devices = {}",
                set(&zone.match_devices, true)
            )
            .expect("writing to String cannot fail");
            writeln!(
                out,
                "\tdefine {n}_subnets = {}\n",
                set(&zone.match_subnets, true)
            )
            .expect("writing to String cannot fail");
        }
        out.push('\n');
        if !zones_with_limits.is_empty() {
            out.push_str("\t#\n\t# Limits\n\t#\n\n");
            for zone in &zones_with_limits {
                let l = zone.log_limit.as_ref().unwrap();
                writeln!(
                    out,
                    "\tlimit {}.log_limit {{\n\t\tcomment \"{} log limit\"\n\t\trate {}/{}\n\t}}\n",
                    zone.name,
                    zone.name,
                    num(l.rate),
                    l.unit
                )
                .expect("writing to String cannot fail");
            }
            out.push('\n');
        }
        out.push_str("\t#\n\t# User includes\n\t#\n\n\tinclude \"/etc/nftables.d/*.nft\"\n");
        inc(self, "table-prepend", None, &mut out);
        out.push_str("\n\n\t#\n\t# Filter rules\n\t#\n\n");

        let vmap = |comment: &str| {
            format!(
                "\t\tct state vmap {{ established : accept, related : accept{} }} comment \"!fw4: {comment}\"\n",
                if drop_invalid { ", invalid : drop" } else { "" }
            )
        };

        // input
        writeln!(out,
            "\tchain input {{\n\t\ttype filter hook input priority filter; policy {};\n\n\t\tiif \"lo\" accept comment \"!fw4: Accept traffic from loopback\"\n",
            self.input_policy(true)
        ).expect("writing to String cannot fail");
        inc(self, "chain-prepend", Some("input"), &mut out);
        out.push_str(&vmap("Handle inbound flows"));
        if synflood {
            out.push_str("\t\ttcp flags & (fin | syn | rst | ack) == syn jump syn_flood comment \"!fw4: Rate limit TCP syn packets\"\n");
        }
        self.chain_rules("input", None, &mut out);
        self.zone_jumps("input", None, &mut out);
        if self.input_policy(false) == "reject" {
            out.push_str("\t\tjump handle_reject\n");
        }
        inc(self, "chain-append", Some("input"), &mut out);
        out.push_str("\t}\n\n");

        // forward
        writeln!(
            out,
            "\tchain forward {{\n\t\ttype filter hook forward priority filter; policy {};\n",
            self.forward_policy(true)
        )
        .expect("writing to String cannot fail");
        if !flowtable_devices.is_empty() {
            out.push_str("\t\tmeta l4proto { tcp, udp } flow offload @ft;\n");
        }
        inc(self, "chain-prepend", Some("forward"), &mut out);
        out.push_str(&vmap("Handle forwarded flows"));
        for rule in self.rules("forward") {
            let src_zone = rule.src.and_then(|z| z.zone);
            let zone = if src_zone
                .and_then(|i| self.state.zones[i].log_limit.as_ref())
                .is_some()
            {
                src_zone
            } else {
                rule.dest.and_then(|z| z.zone)
            };
            out.push_str("\t\t");
            self.render_rule(zone, rule, &mut out);
        }
        self.zone_jumps("forward", None, &mut out);
        inc(self, "chain-append", Some("forward"), &mut out);
        if self.forward_policy(false) == "reject" {
            out.push_str("\t\tjump handle_reject\n");
        }
        out.push_str("\t}\n\n");

        // output
        writeln!(out,
            "\tchain output {{\n\t\ttype filter hook output priority filter; policy {};\n\n\t\toif \"lo\" accept comment \"!fw4: Accept traffic towards loopback\"\n",
            self.output_policy(true)
        ).expect("writing to String cannot fail");
        inc(self, "chain-prepend", Some("output"), &mut out);
        out.push_str(&vmap("Handle outbound flows"));
        self.chain_rules("output", None, &mut out);
        for zone in &self.state.zones {
            for mr in &zone.match_rules {
                if zone.dflags.has("helper") {
                    let m = self.loopback_filtered(mr, true);
                    if m.devices_pos.is_some() || m.subnets_pos.is_some() {
                        out.push_str("\t\t");
                        self.render_zone_jump(zone, &m, "helper", &mut out);
                    }
                }
                out.push_str("\t\t");
                self.render_zone_jump(zone, mr, "output", &mut out);
            }
        }
        inc(self, "chain-append", Some("output"), &mut out);
        if self.output_policy(false) == "reject" {
            out.push_str("\t\tjump handle_reject\n");
        }
        out.push_str("\t}\n\n");

        // prerouting
        out.push_str("\tchain prerouting {\n\t\ttype filter hook prerouting priority filter; policy accept;\n");
        for zone in &self.state.zones {
            if zone.dflags.has("helper") {
                for mr in &zone.match_rules {
                    let m = self.loopback_filtered(mr, false);
                    if mr.devices_neg.is_some()
                        || mr.subnets_neg.is_some()
                        || m.devices_pos.is_some()
                        || m.subnets_pos.is_some()
                    {
                        out.push_str("\t\t");
                        self.render_zone_jump(zone, &m, "helper", &mut out);
                    }
                }
            }
        }
        out.push_str("\t}\n\n");

        // handle_reject
        let reject_with = |code: Option<&str>| match code {
            Some("tcp-reset") => "tcp reset".to_owned(),
            Some(c) => format!("icmpx type {c}"),
            None => "icmpx type ".to_owned(),
        };
        writeln!(out,
            "\tchain handle_reject {{\n\t\tmeta l4proto tcp reject with {} comment \"!fw4: Reject TCP traffic\"\n\t\treject with {} comment \"!fw4: Reject any other traffic\"\n\t}}\n",
            reject_with(d.tcp_reject_code.as_deref()),
            reject_with(d.any_reject_code.as_deref())
        ).expect("writing to String cannot fail");
        if synflood {
            let r = d.synflood_rate.as_ref().unwrap();
            write!(
                out,
                "\tchain syn_flood {{\n\t\tlimit rate {}/{}",
                num(r.rate),
                r.unit
            )
            .expect("writing to String cannot fail");
            if let Some(b) = d.synflood_burst.filter(|b| b.as_f64() != 0.0) {
                write!(out, " burst {} packets", num(b)).expect("writing to String cannot fail");
            }
            out.push_str(" return comment \"!fw4: Accept SYN packets below rate-limit\"\n\t\tdrop comment \"!fw4: Drop excess packets\"\n\t}\n\n");
        }

        // per-zone chains
        let nzones = self.state.zones.len();
        for zi in 0..nzones {
            let zone = &self.state.zones[zi];
            let n = &zone.name;
            writeln!(out, "\tchain input_{n} {{").expect("writing to String cannot fail");
            inc(self, "chain-prepend", Some(&format!("input_{n}")), &mut out);
            self.chain_rules(&format!("input_{n}"), Some(zi), &mut out);
            if zone.dflags.has("dnat") {
                out.push_str(
                    "\t\tct status dnat accept comment \"!fw4: Accept port redirections\"\n",
                );
            }
            inc(self, "chain-append", Some(&format!("input_{n}")), &mut out);
            writeln!(out, "\t\tjump {}_from_{n}\n\t}}\n", zone.input)
                .expect("writing to String cannot fail");

            writeln!(out, "\tchain output_{n} {{").expect("writing to String cannot fail");
            inc(
                self,
                "chain-prepend",
                Some(&format!("output_{n}")),
                &mut out,
            );
            self.chain_rules(&format!("output_{n}"), Some(zi), &mut out);
            inc(self, "chain-append", Some(&format!("output_{n}")), &mut out);
            writeln!(out, "\t\tjump {}_to_{n}\n\t}}\n", zone.output)
                .expect("writing to String cannot fail");

            writeln!(out, "\tchain forward_{n} {{").expect("writing to String cannot fail");
            inc(
                self,
                "chain-prepend",
                Some(&format!("forward_{n}")),
                &mut out,
            );
            self.chain_rules(&format!("forward_{n}"), Some(zi), &mut out);
            if zone.dflags.has("dnat") {
                out.push_str("\t\tct status dnat accept comment \"!fw4: Accept port forwards\"\n");
            }
            inc(
                self,
                "chain-append",
                Some(&format!("forward_{n}")),
                &mut out,
            );
            writeln!(out, "\t\tjump {}_to_{n}", zone.forward)
                .expect("writing to String cannot fail");
            if self.forward_policy(false) != "accept" && (zone.log_bits() & 1) != 0 {
                out.push_str("\t\t");
                if zone.log_limit.is_some() {
                    write!(out, "limit name \"{n}.log_limit\" ")
                        .expect("writing to String cannot fail");
                }
                writeln!(
                    out,
                    "log prefix \"{} {n} forward: \"",
                    self.forward_policy(false)
                )
                .expect("writing to String cannot fail");
            }
            out.push_str("\t}\n\n");

            if zone.dflags.has("helper") {
                writeln!(out, "\tchain helper_{n} {{").expect("writing to String cannot fail");
                self.chain_rules(&format!("helper_{n}"), Some(zi), &mut out);
                out.push_str("\t}\n\n");
            }
            for verdict in ["accept", "reject", "drop"] {
                if zone.sflags.has(verdict) {
                    writeln!(out, "\tchain {verdict}_from_{n} {{")
                        .expect("writing to String cannot fail");
                    for mr in &zone.match_rules {
                        out.push_str("\t\t");
                        self.render_zone_verdict(
                            zone,
                            zone.log_bits(),
                            mr,
                            false,
                            verdict,
                            &mut out,
                        );
                    }
                    out.push_str("\t}\n\n");
                }
                if zone.dflags.has(verdict) {
                    writeln!(out, "\tchain {verdict}_to_{n} {{")
                        .expect("writing to String cannot fail");
                    for mr in &zone.match_rules {
                        if !drop_invalid
                            && verdict == "accept"
                            && (zone.masq || zone.masq6)
                            && !zone.masq_allow_invalid
                        {
                            out.push_str("\t\t");
                            self.render_zone_drop_invalid(zone, zone.log_bits(), mr, &mut out);
                        }
                        out.push_str("\t\t");
                        self.render_zone_verdict(
                            zone,
                            zone.log_bits(),
                            mr,
                            true,
                            verdict,
                            &mut out,
                        );
                    }
                    out.push_str("\t}\n\n");
                }
            }
        }

        // NAT
        out.push_str("\n\t#\n\t# NAT rules\n\t#\n\n\tchain dstnat {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n");
        inc(self, "chain-prepend", Some("dstnat"), &mut out);
        self.zone_jumps("dstnat", Some("dnat"), &mut out);
        inc(self, "chain-append", Some("dstnat"), &mut out);
        out.push_str("\t}\n\n\tchain srcnat {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n");
        inc(self, "chain-prepend", Some("srcnat"), &mut out);
        for r in self.redirects("srcnat") {
            out.push_str("\t\t");
            self.render_redirect(None, r, &mut out);
        }
        self.zone_jumps("srcnat", Some("snat"), &mut out);
        inc(self, "chain-append", Some("srcnat"), &mut out);
        out.push_str("\t}\n\n");
        for zi in 0..nzones {
            let zone = &self.state.zones[zi];
            let n = &zone.name;
            if zone.dflags.has("dnat") {
                writeln!(out, "\tchain dstnat_{n} {{").expect("writing to String cannot fail");
                inc(
                    self,
                    "chain-prepend",
                    Some(&format!("dstnat_{n}")),
                    &mut out,
                );
                for r in self.redirects(&format!("dstnat_{n}")) {
                    out.push_str("\t\t");
                    self.render_redirect(Some(zi), r, &mut out);
                }
                inc(self, "chain-append", Some(&format!("dstnat_{n}")), &mut out);
                out.push_str("\t}\n\n");
            }
            if zone.dflags.has("snat") {
                writeln!(out, "\tchain srcnat_{n} {{").expect("writing to String cannot fail");
                inc(
                    self,
                    "chain-prepend",
                    Some(&format!("srcnat_{n}")),
                    &mut out,
                );
                for r in self.redirects(&format!("srcnat_{n}")) {
                    out.push_str("\t\t");
                    self.render_redirect(Some(zi), r, &mut out);
                }
                if zone.masq {
                    for saddrs in &zone.masq4_src_subnets {
                        for daddrs in &zone.masq4_dest_subnets {
                            out.push_str("\t\t");
                            self.render_zone_masq(zone, 4, saddrs, daddrs, &mut out);
                        }
                    }
                }
                if zone.masq6 {
                    for saddrs in &zone.masq6_src_subnets {
                        for daddrs in &zone.masq6_dest_subnets {
                            out.push_str("\t\t");
                            self.render_zone_masq(zone, 6, saddrs, daddrs, &mut out);
                        }
                    }
                }
                inc(self, "chain-append", Some(&format!("srcnat_{n}")), &mut out);
                out.push_str("\t}\n\n");
            }
        }

        // raw
        out.push_str("\n\t#\n\t# Raw rules (notrack)\n\t#\n\n\tchain raw_prerouting {\n\t\ttype filter hook prerouting priority raw; policy accept;\n");
        for zone in &self.state.zones {
            if zone.dflags.has("notrack") {
                for mr in &zone.match_rules {
                    let m = self.loopback_filtered(mr, false);
                    if mr.devices_neg.is_some()
                        || mr.subnets_neg.is_some()
                        || m.devices_pos.is_some()
                        || m.subnets_pos.is_some()
                    {
                        out.push_str("\t\t");
                        self.render_zone_jump(zone, &m, "notrack", &mut out);
                    }
                }
            }
        }
        inc(self, "chain-append", Some("raw_prerouting"), &mut out);
        out.push_str("\t}\n\n\tchain raw_output {\n\t\ttype filter hook output priority raw; policy accept;\n");
        inc(self, "chain-prepend", Some("raw_output"), &mut out);
        for zone in &self.state.zones {
            if zone.dflags.has("notrack") {
                for mr in &zone.match_rules {
                    let m = self.loopback_filtered(mr, true);
                    if m.devices_pos.is_some() || m.subnets_pos.is_some() {
                        out.push_str("\t\t");
                        self.render_zone_jump(zone, &m, "notrack", &mut out);
                    }
                }
            }
        }
        inc(self, "chain-append", Some("raw_output"), &mut out);
        out.push_str("\t}\n\n");
        for zi in 0..nzones {
            let zone = &self.state.zones[zi];
            if zone.dflags.has("notrack") {
                writeln!(out, "\tchain notrack_{} {{", zone.name)
                    .expect("writing to String cannot fail");
                self.chain_rules(&format!("notrack_{}", zone.name), Some(zi), &mut out);
                out.push_str("\t}\n\n");
            }
        }

        // mangle
        out.push_str("\n\t#\n\t# Mangle rules\n\t#\n\n\tchain mangle_prerouting {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n");
        inc(self, "chain-prepend", Some("mangle_prerouting"), &mut out);
        self.chain_rules("mangle_prerouting", None, &mut out);
        inc(self, "chain-append", Some("mangle_prerouting"), &mut out);
        out.push_str("\t}\n\n\tchain mangle_postrouting {\n\t\ttype filter hook postrouting priority mangle; policy accept;\n");
        inc(self, "chain-prepend", Some("mangle_postrouting"), &mut out);
        self.chain_rules("mangle_postrouting", None, &mut out);
        for zone in &self.state.zones {
            if zone.mtu_fix {
                for mr in &zone.match_rules {
                    out.push_str("\t\t");
                    self.render_zone_mssfix(zone, mr, true, &mut out);
                }
            }
        }
        inc(self, "chain-append", Some("mangle_postrouting"), &mut out);
        out.push_str("\t}\n\n\tchain mangle_input {\n\t\ttype filter hook input priority mangle; policy accept;\n");
        inc(self, "chain-prepend", Some("mangle_input"), &mut out);
        self.chain_rules("mangle_input", None, &mut out);
        inc(self, "chain-append", Some("mangle_input"), &mut out);
        out.push_str("\t}\n\n\tchain mangle_output {\n\t\ttype route hook output priority mangle; policy accept;\n");
        inc(self, "chain-prepend", Some("mangle_output"), &mut out);
        self.chain_rules("mangle_output", None, &mut out);
        inc(self, "chain-append", Some("mangle_output"), &mut out);
        out.push_str("\t}\n\n\tchain mangle_forward {\n\t\ttype filter hook forward priority mangle; policy accept;\n");
        inc(self, "chain-prepend", Some("mangle_forward"), &mut out);
        self.chain_rules("mangle_forward", None, &mut out);
        for zone in &self.state.zones {
            if zone.mtu_fix {
                for mr in &zone.match_rules {
                    out.push_str("\t\t");
                    self.render_zone_mssfix(zone, mr, false, &mut out);
                }
            }
        }
        inc(self, "chain-append", Some("mangle_forward"), &mut out);
        out.push_str("\t}\n");
        inc(self, "table-append", None, &mut out);
        out.push_str("}\n");
        inc(self, "ruleset-append", None, &mut out);
        out
    }
}

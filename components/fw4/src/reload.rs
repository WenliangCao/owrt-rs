//! A reload may retain an already installed ruleset. This is deliberately not
//! an nft parser: only generated, unreferenced zone definitions are discarded.
//! The saved kernel listing guards against external changes or a removed table.

use crate::parse::Fw4;
use owrt_ubus::json::{self, Json};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CACHE: &str = "/var/run/fw4.reload-state";
const TEMP: &str = "/var/run/fw4.reload-state.tmp";

/// NFT_MSG_GETGEN (16) / NFT_MSG_NEWGEN (15), NFTA_GEN_ID (1), from the
/// matching Linux nf_tables UAPI. It advances once per committed transaction.
pub fn generation() -> Option<u32> {
    const SEQ: u32 = 0x6677_3401;
    let mut request = [0u8; 20];
    request[..4].copy_from_slice(&20u32.to_ne_bytes());
    request[4..6].copy_from_slice(&((10u16 << 8) | 16).to_ne_bytes());
    request[6..8].copy_from_slice(&1u16.to_ne_bytes());
    request[8..12].copy_from_slice(&SEQ.to_ne_bytes());
    let reply = crate::flowtable::exchange(&request)?;
    if reply.len() < 28
        || u32::from_ne_bytes(reply[..4].try_into().ok()?) as usize != reply.len()
        || u16::from_ne_bytes(reply[4..6].try_into().ok()?) != (10 << 8) | 15
        || u32::from_ne_bytes(reply[8..12].try_into().ok()?) != SEQ
    {
        return None;
    }
    let mut attrs = &reply[20..];
    while attrs.len() >= 4 {
        let length = u16::from_ne_bytes(attrs[..2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(attrs[2..4].try_into().ok()?) & 0x3fff;
        if length < 4 || length > attrs.len() {
            return None;
        }
        if kind == 1 && length == 8 {
            return Some(u32::from_be_bytes(attrs[4..8].try_into().ok()?));
        }
        attrs = attrs.get(((length + 3) & !3)..)?;
    }
    None
}

fn comments_only(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    text.lines().all(|line| {
        let line = line.trim();
        // A backslash can continue an nft logical line. Reject it even in a
        // comment rather than depending on lexer continuation ordering.
        line.is_empty() || (line.starts_with('#') && !line.contains('\\'))
    })
}

type Metadata = (u64, u64, i64, i64, i64, i64, u64);

fn metadata(path: &Path, follow: bool) -> io::Result<Option<Metadata>> {
    let result = if follow {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    match result {
        Ok(m) => Ok(Some((
            m.dev(),
            m.ino(),
            m.ctime(),
            m.ctime_nsec(),
            m.mtime(),
            m.mtime_nsec(),
            m.size(),
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

struct InputStamp {
    path: PathBuf,
    link: Option<Metadata>,
    target: Option<Metadata>,
    comments: bool,
}

impl InputStamp {
    fn current(&self) -> bool {
        let same = || {
            metadata(&self.path, false).ok() == Some(self.link)
                && metadata(&self.path, true).ok() == Some(self.target)
        };
        same()
            && (!self.comments || fs::read(&self.path).is_ok_and(|b| comments_only(&b)))
            && same()
    }
}

pub struct Eligible {
    rules: String,
    inputs: Vec<InputStamp>,
}

fn track(inputs: &mut Vec<InputStamp>, path: &Path, comments: bool) -> Option<()> {
    let input = InputStamp {
        path: path.into(),
        link: metadata(path, false).ok()?,
        target: metadata(path, true).ok()?,
        comments,
    };
    if !input.current() {
        return None;
    }
    inputs.push(input);
    // Parent stamps catch wildcard additions/removals and atomic replacement,
    // including swapping a path away and back before the final check.
    if let Some(parent) = path.parent() {
        track(inputs, parent, false)?;
    }
    Some(())
}

fn empty_user_includes(inputs: &mut Vec<InputStamp>) -> Option<()> {
    track(inputs, Path::new("/etc/nftables.d"), false)?;
    let entries = match fs::read_dir("/etc/nftables.d") {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Some(()),
        Err(_) => return None,
    };
    for entry in entries {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let name = name.to_str()?;
        if !name.starts_with('.') && name.ends_with(".nft") {
            track(inputs, &entry.path(), true)?;
        }
    }
    Some(())
}

pub fn effective_rules(fw: &Fw4, ruleset: &str) -> Option<Eligible> {
    // Mock fixtures retain their exact upstream trace/CLI contract. Named
    // sets can have external or expiring members; their reset is not elided.
    if fw.inputs.is_mock() || !fw.state.ipsets.is_empty() {
        return None;
    }
    // Even an ignored/unreachable user script prevents certification. It can
    // become reachable between parsing and the includes phase.
    if fw
        .firewall
        .of_type("include")
        .any(|inc| inc.get("type").and_then(Json::as_str).unwrap_or("script") != "nftables")
    {
        return None;
    }
    let mut inputs = Vec::new();
    for inc in &fw.state.includes {
        if inc.ty != "nftables" {
            return None;
        }
        track(&mut inputs, Path::new(&inc.path), true)?;
    }
    empty_user_includes(&mut inputs)?;
    if !inputs.iter().all(InputStamp::current) {
        return None;
    }
    let names: Vec<String> = fw
        .state
        .zones
        .iter()
        .flat_map(|zone| {
            let name = if zone.name.starts_with(|c: char| c.is_ascii_digit()) {
                format!("_{}", zone.name)
            } else {
                zone.name.clone()
            };
            [format!("{name}_devices"), format!("{name}_subnets")]
        })
        .collect();
    Some(Eligible {
        rules: without_unused_defines(ruleset, &names),
        inputs,
    })
}

fn without_unused_defines(ruleset: &str, names: &[String]) -> String {
    let unused: Vec<String> = names
        .iter()
        // A prefix match may conservatively retain a definition. It cannot
        // discard a referenced definition, including one referenced by a define.
        .filter(|name| !ruleset.contains(&format!("${name}")))
        .map(|name| format!("\tdefine {name} = "))
        .collect();
    ruleset
        .split_inclusive('\n')
        .filter(|line| !unused.iter().any(|prefix| line.starts_with(prefix)))
        .collect()
}

fn kernel_rules() -> Option<String> {
    let output = Command::new("nft")
        // Stateless output excludes changing packet/byte counters. Flowtable
        // definitions remain in the comparison; live flows are retained.
        .args(["-s", "list", "table", "inet", "fw4"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    if !text.starts_with("table inet fw4 {") || !text.ends_with("}\n") {
        return None;
    }
    Some(text)
}

pub fn unchanged(effective: &Eligible) -> bool {
    let Some(saved) = fs::read_to_string(CACHE)
        .ok()
        .and_then(|s| json::parse(&s).ok())
    else {
        return false;
    };
    if saved.get("version").and_then(Json::as_str) != Some("1")
        || saved.get("effective").and_then(Json::as_str) != Some(effective.rules.as_str())
    {
        return false;
    }
    let Some(before) = generation() else {
        return false;
    };
    let Some(kernel) = kernel_rules() else {
        return false;
    };
    generation() == Some(before)
        && saved.get("kernel").and_then(Json::as_str) == Some(kernel.as_str())
        && effective.inputs.iter().all(InputStamp::current)
}

pub fn invalidate() {
    let _ = fs::remove_file(CACHE);
}

pub fn remember(effective: &Eligible, before_apply: u32) {
    let Some(expected) = before_apply.checked_add(1) else {
        return;
    };
    if generation() != Some(expected) || !effective.inputs.iter().all(InputStamp::current) {
        return;
    }
    let Some(kernel) = kernel_rules() else { return };
    // Never pair our candidate with an external change between apply and
    // snapshot. Concurrent writers make this reload ineligible for caching.
    if generation() != Some(expected) || !effective.inputs.iter().all(InputStamp::current) {
        return;
    }
    let saved = Json::Object(vec![
        ("version".into(), Json::Str("1".into())),
        ("effective".into(), Json::Str(effective.rules.clone())),
        ("kernel".into(), Json::Str(kernel)),
    ])
    .to_compact();
    // The caller holds fw4.lock. Rename commits both exact byte strings at
    // once, and a crash or write failure can only lose the optimization.
    let result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(TEMP)?;
        file.write_all(saved.as_bytes())?;
        fs::rename(TEMP, CACHE)
    })();
    if result.is_err() {
        let _ = fs::remove_file(TEMP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unreferenced_generated_definitions_are_ignored() {
        let names = vec!["wan_subnets".into(), "wan_devices".into()];
        let a = "\tdefine wan_subnets = { 2001:db8::/64 }\n\tdefine wan_devices = { \"eth0\" }\n\tiifname $wan_devices accept\n";
        let b = a.replace("2001:db8::/64", "2001:db8:1::/64");
        assert_eq!(
            without_unused_defines(a, &names),
            without_unused_defines(&b, &names)
        );
        let used_a = format!("{a}ip6 saddr $wan_subnets accept\n");
        let used_b = format!("{b}ip6 saddr $wan_subnets accept\n");
        assert_ne!(
            without_unused_defines(&used_a, &names),
            without_unused_defines(&used_b, &names)
        );
        assert!(without_unused_defines(a, &names).contains("define wan_devices"));
        assert_eq!(without_unused_defines(a, &[]), a);
        let referenced_by_define = format!("{a}\tdefine alias = $wan_subnets\n");
        assert_eq!(
            without_unused_defines(&referenced_by_define, &names),
            referenced_by_define
        );
    }

    #[test]
    fn includes_must_be_only_comments_without_continuations() {
        assert!(comments_only(b"# custom filter chains\n  # no rules\n\n"));
        for text in [
            b"# comment\naccept\n".as_slice(),
            b"include \"other\"\n",
            b"# continued\\\n",
            b"# invalid \xff\n",
        ] {
            assert!(!comments_only(text));
        }
    }
}

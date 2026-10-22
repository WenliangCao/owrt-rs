//! Byte-oriented dnsmasq 2.93 configuration primitives.
//!
//! Option metadata is a contract index, not a claim that the runtime implements
//! each option. Callers must reject `ScalarConfig::apply`'s unhandled options
//! until their owning subsystem implements them.

pub mod auth;
pub mod dhcp;
pub mod dhcp_device;
pub mod dhcp_network;
pub mod dhcp_pxe;
pub mod dhcp_relay;
pub mod dns;
pub mod domains;
pub mod dump;
pub mod edns;
pub mod ethers;
pub mod interface_records;
#[cfg(unix)]
pub mod loader;
pub mod logging;
mod options;
pub mod records;
pub(crate) mod rrtypes;
mod scalar;
pub mod script_arp;
pub mod synth_domain;
pub mod tftp;
pub mod ubus;

pub use options::OPTIONS;
pub use scalar::{FastRetry, ScalarConfig, StaleCache};

use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Argument {
    None,
    Required,
    Optional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Repeat {
    Boolean,
    Repeatable,
    OncePerOrigin,
}

#[derive(Clone, Copy, Debug)]
pub struct OptionSpec {
    pub name: &'static str,
    /// Shared by aliases, e.g. dhcp-leasefile and dhcp-lease.
    pub id: &'static str,
    pub argument: Argument,
    pub repeat: Repeat,
    pub short: Option<u8>,
    /// Capability exists in the target build; this does not mean implemented.
    pub available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(pub &'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

/// C option.c:619-660 uses hidden metacharacters until semantic parsing.
/// Keeping this representation prevents quoted commas becoming separators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedArg(Vec<u8>);

const META: &[u8] = b"\x00123456 \x08\t\n78\r90abcdefABCDE\x1bF:,.";

impl EncodedArg {
    /// Command-line arguments are not subject to configuration-file quoting.
    pub fn command_line(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn encoded(&self) -> &[u8] {
        &self.0
    }

    pub fn decoded(&self) -> Vec<u8> {
        self.0
            .iter()
            .map(|&c| META.get(c as usize).copied().unwrap_or(c))
            .collect()
    }

    /// Split the first delimiter, retaining the encoded tail. Consumers such
    /// as domain= decode the tail before applying additional separators.
    pub fn split_once(&self, delimiter: u8) -> (Self, Option<Self>) {
        let Some(at) = self.0.iter().position(|&c| c == delimiter) else {
            return (self.clone(), None);
        };
        let mut end = at;
        while end > 0 && self.0[end - 1] == b' ' {
            end -= 1;
        }
        let mut start = at + 1;
        while self.0.get(start) == Some(&b' ') {
            start += 1;
        }
        (
            Self(self.0[..end].to_vec()),
            Some(Self(self.0[start..].to_vec())),
        )
    }

    /// C split_chr: trim ordinary spaces adjacent to each delimiter, leaving
    /// quoted spaces and delimiters hidden until the consumer decodes them.
    pub fn split(&self, delimiter: u8) -> Vec<Self> {
        let mut parts: Vec<Self> = self
            .0
            .split(|&c| c == delimiter)
            .map(|part| Self(part.to_vec()))
            .collect();
        let count = parts.len();
        for (index, part) in parts.iter_mut().enumerate() {
            if index != 0 {
                let first = part
                    .0
                    .iter()
                    .position(|&c| c != b' ')
                    .unwrap_or(part.0.len());
                part.0.drain(..first);
            }
            if index + 1 != count {
                while part.0.last() == Some(&b' ') {
                    part.0.pop();
                }
            }
        }
        parts
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Directive {
    pub name: Vec<u8>,
    pub argument: Option<EncodedArg>,
}

fn white(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Parse one physical configuration line, following option.c:5471-5597.
/// Input remains bytes: paths and TXT data need not be UTF-8. C ignores bytes
/// following an embedded NUL in the line; the reference behavior is retained.
/// The scanner is linear; C repeatedly memmoves the remaining line per quote.
pub fn lex_line(line: &[u8]) -> Result<Option<Directive>, Error> {
    let Some(argument) = lex_argument_line(line)? else {
        return Ok(None);
    };
    let value = argument.encoded();
    let directive = if let Some(equal) = value.iter().position(|&c| c == b'=') {
        let name_end = value[..equal]
            .iter()
            .rposition(|&c| c != b' ' && c != b'=')
            .map(|n| n + 1)
            .unwrap_or(0);
        let mut arg_start = equal + 1;
        while value.get(arg_start) == Some(&b' ') {
            arg_start += 1;
        }
        Directive {
            name: value[..name_end].to_vec(),
            argument: Some(EncodedArg(value[arg_start..].to_vec())),
        }
    } else {
        Directive {
            name: value.to_vec(),
            argument: None,
        }
    };
    Ok(Some(directive))
}

/// The same scanner with option.c's hard-option boundary: a nonempty line is
/// one argument, including ordinary '=' bytes. DHCP data files use this path.
pub fn lex_argument_line(line: &[u8]) -> Result<Option<EncodedArg>, Error> {
    let line = &line[..line
        .iter()
        .position(|&c| c == 0 || c == b'\n')
        .unwrap_or(line.len())];
    let mut out = Vec::with_capacity(line.len());
    let mut i = 0;
    let mut was_white = true;
    while i < line.len() {
        if line[i] == b'"' {
            i += 1;
            while i < line.len() && line[i] != b'"' {
                let mut c = line[i];
                if c == b'\\' && i + 1 < line.len() {
                    let escaped = match line[i + 1] {
                        b't' => Some(b'\t'),
                        b'n' => Some(b'\n'),
                        b'b' => Some(0x08),
                        b'r' => Some(b'\r'),
                        b'e' => Some(0x1b),
                        b'"' => Some(b'"'),
                        b'\\' => Some(b'\\'),
                        _ => None,
                    };
                    if let Some(value) = escaped {
                        c = value;
                        i += 1;
                    }
                }
                out.push(
                    META.iter()
                        .position(|&m| m == c)
                        .map(|n| n as u8)
                        .unwrap_or(c),
                );
                i += 1;
            }
            if i == line.len() {
                return Err(Error("missing \""));
            }
            i += 1;
            // C processes the byte immediately after a closing quote as an
            // ordinary byte in this same loop iteration, including another
            // quote. Preserve that edge case rather than invent shell syntax.
            if i == line.len() {
                break;
            }
        }
        let c = line[i];
        if white(c) {
            out.push(b' ');
            was_white = true;
        } else {
            if was_white && c == b'#' {
                break;
            }
            out.push(c);
            was_white = false;
        }
        i += 1;
    }
    let start = out.iter().position(|&c| c != b' ').unwrap_or(out.len());
    let end = out
        .iter()
        .rposition(|&c| c != b' ')
        .map(|n| n + 1)
        .unwrap_or(start);
    if start == end {
        return Ok(None);
    }
    out.truncate(end);
    out.drain(..start);
    Ok(Some(EncodedArg(out)))
}

pub fn lookup(name: &[u8]) -> Option<&'static OptionSpec> {
    OPTIONS
        .binary_search_by(|spec| spec.name.as_bytes().cmp(name))
        .ok()
        .map(|i| &OPTIONS[i])
}

/// Lexical option and argument validation only. Semantic/variant validation
/// remains the owning subsystem's responsibility (C also separates them).
pub fn validate_directive(directive: &Directive) -> Result<&'static OptionSpec, Error> {
    let spec = lookup(&directive.name).ok_or(Error("bad option"))?;
    match (spec.argument, directive.argument.is_some()) {
        (Argument::None, true) => Err(Error("extraneous parameter")),
        (Argument::Required, false) => Err(Error("missing parameter")),
        _ => Ok(spec),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    CommandLine,
    File,
}

/// C one_opt:2023-2050: file scalars may override CLI once; aliases share a
/// repetition slot. File/includes share one origin, not one slot per file.
/// `record` returns false when a later CLI scalar is ignored after a file.
#[derive(Default)]
pub struct OccurrenceTracker {
    seen: HashMap<&'static str, Origin>,
}

impl OccurrenceTracker {
    pub fn record(&mut self, spec: &OptionSpec, origin: Origin) -> Result<bool, Error> {
        if spec.repeat != Repeat::OncePerOrigin {
            return Ok(true);
        }
        if self.seen.get(spec.id) == Some(&origin) {
            return Err(Error(match origin {
                Origin::CommandLine => "illegal repeated flag",
                Origin::File => "illegal repeated keyword",
            }));
        }
        // A later CLI option after an immediately loaded extra -C file is
        // skipped by C's ARG_USED_FILE branch, retaining the file value.
        if self.seen.get(spec.id) == Some(&Origin::File) && origin == Origin::CommandLine {
            return Ok(false);
        }
        self.seen.insert(spec.id, origin);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg(line: &[u8]) -> EncodedArg {
        lex_line(line).unwrap().unwrap().argument.unwrap()
    }

    #[test]
    fn exact_quote_comment_and_split_rules() {
        assert_eq!(lex_line(b" \t# ignored").unwrap(), None);
        assert_eq!(
            arg(b"txt-record = test,\" a,b#c \", tail # ignored")
                .split(b',')
                .iter()
                .map(EncodedArg::decoded)
                .collect::<Vec<_>>(),
            [b"test".to_vec(), b" a,b#c ".to_vec(), b"tail".to_vec()]
        );
        assert_eq!(arg(b"server=127.0.0.1#5300").decoded(), b"127.0.0.1#5300");
        assert_eq!(
            arg(b"txt-record=\"\\t\\n\\e\\b\\r\\\\\\\"\\q\"").decoded(),
            b"\t\n\x1b\x08\r\\\"\\q"
        );
        assert_eq!(arg(b"pid-file=\xff\x00ignored").decoded(), b"\xff");
        assert_eq!(lex_line(b"txt-record=\"a\"\"b\""), Err(Error("missing \"")));
        assert_eq!(
            lex_line(b"txt-record=\"unterminated"),
            Err(Error("missing \""))
        );
    }

    #[test]
    fn empty_argument_differs_from_absent_and_arity_is_exact() {
        assert_eq!(
            validate_directive(&lex_line(b"port").unwrap().unwrap()).unwrap_err(),
            Error("missing parameter")
        );
        assert!(validate_directive(&lex_line(b"port=").unwrap().unwrap()).is_ok());
        assert_eq!(
            validate_directive(&lex_line(b"no-hosts=").unwrap().unwrap()).unwrap_err(),
            Error("extraneous parameter")
        );
        assert!(validate_directive(&lex_line(b"enable-ubus").unwrap().unwrap()).is_ok());
        assert!(validate_directive(&lex_line(b"filter-AAAA").unwrap().unwrap()).is_ok());
        assert!(lookup(b"filter-aaaa").is_none());
    }

    #[test]
    fn aliases_and_origin_override_share_repetition_slot() {
        let mut tracker = OccurrenceTracker::default();
        tracker
            .record(lookup(b"dhcp-leasefile").unwrap(), Origin::CommandLine)
            .unwrap();
        assert!(tracker
            .record(lookup(b"dhcp-lease").unwrap(), Origin::CommandLine)
            .is_err());
        tracker
            .record(lookup(b"dhcp-lease").unwrap(), Origin::File)
            .unwrap();
        assert!(tracker
            .record(lookup(b"dhcp-leasefile").unwrap(), Origin::File)
            .is_err());
        tracker
            .record(lookup(b"server").unwrap(), Origin::File)
            .unwrap();
        tracker
            .record(lookup(b"server").unwrap(), Origin::File)
            .unwrap();
    }

    #[test]
    fn sorted_exhaustive_metadata_has_explicit_variant_boundary() {
        assert_eq!(OPTIONS.len(), 195);
        assert!(OPTIONS.windows(2).all(|pair| pair[0].name < pair[1].name));
        for name in [
            "enable-tftp",
            "bootp-dynamic",
            "pxe-service",
            "leasequery",
            "dhcp-relay",
            "proxy-dnssec",
        ] {
            assert!(lookup(name.as_bytes()).unwrap().available);
        }
        for name in ["dnssec", "enable-ra", "nftset", "enable-dbus"] {
            assert!(!lookup(name.as_bytes()).unwrap().available);
        }
    }

    /// Run on a host with the exact patched C reference. Only config parsing
    /// is exercised: --test exits before sockets, privilege changes, or DHCP.
    #[test]
    #[ignore = "requires DNSMASQ_C_REFERENCE pointing to exact C 2.93 build"]
    fn scalar_config_acceptance_matches_c() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let reference = std::env::var_os("DNSMASQ_C_REFERENCE").expect("DNSMASQ_C_REFERENCE");
        let cases = [
            "port=53",
            "port=",
            "port",
            "port=65535",
            "port=65536",
            "port=-1",
            "port= 53 # trailing comment",
            "port=53#not-comment",
            "port=\"53\"",
            "port=53\nport=54",
            "cache-size=0",
            "cache-size=5000001",
            "cache-size",
            "cache-size=",
            "cache-size=\"123\"",
            "edns-packet-max=65536",
            "edns-packet-max=511",
            "edns-packet-max=1,2",
            "fast-dns-retry",
            "fast-dns-retry=50,1999",
            "fast-dns-retry=49",
            "fast-dns-retry=50,",
            "fast-dns-retry=50,1000,2000",
            "use-stale-cache",
            "use-stale-cache=0",
            "use-stale-cache=-1",
            "min-cache-ttl=4000",
            "local-ttl=",
            "max-tcp-connections=0",
            "max-tcp-connections=1",
            "query-port=0",
            "port-limit=0",
            "port-limit=1",
            "port=\"5\"\"3\"",
            "port=\"unterminated",
            "unknown-setting=1",
        ];
        let mut successes = 0;
        let mut failures = 0;
        for text in cases {
            let mut config = ScalarConfig::default();
            let mut tracker = OccurrenceTracker::default();
            let rust_ok = text
                .as_bytes()
                .split(|&c| c == b'\n')
                .try_for_each(|line| {
                    if let Some(directive) = lex_line(line)? {
                        let spec = validate_directive(&directive)?;
                        if tracker.record(spec, Origin::File)? && !config.apply(&directive)? {
                            return Err(Error("unhandled option in differential corpus"));
                        }
                    }
                    Ok::<(), Error>(())
                })
                .is_ok();
            let mut child = Command::new(&reference)
                .args(["--test", "--conf-file=-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn exact C reference");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert_eq!(
                rust_ok,
                output.status.success(),
                "config {text:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if rust_ok {
                successes += 1;
            } else {
                failures += 1;
            }
        }
        // Calibrate that the harness actually exercised both outcomes.
        assert!(
            successes > 10 && failures > 10,
            "successes={successes}, failures={failures}"
        );
        eprintln!("scalar configuration C differential: {successes} accepted, {failures} rejected, {} matched", successes + failures);
    }
}

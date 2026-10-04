use super::{validate_directive, Directive, EncodedArg, Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FastRetry {
    pub interval_ms: u32,
    pub timeout_seconds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaleCache {
    Disabled,
    Until(u32),
    Forever,
}

/// Defaults from option.c:5952-5991; each apply branch cites the C switch.
/// Fields are parser state. Runtime finalization is explicit because --test
/// exits before main clamps EDNS and checks source-port range relationships.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarConfig {
    pub cache_size: u32,
    pub dns_port: u16,
    pub forward_max: u32,
    pub edns_packet_max: u16,
    pub query_port: u16,
    pub query_port_os_assigned: bool,
    pub min_port: u16,
    pub max_port: u16,
    pub port_limit: u32,
    pub local_ttl: u32,
    pub negative_ttl: u32,
    pub max_ttl: u32,
    pub min_cache_ttl: u32,
    pub max_cache_ttl: u32,
    pub dhcp_ttl: Option<u32>,
    pub fast_retry: Option<FastRetry>,
    pub stale_cache: StaleCache,
    pub max_tcp_connections: u32,
}

impl Default for ScalarConfig {
    fn default() -> Self {
        Self {
            cache_size: 150,
            dns_port: 53,
            forward_max: 150,
            edns_packet_max: 1232,
            query_port: 0,
            query_port_os_assigned: false,
            min_port: 0,
            max_port: 0,
            port_limit: 1,
            local_ttl: 0,
            negative_ttl: 0,
            max_ttl: 0,
            min_cache_ttl: 0,
            max_cache_ttl: 0,
            dhcp_ttl: None,
            fast_retry: None,
            stale_cache: StaleCache::Disabled,
            max_tcp_connections: 30,
        }
    }
}

fn integer(argument: Option<&EncodedArg>) -> Result<u32, Error> {
    let argument = argument.ok_or(Error("missing parameter"))?.decoded();
    // numeric_check allows an empty supplied string and atoi maps it to zero.
    let mut value = 0u32;
    for c in argument {
        if !c.is_ascii_digit() {
            return Err(Error("bad integer"));
        }
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add((c - b'0') as u32))
            .filter(|&v| v <= i32::MAX as u32)
            .ok_or(Error("integer exceeds defined C int range"))?;
    }
    Ok(value)
}

fn dhcp_ttl(argument: Option<&EncodedArg>) -> Result<u32, Error> {
    let argument = argument.ok_or(Error("missing parameter"))?.decoded();
    let mut value = 0u32;
    for c in argument {
        if !c.is_ascii_digit() {
            return Err(Error("error"));
        }
        // option.c uses atoi_check. The exact image's musl atoi wraps to
        // 32 bits, including long decimal input; express that safely here.
        value = value.wrapping_mul(10).wrapping_add(u32::from(c - b'0'));
    }
    Ok(value)
}

fn port(argument: Option<&EncodedArg>) -> Result<u16, Error> {
    let bytes = argument.ok_or(Error("missing parameter"))?.decoded();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Error("error"));
    }
    // option.c's atoi_check16 calls musl atoi first. Long decimal input wraps
    // to a 32-bit signed int before the 0..65535 check.
    let value = bytes.iter().fold(0u32, |value, byte| {
        value.wrapping_mul(10).wrapping_add(u32::from(byte - b'0'))
    }) as i32;
    if !(0..=u16::MAX as i32).contains(&value) {
        return Err(Error("error"));
    }
    Ok(value as u16)
}

impl ScalarConfig {
    /// `false` means the owning module must handle or reject this directive.
    /// No unimplemented option is silently applied by this API.
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        validate_directive(directive)?;
        let arg = directive.argument.as_ref();
        match directive.name.as_slice() {
            // option.c:3413-3457.
            b"cache-size" => self.cache_size = integer(arg)?.min(5_000_000),
            b"port" => self.dns_port = port(arg)?,
            b"min-port" => self.min_port = port(arg)?,
            b"max-port" => self.max_port = port(arg)?,
            b"dns-forward-max" => self.forward_max = integer(arg)?,
            // option.c:3494-3550. The EDNS assignment explicitly narrows.
            b"edns-packet-max" => self.edns_packet_max = integer(arg)? as u16,
            b"query-port" => {
                self.query_port = port(arg)?;
                if self.query_port == 0 {
                    self.query_port_os_assigned = true;
                }
            }
            b"port-limit" => {
                let bytes = arg.ok_or(Error("missing parameter"))?.decoded();
                if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
                    return Err(Error("error"));
                }
                let value = bytes.iter().fold(0u32, |value, byte| {
                    value.wrapping_mul(10).wrapping_add(u32::from(byte - b'0'))
                }) as i32;
                if value < 1 {
                    return Err(Error("error"));
                }
                self.port_limit = value as u32;
            }
            b"local-ttl" => self.local_ttl = integer(arg)?,
            b"neg-ttl" => self.negative_ttl = integer(arg)?,
            b"max-ttl" => self.max_ttl = integer(arg)?,
            b"min-cache-ttl" => self.min_cache_ttl = integer(arg)?.min(3600),
            b"max-cache-ttl" => self.max_cache_ttl = integer(arg)?,
            b"dhcp-ttl" => self.dhcp_ttl = Some(dhcp_ttl(arg)?),
            // option.c:3552-3575; timeout input milliseconds truncates to sec.
            b"fast-dns-retry" => {
                let retry = if let Some(arg) = arg {
                    let parts = arg.split(b',');
                    let interval_ms = integer(parts.first()).map_err(|_| Error("error"))?;
                    if interval_ms < 50 {
                        return Err(Error("error"));
                    }
                    if parts.len() > 2 {
                        return Err(Error("error"));
                    }
                    FastRetry {
                        interval_ms,
                        timeout_seconds: if parts.len() == 2 {
                            integer(parts.get(1)).map_err(|_| Error("error"))? / 1000
                        } else {
                            10
                        },
                    }
                } else {
                    FastRetry {
                        interval_ms: 1000,
                        timeout_seconds: 10,
                    }
                };
                self.fast_retry = Some(retry);
            }
            // option.c:5335-5350, 5453-5462.
            b"use-stale-cache" => {
                self.stale_cache = match arg.map(|a| integer(Some(a))).transpose()? {
                    None => StaleCache::Until(86400),
                    Some(0) => StaleCache::Forever,
                    Some(seconds) => StaleCache::Until(seconds),
                }
            }
            b"max-tcp-connections" => {
                let value = integer(arg).map_err(|_| Error("error"))?;
                if value == 0 {
                    return Err(Error("error"));
                }
                self.max_tcp_connections = value;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// dnsmasq.c:117-118, 251-265. Call only after parser test-mode handling.
    pub fn finalize_runtime(&mut self) -> Result<(), Error> {
        self.edns_packet_max = self.edns_packet_max.max(512);
        if self.min_port != 0 && self.max_port == 0 {
            self.max_port = 65535;
        }
        if self.max_port != 0 && self.min_port == 0 {
            self.min_port = 1024;
        }
        if self.max_port < self.min_port {
            return Err(Error("max_port cannot be smaller than min_port"));
        }
        if self.max_port != 0
            && u32::from(self.max_port) - u32::from(self.min_port) + 1 < self.port_limit
        {
            return Err(Error(
                "port_limit must not be larger than available port range",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lex_line;

    fn apply(config: &mut ScalarConfig, text: &str) -> Result<bool, Error> {
        config.apply(&lex_line(text.as_bytes())?.unwrap())
    }

    #[test]
    fn defaults_limits_empty_and_explicit_zero() {
        let mut config = ScalarConfig::default();
        assert_eq!(config.cache_size, 150);
        apply(&mut config, "cache-size=6000000").unwrap();
        assert_eq!(config.cache_size, 5_000_000);
        apply(&mut config, "port=").unwrap();
        assert_eq!(config.dns_port, 0);
        assert!(!config.query_port_os_assigned);
        apply(&mut config, "query-port=0").unwrap();
        assert!(config.query_port_os_assigned);
        apply(&mut config, "min-cache-ttl=4000").unwrap();
        assert_eq!(config.min_cache_ttl, 3600);
        assert!(apply(&mut config, "port=65536").is_err());
        assert!(apply(&mut config, "local-ttl=-1").is_err());
        assert!(apply(&mut config, "local-ttl=2147483648").is_err());
    }

    #[test]
    fn dhcp_ttl_preserves_image_integer_boundaries_and_diagnostics() {
        let mut config = ScalarConfig::default();
        for (input, expected) in [
            ("", 0),
            ("2147483647", 2_147_483_647),
            ("2147483648", 2_147_483_648),
            ("4294967295", u32::MAX),
            ("4294967296", 0),
            (
                "9999999999999999999999999999999999999999999999999999999999999999",
                u32::MAX,
            ),
        ] {
            apply(&mut config, &format!("dhcp-ttl={input}")).unwrap();
            assert_eq!(config.dhcp_ttl, Some(expected));
        }
        for input in ["-1", "x"] {
            assert_eq!(
                apply(&mut config, &format!("dhcp-ttl={input}")),
                Err(Error("error"))
            );
        }
    }

    #[test]
    fn retry_stale_and_runtime_validation_are_separate() {
        let mut config = ScalarConfig::default();
        apply(&mut config, "fast-dns-retry=50,1999").unwrap();
        assert_eq!(
            config.fast_retry,
            Some(FastRetry {
                interval_ms: 50,
                timeout_seconds: 1
            })
        );
        assert!(apply(&mut config, "fast-dns-retry=49").is_err());
        apply(&mut config, "use-stale-cache=0").unwrap();
        assert_eq!(config.stale_cache, StaleCache::Forever);
        apply(&mut config, "edns-packet-max=65536").unwrap();
        assert_eq!(config.edns_packet_max, 0);
        config.finalize_runtime().unwrap();
        assert_eq!(config.edns_packet_max, 512);
        apply(&mut config, "min-port=55000").unwrap();
        apply(&mut config, "max-port=54000").unwrap();
        assert!(config.finalize_runtime().is_err());
        assert!(!apply(&mut config, "enable-tftp").unwrap());
    }
}

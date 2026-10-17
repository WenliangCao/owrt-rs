//! Configuration owned by odhcpd, with the shared dnsmasq fields left intact.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use owrt_ubus::json::Json;
use owrt_uci::{OptionValue, Package, Section};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ConfigError {}
type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostDuid {
    pub duid: Vec<u8>,
    pub iaid: Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostConfig {
    pub duids: Vec<HostDuid>,
    pub macs: Vec<[u8; 6]>,
    pub host_id: u64,
    pub ignore_v6: bool,
    pub hostname: Option<String>,
    pub lease_time: Option<u32>,
    pub ipv4: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolConfig {
    pub name: String,
    pub ifname: Option<String>,
    pub ra: bool,
    pub dhcpv6: bool,
    pub dynamic_dhcp: bool,
    pub lease_time: u32,
    pub max_preferred_lifetime: u32,
    pub max_valid_lifetime: u32,
    pub dhcpv6_assign_all: bool,
    pub dhcpv6_na: bool,
    pub dhcpv6_pd: bool,
    pub pd_min_len: u8,
    pub hostid_length: u8,
    pub ra_flags: u8,
    pub ra_slaac: bool,
    pub ra_offlink: bool,
    pub ra_preference: i8,
    pub ra_default: u8,
    pub ra_min_interval: u32,
    pub ra_max_interval: u32,
    pub ra_lifetime: u32,
    pub ra_reachable_time: u32,
    pub ra_retrans_time: u32,
    pub ra_hop_limit: u8,
    pub ra_mtu: Option<u32>,
    pub ra_dns: bool,
    pub dns_service: bool,
    pub dns: Vec<Ipv6Addr>,
    pub domains: Vec<String>,
}

impl PoolConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ifname: None,
            ra: false,
            dhcpv6: false,
            dynamic_dhcp: true,
            lease_time: 43_200,
            max_preferred_lifetime: 2700,
            max_valid_lifetime: 5400,
            dhcpv6_assign_all: true,
            dhcpv6_na: true,
            dhcpv6_pd: true,
            pd_min_len: 62,
            hostid_length: 12,
            ra_flags: 0x40,
            ra_slaac: true,
            ra_offlink: false,
            ra_preference: 0,
            ra_default: 0,
            ra_min_interval: 200,
            ra_max_interval: 600,
            ra_lifetime: 1800,
            ra_reachable_time: 0,
            ra_retrans_time: 0,
            ra_hop_limit: 0,
            ra_mtu: None,
            ra_dns: true,
            dns_service: true,
            dns: Vec::new(),
            domains: Vec::new(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.ra || self.dhcpv6
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub pools: Vec<PoolConfig>,
    pub hosts: Vec<HostConfig>,
    pub lease_file: Option<PathBuf>,
    pub hosts_dir: Option<PathBuf>,
    pub pio_dir: Option<PathBuf>,
    pub lease_trigger: Option<PathBuf>,
    pub log_level: u8,
    pub enable_tz: bool,
    pub timezone: Option<String>,
    pub zonename: Option<String>,
    pub default_duid: Option<Vec<u8>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pools: Vec::new(),
            hosts: Vec::new(),
            lease_file: None,
            hosts_dir: None,
            pio_dir: None,
            lease_trigger: None,
            log_level: 4,
            enable_tz: true,
            timezone: None,
            zonename: None,
            default_duid: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NetworkInterface {
    pub name: String,
    pub device: Option<String>,
    pub up: bool,
    pub data: Json,
}

impl Config {
    /// `-c` loads absolute filenames, matching C's exclusion of UCI deltas.
    pub fn load(directory: Option<&Path>) -> Result<Self> {
        let mut ctx = owrt_uci::Context::new();
        let mut load = |name: &str, required: bool| -> Result<Option<Package>> {
            let file = directory.map(|dir| dir.join(name));
            let name = match file.as_deref() {
                Some(file) => file
                    .to_str()
                    .ok_or_else(|| ConfigError("non-UTF8 configuration path".into()))?,
                None => name,
            };
            match owrt_uci::file::load(&mut ctx, name) {
                Ok(index) => Ok(Some(ctx.root.remove(index))),
                Err(owrt_uci::Error::NotFound) if !required => Ok(None),
                Err(error) => Err(ConfigError(format!("cannot load {name}: {error:?}"))),
            }
        };
        let network = load("network", false)?;
        let dhcp = load("dhcp", true)?.expect("required package");
        let system = load("system", false)?;
        Self::from_packages(&dhcp, network.as_ref(), system.as_ref())
    }

    pub fn from_packages(
        dhcp: &Package,
        network: Option<&Package>,
        system: Option<&Package>,
    ) -> Result<Self> {
        let mut config = Self::default();
        if let Some(network) = network {
            for section in network.sections.iter().filter(|s| s.ty == "globals") {
                if let Some(value) = text(&section_json(section)?, "dhcp_default_duid")? {
                    let duid = parse_hex(&value)?;
                    if !(10..=130).contains(&duid.len()) {
                        return Err(ConfigError("invalid server DUID length".into()));
                    }
                    config.default_duid = Some(duid);
                }
            }
        }
        for section in dhcp.sections.iter().filter(|s| s.ty == "odhcpd") {
            let data = section_json(section)?;
            if boolean(&data, "maindhcp")?.unwrap_or(false) {
                return Err(ConfigError(
                    "odhcpd DHCPv4 (maindhcp=1) is not supported".into(),
                ));
            }
            set_path(&data, "leasefile", &mut config.lease_file)?;
            set_path(&data, "hostsdir", &mut config.hosts_dir)?;
            set_path(&data, "piodir", &mut config.pio_dir)?;
            set_path(&data, "leasetrigger", &mut config.lease_trigger)?;
            if let Some(level) = number(&data, "loglevel")? {
                config.log_level = (level & 7) as u8;
            }
            if let Some(enabled) = boolean(&data, "enable_tz")? {
                config.enable_tz = enabled;
            }
        }
        for section in &dhcp.sections {
            if !matches!(section.ty.as_str(), "dhcp" | "host" | "boot6") {
                continue;
            }
            let data = section_json(section)?;
            match section.ty.as_str() {
                "dhcp" => {
                    let name = text(&data, "interface")?.unwrap_or_else(|| section.name.clone());
                    let mut pool = PoolConfig::new(name);
                    apply_pool(&mut pool, &data)?;
                    config.pools.push(pool);
                }
                "host" => config.hosts.push(host_from_json(&data)?),
                "boot6" => {
                    return Err(ConfigError(
                        "DHCPv6 PXE is outside the supported configuration".into(),
                    ))
                }
                _ => {} // Shared dnsmasq sections belong to dnsmasq.
            }
        }
        if config.enable_tz {
            if let Some(system) = system {
                for section in system.sections.iter().filter(|s| s.ty == "system") {
                    let data = section_json(section)?;
                    if let Some(value) = text(&data, "timezone")? {
                        config.timezone = timezone(value);
                    }
                    if let Some(value) = text(&data, "zonename")? {
                        config.zonename = timezone(value);
                    }
                }
            }
        }
        Ok(config)
    }

    /// Apply a freshly obtained complete netifd dump to a fresh UCI snapshot.
    /// Callers must not repeatedly apply patches to an already patched Config.
    pub fn apply_network(&mut self, interfaces: &[NetworkInterface]) -> Result<()> {
        for network in interfaces {
            if let Some(pool) = self.pools.iter_mut().find(|pool| pool.name == network.name) {
                if pool.enabled() {
                    apply_pool(pool, &network.data)?;
                }
                pool.ifname = network.device.clone();
            } else {
                let mut pool = PoolConfig::new(network.name.clone());
                apply_pool(&mut pool, &network.data)?;
                pool.ifname = network.device.clone();
                if pool.enabled() {
                    self.pools.push(pool);
                }
            }
        }
        Ok(())
    }
}

fn timezone(value: String) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    Some(
        value
            .chars()
            .map(|ch| if ch.is_ascii_whitespace() { '_' } else { ch })
            .collect(),
    )
}

fn set_path(data: &Json, key: &str, target: &mut Option<PathBuf>) -> Result<()> {
    if let Some(value) = text(data, key)? {
        *target = Some(value.into());
    }
    Ok(())
}

fn section_json(section: &Section) -> Result<Json> {
    let decode = |value: &[u8]| -> Result<Json> {
        let text = std::str::from_utf8(value)
            .map_err(|_| ConfigError(format!("{}: non-UTF8 configuration value", section.name)))?;
        if text.contains('\0') {
            return Err(ConfigError(format!(
                "{}: NUL in configuration",
                section.name
            )));
        }
        Ok(Json::Str(text.to_owned()))
    };
    let mut fields = Vec::new();
    for option in &section.options {
        let value = match &option.value {
            OptionValue::Str(value) => decode(value)?,
            OptionValue::List(values) => Json::Array(
                values
                    .iter()
                    .map(|value| decode(value))
                    .collect::<Result<_>>()?,
            ),
        };
        fields.push((option.name.clone(), value));
    }
    Ok(Json::Object(fields))
}

fn text(data: &Json, key: &str) -> Result<Option<String>> {
    let Some(value) = data.get(key) else {
        return Ok(None);
    };
    if let Some(text) = value.as_str() {
        if text.contains('\0') {
            return Err(ConfigError(format!("{key}: NUL in string")));
        }
        return Ok(Some(text.to_owned()));
    }
    if let Some(values) = value.as_array() {
        return values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ConfigError(format!("{key}: expected string list")))
            })
            .collect::<Result<Vec<_>>>()
            .map(|values| Some(values.join(" ")));
    }
    Err(ConfigError(format!("{key}: expected string")))
}

fn list(data: &Json, key: &str) -> Result<Option<Vec<String>>> {
    let Some(value) = data.get(key) else {
        return Ok(None);
    };
    if let Some(values) = value.as_array() {
        return values
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ConfigError(format!("{key}: expected string list")))
            })
            .collect::<Result<_>>()
            .map(Some);
    }
    Ok(text(data, key)?.map(|value| value.split_whitespace().map(str::to_owned).collect()))
}

fn boolean(data: &Json, key: &str) -> Result<Option<bool>> {
    if let Some(Json::Bool(value)) = data.get(key) {
        return Ok(Some(*value));
    }
    Ok(text(data, key)?
        .map(|value| matches!(value.as_str(), "1" | "true" | "on" | "yes" | "enabled")))
}

fn number(data: &Json, key: &str) -> Result<Option<u32>> {
    if let Some(Json::Int(value)) = data.get(key) {
        return u32::try_from(*value)
            .map(Some)
            .map_err(|_| ConfigError(format!("{key}: integer out of range")));
    }
    text(data, key)?
        .map(|text| {
            text.parse()
                .map_err(|_| ConfigError(format!("{key}: invalid unsigned integer")))
        })
        .transpose()
}

fn mode(data: &Json, key: &str) -> Result<Option<bool>> {
    text(data, key)?
        .map(|mode| match mode.as_str() {
            "disabled" => Ok(false),
            "server" => Ok(true),
            _ => Err(ConfigError(format!(
                "{key}: mode {mode:?} is not supported"
            ))),
        })
        .transpose()
}

fn apply_pool(pool: &mut PoolConfig, data: &Json) -> Result<()> {
    if let Some(value) = text(data, "ndp")? {
        if value != "disabled" {
            return Err(ConfigError("NDP proxy is not supported".into()));
        }
    }
    if boolean(data, "master")?.unwrap_or(false) {
        return Err(ConfigError("relay master is not supported".into()));
    }
    for key in ["ra_advrouter", "dhcpv6_pd_preferred"] {
        if boolean(data, key)?.unwrap_or(false) {
            return Err(ConfigError(format!(
                "{key} is outside the supported configuration"
            )));
        }
    }
    for key in [
        "upstream",
        "dhcpv6_raw",
        "dnr",
        "ra_pref64",
        "prefix_filter",
        "ntp",
        "captive_portal_uri",
    ] {
        if list(data, key)?.is_some_and(|values| !values.is_empty()) {
            return Err(ConfigError(format!(
                "{key} is outside the supported configuration"
            )));
        }
    }
    if let Some(value) = text(data, "ifname")?.or(text(data, "networkid")?) {
        pool.ifname = Some(value);
    }
    if let Some(value) = mode(data, "ra")? {
        pool.ra = value;
    }
    if let Some(value) = mode(data, "dhcpv6")? {
        pool.dhcpv6 = value;
    }
    // maindhcp=0: dhcpv4/start/limit are shared dnsmasq input, not a v4 request.
    for (key, target) in [
        ("dynamicdhcp", &mut pool.dynamic_dhcp),
        ("dhcpv6_assignall", &mut pool.dhcpv6_assign_all),
        ("dhcpv6_na", &mut pool.dhcpv6_na),
        ("dhcpv6_pd", &mut pool.dhcpv6_pd),
        ("ra_slaac", &mut pool.ra_slaac),
        ("ra_offlink", &mut pool.ra_offlink),
        ("ra_dns", &mut pool.ra_dns),
        ("dns_service", &mut pool.dns_service),
    ] {
        if let Some(value) = boolean(data, key)? {
            *target = value;
        }
    }
    for (key, target) in [
        ("leasetime", &mut pool.lease_time),
        ("max_preferred_lifetime", &mut pool.max_preferred_lifetime),
        ("max_valid_lifetime", &mut pool.max_valid_lifetime),
    ] {
        if let Some(value) = text(data, key)? {
            *target = parse_lease_time(&value)?;
        }
    }
    if let Some(value) = number(data, "dhcpv6_pd_min_len")? {
        pool.pd_min_len = value.min(64) as u8;
    }
    if let Some(value) = number(data, "dhcpv6_hostidlength")? {
        pool.hostid_length = value.clamp(12, 64) as u8;
    }
    if let Some(value) = number(data, "ra_default")? {
        if value > 2 {
            return Err(ConfigError("ra_default must be 0, 1 or 2".into()));
        }
        pool.ra_default = value as u8;
    }
    if let Some(value) = number(data, "ra_maxinterval")? {
        pool.ra_max_interval = value.clamp(4, 65535);
    }
    if let Some(value) = number(data, "ra_mininterval")? {
        pool.ra_min_interval = value.clamp(3, pool.ra_max_interval * 3 / 4);
    }
    if let Some(value) = number(data, "ra_lifetime")? {
        pool.ra_lifetime = if value == 0 {
            0
        } else {
            value.clamp(pool.ra_max_interval, 65535)
        };
    }
    if let Some(value) = number(data, "ra_reachabletime")? {
        pool.ra_reachable_time = value.min(3_600_000);
    }
    if let Some(value) = number(data, "ra_retranstime")? {
        pool.ra_retrans_time = value.min(60_000);
    }
    if let Some(value) = number(data, "ra_hoplimit")? {
        pool.ra_hop_limit = value.min(255) as u8;
    }
    if let Some(value) = number(data, "ra_mtu")? {
        pool.ra_mtu = Some(value.clamp(1280, 65535));
    }
    if let Some(value) = text(data, "ra_preference")? {
        pool.ra_preference = match value.as_str() {
            "medium" => 0,
            "high" => 1,
            "low" => -1,
            _ => return Err(ConfigError("invalid ra_preference".into())),
        };
    }
    if let Some(flags) = list(data, "ra_flags")? {
        pool.ra_flags = 0;
        for flag in flags {
            pool.ra_flags |= match flag.as_str() {
                "none" => 0,
                "managed-config" => 0x80,
                "other-config" => 0x40,
                _ => return Err(ConfigError(format!("unsupported RA flag {flag:?}"))),
            };
        }
    }
    if let Some(values) = list(data, "dns")? {
        pool.dns.clear();
        for value in values {
            match value.parse::<IpAddr>() {
                Ok(IpAddr::V6(address)) => pool.dns.push(address),
                Ok(IpAddr::V4(_)) => {}
                Err(_) => return Err(ConfigError("invalid DNS address".into())),
            }
        }
    }
    if let Some(values) = list(data, "domain")? {
        pool.domains.clear();
        for value in values {
            let value = value.trim_end_matches('.');
            if !hostname_valid(value) {
                return Err(ConfigError("invalid search domain".into()));
            }
            pool.domains.push(value.into());
        }
    }
    Ok(())
}

pub fn parse_lease_time(value: &str) -> Result<u32> {
    if value == "infinite" {
        return Ok(u32::MAX);
    }
    let end = value
        .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
        .unwrap_or(value.len());
    let number: f64 = value[..end]
        .parse()
        .map_err(|_| ConfigError("invalid lease duration".into()))?;
    if !number.is_finite() || number < 0.0 || number > u32::MAX as f64 {
        return Err(ConfigError("lease duration out of range".into()));
    }
    let multiplier = match value[end..].chars().next() {
        None | Some('s') => 1,
        Some('m') => 60,
        Some('h') => 3600,
        Some('d') => 86400,
        Some('w') => 604800,
        _ => return Err(ConfigError("invalid lease duration suffix".into())),
    };
    Ok((number as u32).wrapping_mul(multiplier).max(60))
}

pub fn hostname_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

fn parse_hex(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) || !value.is_ascii() {
        return Err(ConfigError("invalid hexadecimal value".into()));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| (byte as char).to_digit(16).map(|n| n as u8);
            match (digit(pair[0]), digit(pair[1])) {
                (Some(a), Some(b)) => Ok((a << 4) | b),
                _ => Err(ConfigError("invalid hexadecimal value".into())),
            }
        })
        .collect()
}

pub fn host_from_blob(fields: &[u8]) -> Result<HostConfig> {
    // The ubus policy requires arrays. UCI strings are split by uci_to_blob.
    let value = owrt_ubus::convert::fields_to_json(fields);
    for key in ["mac", "duid"] {
        if value.get(key).is_some_and(|v| !matches!(v, Json::Array(_))) {
            return Err(ConfigError(format!("{key}: ubus requires an array")));
        }
    }
    host_from_json(&value)
}

fn host_from_json(data: &Json) -> Result<HostConfig> {
    let mut host = HostConfig::default();
    for value in list(data, "mac")?.unwrap_or_default() {
        let bytes = value
            .split(':')
            .map(|part| u8::from_str_radix(part, 16))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| ConfigError("invalid MAC address".into()))?;
        host.macs.push(
            bytes
                .try_into()
                .map_err(|_| ConfigError("invalid MAC address length".into()))?,
        );
    }
    for value in list(data, "duid")?.unwrap_or_default() {
        let (duid, iaid) = if let Some((duid, iaid)) = value.rsplit_once('%') {
            if iaid.is_empty() || iaid.len() > 8 {
                return Err(ConfigError("invalid IAID length".into()));
            }
            (
                duid,
                Some(
                    u32::from_str_radix(iaid, 16)
                        .map_err(|_| ConfigError("invalid IAID".into()))?,
                ),
            )
        } else {
            (value.as_str(), None)
        };
        let duid = parse_hex(duid)?;
        if duid.len() > 130 {
            return Err(ConfigError("DUID is too long".into()));
        }
        host.duids.push(HostDuid { duid, iaid });
    }
    if let Some(name) = text(data, "name")? {
        if !hostname_valid(&name) {
            return Err(ConfigError("invalid static hostname".into()));
        }
        host.hostname = Some(name);
    }
    if let Some(ip) = text(data, "ip")? {
        if ip != "ignore" {
            host.ipv4 = Some(
                ip.parse()
                    .map_err(|_| ConfigError("invalid static IPv4 address".into()))?,
            );
        }
    }
    if let Some(value) = text(data, "hostid")? {
        if value == "ignore" {
            host.ignore_v6 = true;
        } else {
            host.host_id = u64::from_str_radix(value.trim_start_matches("0x"), 16)
                .map_err(|_| ConfigError("invalid hostid".into()))?;
        }
    } else if let Some(ip) = host.ipv4 {
        let last = ip.octets()[3] as u64;
        host.host_id = ((last / 100) << 8) | (((last % 100) / 10) << 4) | (last % 10);
    }
    host.lease_time = text(data, "leasetime")?
        .map(|value| parse_lease_time(&value))
        .transpose()?;
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(dhcp: &str, system: Option<&str>) -> Result<Config> {
        fn package(name: &str, text: &str) -> Package {
            let mut ctx = owrt_uci::Context::new();
            let idx =
                owrt_uci::parse::import(&mut ctx, &mut text.as_bytes(), Some(name), None, true)
                    .unwrap()
                    .unwrap();
            ctx.root.remove(idx)
        }
        Config::from_packages(
            &package("dhcp", dhcp),
            None,
            system.map(|s| package("system", s)).as_ref(),
        )
    }
    const LOCAL: &str = "config odhcpd 'odhcpd'\n option maindhcp '0'\nconfig dhcp 'lan'\n option interface 'lan'\n option dhcpv4 'server'\n option start '100'\n option limit '150'\n option leasetime '12h'\n option ra 'server'\n option dhcpv6 'server'\n option ra_slaac '1'\n list ra_flags 'managed-config'\n list ra_flags 'other-config'\nconfig dhcp 'wan'\n option ignore '1'\n";
    #[test]
    fn local_shared_configuration_keeps_ipv6_and_defaults() {
        let config = parse(LOCAL, Some("config system\n option timezone 'CET-1CEST,M3.5.0,M10.5.0/3'\n option zonename 'Europe/Berlin'\n")).unwrap();
        assert_eq!(config.pools[0].ra_flags, 0xc0);
        assert_eq!(config.pools[0].lease_time, 43200);
        assert!(config.pools[0].dhcpv6_pd && config.pools[0].dhcpv6_na);
        assert!(!config.pools[1].enabled());
        assert_eq!(config.zonename.as_deref(), Some("Europe/Berlin"));
    }
    #[test]
    fn unsupported_modes_fail_before_runtime() {
        for (field, value) in [
            ("ra", "relay"),
            ("ra", "hybrid"),
            ("dhcpv6", "relay"),
            ("ndp", "relay"),
            ("master", "1"),
        ] {
            assert!(parse(
                &format!("config dhcp lan\n option {field} '{value}'\n"),
                None
            )
            .is_err());
        }
        assert!(parse("config odhcpd\n option maindhcp 1\n", None).is_err());
    }
    #[test]
    fn static_shared_ipv4_identity_and_iaid_remain_usable() {
        let config = parse("config host\n option ip '192.0.2.123'\n option mac '00:11:22:33:44:55'\n list duid '00010203%abcd'\n option name 'test-host'\n",None).unwrap();
        assert_eq!(config.hosts[0].host_id, 0x123);
        assert_eq!(config.hosts[0].duids[0].iaid, Some(0xabcd));
    }
    #[test]
    fn runtime_scope_is_checked_and_device_is_resolved() {
        let mut config = parse(LOCAL, None).unwrap();
        let data = owrt_ubus::json::parse("{\"dhcpv6\":\"relay\"}").unwrap();
        assert!(config
            .apply_network(&[NetworkInterface {
                name: "lan".into(),
                device: Some("br-lan".into()),
                up: true,
                data
            }])
            .is_err());
    }
    #[test]
    fn durations_names_and_ubus_arrays_have_checked_edges() {
        assert_eq!(parse_lease_time("12h").unwrap(), 43200);
        assert_eq!(parse_lease_time("0").unwrap(), 60);
        assert_eq!(parse_lease_time("infinite").unwrap(), u32::MAX);
        for name in ["", "a\nb", "a..b", "-a", "a_"] {
            assert!(!hostname_valid(name));
        }
        let payload = owrt_ubus::convert::object_to_payload(
            &owrt_ubus::json::parse("{\"duid\":\"000102\"}").unwrap(),
        );
        assert!(host_from_blob(&payload).is_err());
    }
}

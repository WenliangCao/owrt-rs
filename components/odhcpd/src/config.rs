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
    pub ignore_updates: bool,
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
            ignore_updates: true,
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
    pub diagnostics: Vec<String>,
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
            diagnostics: Vec::new(),
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
            if section.ty == "host" {
                match section_json(section).and_then(|data| host_from_json(&data)) {
                    Ok(host) => config.hosts.push(host),
                    Err(error) => config
                        .diagnostics
                        .push(format!("static host {} skipped: {error}", section.name)),
                }
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
        config.validate_devices()?;
        Ok(config)
    }

    /// Apply a freshly obtained complete netifd dump to a fresh UCI snapshot.
    /// Callers must not repeatedly apply patches to an already patched Config.
    pub fn apply_network(&mut self, interfaces: &[NetworkInterface]) -> Result<()> {
        for network in interfaces {
            let index = self.pools.iter().position(|pool| pool.name == network.name);
            let mut candidate = index
                .map(|i| self.pools[i].clone())
                .unwrap_or_else(|| PoolConfig::new(network.name.clone()));
            // l3_device is the independently typed netifd interface binding.
            // A bad optional data patch must not prevent resolving the UCI pool.
            candidate.ifname = network.device.clone().or(candidate.ifname);
            if let Some(i) = index {
                self.pools[i].ifname = candidate.ifname.clone();
            } else {
                // DHCP clients publish unrelated data such as integer leasetime.
                // First inspect only whether an unknown interface requests one
                // of our services; do not parse its client state as server UCI.
                if let Err(error) = apply_pool(&mut candidate, &network_data(&network.data, true)) {
                    self.diagnostics
                        .push(format!("netifd {} data skipped: {error}", network.name));
                    continue;
                }
            }
            if !candidate.enabled() {
                if index.is_none() && candidate.ifname.is_some() {
                    self.pools.push(candidate);
                }
                continue;
            }
            if let Err(error) = apply_pool(&mut candidate, &network_data(&network.data, false)) {
                self.diagnostics
                    .push(format!("netifd {} data skipped: {error}", network.name));
                continue;
            }
            candidate.ifname = network.device.clone().or(candidate.ifname);
            if let Some(i) = index {
                self.pools[i] = candidate;
            } else if candidate.enabled() {
                self.pools.push(candidate);
            }
        }
        self.validate_devices()
    }

    pub fn ignored_interfaces(&self) -> Vec<String> {
        self.pools
            .iter()
            .filter(|pool| pool.ignore_updates)
            .map(|pool| pool.name.clone())
            .collect()
    }

    /// Validate before committing a candidate, never while replacing sockets.
    pub fn validate_devices(&self) -> Result<()> {
        let mut assigned = Vec::new();
        for pool in self.pools.iter().filter(|pool| pool.enabled()) {
            let device = pool.ifname.as_deref().unwrap_or(&pool.name);
            if assigned.contains(&device) {
                return Err(ConfigError(format!(
                    "multiple IPv6 service pools on device {device} are unsupported"
                )));
            }
            assigned.push(device);
        }
        Ok(())
    }
}

/// config.c iface_attrs uses typed blobmsg_parse: a wrong-typed netifd field
/// is absent, unlike a malformed explicitly configured UCI value.
fn network_data(data: &Json, modes_only: bool) -> Json {
    let Json::Object(fields) = data else {
        return Json::Object(Vec::new());
    };
    Json::Object(
        fields
            .iter()
            .filter(|(name, value)| {
                if modes_only
                    && !matches!(
                        name.as_str(),
                        "ra" | "dhcpv6" | "ndp" | "master" | "ifname" | "networkid"
                    )
                {
                    return false;
                }
                match name.as_str() {
                    "ra"
                    | "dhcpv6"
                    | "ndp"
                    | "ifname"
                    | "networkid"
                    | "leasetime"
                    | "max_preferred_lifetime"
                    | "max_valid_lifetime"
                    | "ra_preference"
                    | "dhcpv6_raw"
                    | "ra_pref64"
                    | "prefix_filter"
                    | "captive_portal_uri" => matches!(value, Json::Str(_) | Json::Bytes(_)),
                    "master"
                    | "dynamicdhcp"
                    | "dhcpv6_assignall"
                    | "dhcpv6_na"
                    | "dhcpv6_pd"
                    | "dhcpv6_pd_preferred"
                    | "ra_slaac"
                    | "ra_offlink"
                    | "ra_dns"
                    | "dns_service"
                    | "ra_advrouter" => matches!(value, Json::Bool(_)),
                    "dhcpv6_pd_min_len"
                    | "dhcpv6_hostidlength"
                    | "ra_default"
                    | "ra_maxinterval"
                    | "ra_mininterval"
                    | "ra_lifetime"
                    | "ra_reachabletime"
                    | "ra_retranstime"
                    | "ra_hoplimit"
                    | "ra_mtu" => matches!(value, Json::Int(_)),
                    "dns" | "domain" | "ra_flags" | "upstream" | "dnr" | "ntp" => {
                        matches!(value, Json::Array(_))
                    }
                    _ => false,
                }
            })
            .cloned()
            .collect(),
    )
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
        if value {
            pool.ignore_updates = false;
        }
    }
    if let Some(value) = mode(data, "dhcpv6")? {
        pool.dhcpv6 = value;
        if value {
            pool.ignore_updates = false;
        }
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
            "medium" | "default" => 0,
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
    let value = owrt_ubus::convert::fields_to_json(fields).map_err(ConfigError)?;
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
        config
            .apply_network(&[NetworkInterface {
                name: "lan".into(),
                device: Some("br-lan".into()),
                up: true,
                data,
            }])
            .unwrap();
        assert!(config.pools[0].dhcpv6);
        assert_eq!(config.pools[0].ifname.as_deref(), Some("br-lan"));
        assert_eq!(config.diagnostics.len(), 1);
        assert!(config.diagnostics[0].contains("netifd lan data skipped"));
    }

    #[test]
    fn ra_preference_default_matches_medium_in_uci_and_netifd() {
        for value in ["default", "medium"] {
            let config = parse(
                &format!("{LOCAL}\nconfig dhcp 'second'\n option ra_preference '{value}'\n"),
                None,
            )
            .unwrap();
            assert_eq!(config.pools[2].ra_preference, 0);
            let mut config = parse(LOCAL, None).unwrap();
            config.pools[0].ra_preference = 1;
            config
                .apply_network(&[NetworkInterface {
                    name: "lan".into(),
                    device: Some("br-lan".into()),
                    up: true,
                    data: Json::Object(vec![("ra_preference".into(), Json::Str(value.into()))]),
                }])
                .unwrap();
            assert_eq!(config.pools[0].ra_preference, 0);
        }
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

    fn interface(name: &str, device: &str, data: &str) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            device: Some(device.into()),
            up: true,
            data: owrt_ubus::json::parse(data).unwrap(),
        }
    }

    #[test]
    fn client_data_without_a_uci_pool_cannot_disable_lan_server_configuration() {
        let lan = "config dhcp 'lan'\n option ra 'server'\n option dhcpv6 'server'\n";
        for client_first in [false, true] {
            let mut config = parse(lan, None).unwrap();
            let client = interface(
                "wwan",
                "eth1",
                r#"{"dhcpserver":"192.0.2.1","leasetime":60,"dns":[9],"ra":false}"#,
            );
            let lan = interface(
                "lan",
                "br-lan",
                r#"{"dns":["2001:db8::53"],"leasetime":60,"ra_mtu":"9000","ra_slaac":1}"#,
            );
            config
                .apply_network(&if client_first {
                    vec![client, lan]
                } else {
                    vec![lan, client]
                })
                .unwrap();
            let pool = config.pools.iter().find(|pool| pool.name == "lan").unwrap();
            assert!(pool.ra && pool.dhcpv6);
            assert_eq!(pool.ifname.as_deref(), Some("br-lan"));
            assert_eq!(pool.lease_time, 43200); // netifd integer is not server duration text.
            assert_eq!(pool.dns, vec!["2001:db8::53".parse::<Ipv6Addr>().unwrap()]);
            assert_eq!(pool.ra_mtu, None); // Wrong-typed netifd scalar is absent.
            assert!(pool.ra_slaac);
            let client = config
                .pools
                .iter()
                .find(|pool| pool.name == "wwan")
                .unwrap();
            assert!(!client.enabled());
            assert!(config.diagnostics.is_empty());
            assert_eq!(config.ignored_interfaces(), vec!["wwan"]);
        }
    }

    #[test]
    fn malformed_network_patch_is_skipped_per_interface_without_partial_mutation() {
        let mut config = parse(LOCAL, None).unwrap();
        config
            .apply_network(&[
                interface("bad", "eth2", r#"{"ra":"server","leasetime":"invalid"}"#),
                interface("lan", "br-lan", r#"{"dhcpv6_na":false,"dns":["invalid"]}"#),
                interface("good", "eth3", r#"{"ra":"server","leasetime":"600"}"#),
            ])
            .unwrap();
        assert!(!config.pools.iter().any(|pool| pool.name == "bad"));
        assert_eq!(config.diagnostics.len(), 2);
        assert!(config.pools[0].dhcpv6_na); // Earlier fields in the rejected patch rolled back.
        assert!(config.pools[0].dns.is_empty());
        assert_eq!(config.pools[0].ifname.as_deref(), Some("br-lan"));
        let good = config
            .pools
            .iter()
            .find(|pool| pool.name == "good")
            .unwrap();
        assert!(good.ra);
        assert_eq!(good.lease_time, 600);
        assert!(parse(
            "config dhcp lan\n option ra server\n option leasetime invalid\n",
            None
        )
        .is_err());
    }

    #[test]
    fn duplicate_enabled_devices_are_a_configuration_error_before_commit() {
        assert!(parse("config dhcp lan\n option ra server\n option ifname br-lan\nconfig dhcp lan6\n option dhcpv6 server\n option ifname br-lan\n", None).is_err());
        let mut config = parse(
            "config dhcp lan\n option ra server\nconfig dhcp lan6\n option dhcpv6 server\n",
            None,
        )
        .unwrap();
        let error = config
            .apply_network(&[
                interface("lan", "br-lan", "{}"),
                interface("lan6", "br-lan", "{}"),
            ])
            .unwrap_err();
        assert!(error
            .0
            .contains("multiple IPv6 service pools on device br-lan"));
        let mut disabled = parse(LOCAL, None).unwrap();
        disabled
            .apply_network(&[
                interface("lan", "br-lan", "{}"),
                interface("wan", "br-lan", "{}"),
            ])
            .unwrap();
    }

    #[test]
    fn invalid_uci_hosts_are_individual_diagnostics_but_ubus_stays_strict() {
        for invalid in [
            "option duid 0001000123456",
            "option mac zz:00:11:22:33:44",
            "option ip not-an-ip",
            "option name '-bad'",
        ] {
            let text = format!("{LOCAL}\nconfig host before\n option duid 00030001020000000002\n option name before\nconfig host broken\n {invalid}\nconfig host after\n option duid 00030001020000000003\n option name after\n");
            let config = parse(&text, None).unwrap();
            assert_eq!(
                config
                    .hosts
                    .iter()
                    .filter_map(|host| host.hostname.as_deref())
                    .collect::<Vec<_>>(),
                vec!["before", "after"]
            );
            assert_eq!(config.diagnostics.len(), 1);
            assert!(config.diagnostics[0].starts_with("static host broken skipped:"));
            assert!(config.pools[0].enabled());
        }
        let fields = owrt_ubus::convert::object_to_payload(
            &owrt_ubus::json::parse(r#"{"duid":["0001000123456"]}"#).unwrap(),
        );
        assert!(host_from_blob(&fields).is_err());
    }

    #[test]
    fn notification_ignore_tracks_c_service_modes_and_is_sticky_within_a_load() {
        let source = "config dhcp lan\n option ra server\n option ignore 1\nconfig dhcp wan\n option ignore 1\n";
        let mut config = parse(source, None).unwrap();
        assert_eq!(config.ignored_interfaces(), vec!["wan"]);
        config
            .apply_network(&[
                interface("lan", "br-lan", r#"{"ra":"disabled"}"#),
                interface("wan", "eth1", r#"{"ra":"server"}"#),
            ])
            .unwrap();
        assert!(!config.pools[0].enabled());
        assert!(!config.pools[0].ignore_updates); // A UCI server was enabled earlier in this load.
        assert!(!config.pools[1].enabled()); // Known C ignored interface does not consume data.
        assert_eq!(config.ignored_interfaces(), vec!["wan"]);
        let reset = parse("config dhcp lan\n option ra disabled\n", None).unwrap();
        assert_eq!(reset.ignored_interfaces(), vec!["lan"]);
    }
}

//! Mac-side device tooling for an authorized native firmware window.
//!
//! * `device-probe`: read-only, redacted health check through the router's
//!   actual LAN interface. DNS and HTTPS probes explicitly use the router LAN
//!   even when an alternate Internet connection is the Mac's default route.
//! * `native-deploy-window stage|activate|observe DIR`: stage or explicitly
//!   activate a deployment. The observer survives Wi-Fi loss; device recovery
//!   is independently armed by the configuration archive.
//! * `native-trial-prepare`: add a temporary native-image guard to a private
//!   sysupgrade config backup. Creates a new archive; never writes a router.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::util::{self, bail, ensure, seconds, strings, Args, JsonExt, Output, Result};

pub const NATIVE_PATHS: [(&str, &str); 10] = [
    ("uci", "/sbin/uci"),
    ("reload-config", "/sbin/reload_config"),
    ("fw4", "/sbin/fw4"),
    ("logd", "/sbin/logd"),
    ("httpd", "/usr/sbin/uhttpd"),
    ("rpcd", "/sbin/rpcd"),
    ("procd", "/sbin/procd"),
    ("ubusd", "/sbin/ubusd"),
    ("netifd", "/sbin/netifd"),
    ("dnsmasq", "/usr/sbin/dnsmasq"),
];
/// Exact stock image executables.json; ujail remains an execution-plane input.
pub const STOCK_UJAIL_SHA256: &str =
    "b141627f4c2064b69f214ecc1425904544b69b5b2210fb3195f10ad587c48644";

pub fn native_paths(layout: Option<&str>) -> Result<BTreeMap<String, String>> {
    let mut paths: BTreeMap<String, String> = NATIVE_PATHS
        .iter()
        .map(|(n, p)| ((*n).into(), (*p).into()))
        .collect();
    match layout {
        Some("native-ten") => {}
        Some("native-eleven") => {
            paths.insert("odhcpd".into(), "/usr/sbin/odhcpd".into());
        }
        _ => bail!("unsupported native release layout"),
    }
    Ok(paths)
}

fn hex_re(length: usize) -> Regex {
    Regex::new(&format!("^[0-9a-f]{{{length}}}$")).expect("static regex")
}

fn is_hex(value: &Value, length: usize) -> bool {
    value
        .as_str()
        .is_some_and(|text| util::is_hex(text, length))
}

fn is_boot_id(text: &str) -> bool {
    text.len() == 36
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
}

pub(crate) fn quote(text: &str) -> String {
    if !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@%+=:,./-_".contains(&b))
    {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\"'\"'"))
    }
}

fn component_paths(manifest: &Value) -> Result<BTreeMap<String, String>> {
    manifest
        .obj_field("components")?
        .iter()
        .map(|(name, item)| Ok((name.clone(), item.str_field("path")?.to_owned())))
        .collect()
}

/// External effects of a probe (seam for tests).
pub trait ProbeHost {
    /// stdout of an SSH command (trimmed); fails on a nonzero exit.
    fn ssh(&mut self, host: &str, command: &str, timeout: f64) -> Result<String>;
    /// stdout of a local command (trimmed); fails on a nonzero exit.
    fn run(&mut self, argv: &[String], timeout: f64) -> Result<String>;
    /// A local command whose exit code the caller judges.
    fn fetch(&mut self, argv: &[String], timeout: f64) -> Result<Output>;
}

pub struct RealHost;

pub const SSH_PROBE: [&str; 11] = [
    "ssh",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=4",
    "-o",
    "ConnectionAttempts=1",
    "-o",
    "ServerAliveInterval=4",
    "-o",
    "ServerAliveCountMax=1",
];

impl ProbeHost for RealHost {
    fn ssh(&mut self, host: &str, command: &str, timeout: f64) -> Result<String> {
        let mut argv = strings(SSH_PROBE);
        argv.extend([host.to_owned(), command.to_owned()]);
        self.run(&argv, timeout)
    }

    fn run(&mut self, argv: &[String], timeout: f64) -> Result<String> {
        let output = util::run_timeout(argv, None, seconds(timeout))?;
        ensure!(output.code == 0, "{} exited {}", argv[0], output.code);
        Ok(output.text())
    }

    fn fetch(&mut self, argv: &[String], timeout: f64) -> Result<Output> {
        util::run_timeout(argv, None, seconds(timeout))
    }
}

pub fn load_native_manifest(path: &Path) -> Result<(Value, String)> {
    let raw = fs::read(path)?;
    let manifest: Value = serde_json::from_slice(&raw)?;
    let paths = native_paths(manifest.get("deployment_layout").and_then(Value::as_str))?;
    ensure!(
        is_hex(&manifest["source_commit"], 40),
        "invalid native source identity"
    );
    let names: BTreeSet<&String> = manifest
        .get("components")
        .and_then(Value::as_object)
        .map(|c| c.keys().collect())
        .unwrap_or_default();
    ensure!(
        names == paths.keys().collect(),
        "native component set differs from layout"
    );
    for (name, expected) in &paths {
        let item = &manifest["components"][name];
        ensure!(
            item["path"] == expected.as_str(),
            "wrong native component path: {name}"
        );
        for key in ["rust_sha256", "stock_sha256"] {
            ensure!(is_hex(&item[key], 64), "invalid native hash: {name}");
        }
    }
    Ok((manifest, util::sha256_bytes(&raw)))
}

/// `(pid, (parent, start, digest))` rows of a production process snapshot.
type Inventory = BTreeMap<u64, (u64, u64, String)>;

/// Reads installed/ROM bytes and production generations; never switches.
pub fn native_identity(probe: &mut dyn ProbeHost, host: &str, manifest: &Value) -> Result<String> {
    let components = manifest.obj_field("components")?;
    let mut expected = BTreeMap::new();
    for item in components.values() {
        for prefix in ["", "/rom"] {
            expected.insert(
                format!("{prefix}{}", item.str_field("path")?),
                item.str_field("rust_sha256")?.to_owned(),
            );
        }
    }
    for prefix in ["", "/rom"] {
        expected.insert(
            format!("{prefix}/sbin/ujail"),
            STOCK_UJAIL_SHA256.to_owned(),
        );
    }
    let command = format!(
        "sha256sum {}",
        expected
            .keys()
            .map(|p| quote(p))
            .collect::<Vec<_>>()
            .join(" ")
    );
    ensure!(
        util::sum_map(&probe.ssh(host, &command, 30.0)?)? == expected,
        "native installed/ROM executable identity mismatch"
    );
    let release: Value = serde_json::from_str(&probe.ssh(
        host,
        "cat /usr/share/owrt-control-plane/release.json",
        12.0,
    )?)?;
    let layout = manifest.str_field("deployment_layout")?;
    ensure!(
        release.get("layout") == Some(&json!(layout))
            && release.get("source_commit") == manifest.get("source_commit"),
        "wrong installed native release"
    );
    let installed: BTreeSet<String> = release
        .get("components")
        .and_then(Value::as_object)
        .map(|c| c.keys().cloned().collect())
        .unwrap_or_default();
    ensure!(
        installed == native_paths(Some(layout))?.into_keys().collect(),
        "installed release omits a component"
    );
    for (name, item) in components {
        ensure!(
            ["path", "rust_sha256", "stock_sha256"]
                .iter()
                .all(|key| release["components"][name].get(*key) == item.get(*key)),
            "installed release component differs: {name}"
        );
    }
    let list = "ubus -S -t 3 call service list '{\"name\":\"dnsmasq\"}'";
    let services: Value = serde_json::from_str(&probe.ssh(host, list, 12.0)?)?;
    let instances = services["dnsmasq"]["instances"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    ensure!(
        !instances.is_empty()
            && instances.values().all(|value| value["running"] == true
                && util_truthy(&value["jail"])
                && value["pid"].as_u64().is_some_and(|pid| pid > 1)
                && value["pid"].is_u64()),
        "dnsmasq is not supervised under ujail"
    );
    let parents: BTreeSet<u64> = instances
        .values()
        .filter_map(|value| value["pid"].as_u64())
        .collect();
    ensure!(
        parents.len() == instances.len(),
        "dnsmasq instances share a supervisor PID"
    );
    // Restrict ordinary daemons to host PID1's children; only configured ujail
    // children may satisfy DNS. Same-name isolated processes never qualify.
    let script = INVENTORY_SCRIPT.replace(
        "__PARENTS__",
        &parents
            .iter()
            .map(|pid| format!("*:{pid}"))
            .collect::<Vec<_>>()
            .join("|"),
    );
    let digest_re = hex_re(64);
    let inventory = |probe: &mut dyn ProbeHost| -> Result<Inventory> {
        let mut rows = Inventory::new();
        for line in util::splitlines(&probe.ssh(host, &script, 30.0)?) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            ensure!(fields.len() == 4, "malformed production process identity");
            let numbers: Vec<Option<u64>> = fields[..3]
                .iter()
                .map(|v| {
                    v.bytes()
                        .all(|b| b.is_ascii_digit())
                        .then(|| v.parse().ok())
                        .flatten()
                })
                .collect();
            ensure!(
                numbers.iter().all(Option::is_some) && digest_re.is_match(fields[3]),
                "malformed production process identity"
            );
            let pid = numbers[0].unwrap();
            ensure!(!rows.contains_key(&pid), "duplicate process snapshot");
            rows.insert(
                pid,
                (
                    numbers[1].unwrap(),
                    numbers[2].unwrap(),
                    fields[3].to_owned(),
                ),
            );
        }
        Ok(rows)
    };
    let before = inventory(probe)?;
    let mut selected = Inventory::new();
    let mut lines = Vec::new();
    let mut names: Vec<&String> = components.keys().collect();
    names.sort();
    for name in names {
        let digest = components[name].str_field("rust_sha256")?;
        if matches!(name.as_str(), "uci" | "fw4" | "reload-config") {
            lines.push(format!("{name} - - {digest}"));
        } else if name != "dnsmasq" {
            let matches: Vec<u64> = before
                .iter()
                .filter(|(pid, (parent, _, value))| {
                    value == digest
                        && if name == "procd" {
                            **pid == 1
                        } else {
                            *parent == 1
                        }
                })
                .map(|(pid, _)| *pid)
                .collect();
            ensure!(
                matches.len() == 1,
                "expected one production process: {name}"
            );
            let pid = matches[0];
            selected.insert(pid, before[&pid].clone());
            lines.push(format!("{name} {pid} {} {digest}", before[&pid].1));
        } else {
            let mut sorted: Vec<&String> = instances.keys().collect();
            sorted.sort();
            for value in sorted.into_iter().map(|key| &instances[key]) {
                let parent = value["pid"].as_u64().unwrap_or_default();
                ensure!(
                    before
                        .get(&parent)
                        .is_some_and(|row| row.0 == 1 && row.2 == STOCK_UJAIL_SHA256),
                    "dnsmasq supervisor is not production ujail"
                );
                let matches: Vec<u64> = before
                    .iter()
                    .filter(|(_, row)| row.0 == parent && row.2 == digest)
                    .map(|(pid, _)| *pid)
                    .collect();
                ensure!(
                    matches.len() == 1,
                    "expected one DNS child per production instance"
                );
                let pid = matches[0];
                let argv = probe.ssh(host, &format!("cat /proc/{pid}/cmdline"), 12.0)?;
                let observed: Option<Vec<String>> = argv
                    .strip_suffix('\0')
                    .map(|text| text.split('\0').map(str::to_owned).collect());
                ensure!(
                    observed.is_some() && observed == string_list(&value["command"]),
                    "dnsmasq argv differs from the production init submission"
                );
                selected.insert(parent, before[&parent].clone());
                selected.insert(pid, before[&pid].clone());
                lines.push(format!("{name} {pid} {} {digest}", before[&pid].1));
            }
        }
    }
    let after = inventory(probe)?;
    ensure!(
        selected
            .iter()
            .all(|(pid, row)| after.get(pid) == Some(row)),
        "production process changed during capture"
    );
    let current: Value = serde_json::from_str(&probe.ssh(host, list, 12.0)?)?;
    let current = current["dnsmasq"]["instances"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    ensure!(
        current.keys().collect::<BTreeSet<_>>() == instances.keys().collect()
            && instances
                .iter()
                .all(|(name, value)| current[name]["running"] == true
                    && ["pid", "command", "jail"]
                        .iter()
                        .all(|key| current[name].get(*key) == value.get(*key))),
        "dnsmasq production instances changed during capture"
    );
    Ok(lines.join("\n") + "\n")
}

fn util_truthy(value: &Value) -> bool {
    crate::dnsmasq_package::truthy(value)
}

const INVENTORY_SCRIPT: &str = r#"set -eu
for process in /proc/[0-9]*; do
    pid=${process#/proc/}
    before=$(cat "$process/stat" 2>/dev/null) || continue
    fields=$(printf '%s\n' "$before" | awk '{sub(/^.*\) /, ""); print $2, $20}')
    parent=${fields%% *}
    case "$pid:$parent" in 1:*|*:1|__PARENTS__) ;; *) continue;; esac
    digest=$(sha256sum "$process/exe" 2>/dev/null) || continue
    after=$(cat "$process/stat" 2>/dev/null) || continue
    final=$(sha256sum "$process/exe" 2>/dev/null) || continue
    [ "$fields" = "$(printf '%s\n' "$after" | awk '{sub(/^.*\) /, ""); print $2, $20}')" ] || continue
    [ "${digest%% *}" = "${final%% *}" ] || continue
    printf '%s %s %s\n' "$pid" "$fields" "${digest%% *}"
done
"#;

fn ip_version(text: &str) -> Option<u8> {
    match text.parse::<IpAddr>().ok()? {
        IpAddr::V4(_) => Some(4),
        IpAddr::V6(_) => Some(6),
    }
}

/// Requires DNS through the router and real client HTTPS on its LAN link.
pub fn client_egress(
    probe: &mut dyn ProbeHost,
    interface: &str,
    address: &str,
    ipv6: bool,
) -> Result<Map<String, Value>> {
    // Raw Mac UDP DNS probes have an existing environment limitation. TCP
    // still tests the actual LAN client's access to the router's DNS service;
    // retain its transport explicitly rather than claiming a UDP pass.
    let mut result = Map::new();
    result.insert("client_dns_transport".into(), json!("tcp"));
    let families: &[(u8, &str)] = if ipv6 {
        &[(4, "A"), (6, "AAAA")]
    } else {
        &[(4, "A")]
    };
    for (family, record) in families {
        let answer = probe.run(
            &strings([
                "dig",
                "+tcp",
                "-b",
                address,
                "@192.168.1.1",
                "example.com",
                record,
                "+time=2",
                "+tries=1",
                "+noall",
                "+answer",
            ]),
            10.0,
        )?;
        let found = answer.lines().any(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.len() >= 5
                && fields[fields.len() - 2] == *record
                && ip_version(fields[fields.len() - 1]) == Some(*family)
        });
        ensure!(
            found,
            "client received no IPv{family} DNS answer through router"
        );
        result.insert(format!("client_dns_ipv{family}"), json!(true));
        let fetched = probe.fetch(
            &strings([
                "curl",
                "--interface",
                interface,
                "--noproxy",
                "*",
                &format!("-{family}"),
                "-f",
                "-sS",
                "--connect-timeout",
                "3",
                "--max-time",
                "8",
                "https://example.com/",
            ]),
            10.0,
        )?;
        ensure!(
            fetched.code == 0 && fetched.stdout.windows(14).any(|w| w == b"Example Domain"),
            "client IPv{family} HTTPS through router failed"
        );
        result.insert(format!("client_https_ipv{family}"), json!(true));
    }
    Ok(result)
}

pub struct ProbeOptions<'a> {
    pub host: &'a str,
    pub mode: &'a str,
    pub interface: Option<&'a str>,
    pub ipv6: bool,
    pub static_client: bool,
    pub native_manifest: Option<&'a Path>,
    pub host_bundle: &'a str,
    pub require_client_egress: bool,
}

impl Default for ProbeOptions<'_> {
    fn default() -> Self {
        Self {
            host: "openwrt",
            mode: "existing",
            interface: None,
            ipv6: true,
            static_client: false,
            native_manifest: None,
            host_bundle: "/root/r84",
            require_client_egress: false,
        }
    }
}

pub fn probe(host_io: &mut dyn ProbeHost, options: &ProbeOptions) -> Result<Value> {
    let host = options.host;
    let boot = host_io.ssh(host, "cat /proc/sys/kernel/random/boot_id", 12.0)?;
    let mut result = Map::new();
    result.insert("boot_id".into(), json!(boot));
    result.insert("mode".into(), json!(options.mode));
    ensure!(is_boot_id(&boot), "invalid boot identity");
    if options.mode == "native" {
        let path = options
            .native_manifest
            .ok_or_else(|| util::Error::new("native probe requires a local release manifest"))?;
        let (manifest, digest) = load_native_manifest(path)?;
        let names: Vec<&String> = manifest.obj_field("components")?.keys().collect();
        result.insert(
            "verified_components".into(),
            json!(names.iter().copied().collect::<BTreeSet<_>>()),
        );
        result.insert(
            "native_source_commit".into(),
            manifest["source_commit"].clone(),
        );
        result.insert("native_manifest_sha256".into(), json!(digest));
        result.insert(
            "native_identity".into(),
            json!(native_identity(host_io, host, &manifest)?),
        );
    } else if options.mode != "existing" {
        ensure!(
            matches!(options.mode, "stock" | "rust"),
            "invalid production mode"
        );
        let identity = host_io.ssh(
            host,
            &format!(
                "/bin/sh {} verify {}",
                quote(&format!("{}/stack-switch.sh", options.host_bundle)),
                quote(options.mode)
            ),
            12.0,
        )?;
        let components: Vec<&str> = identity
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .collect();
        ensure!(
            components.len() == 9 && components.iter().collect::<BTreeSet<_>>().len() == 9,
            "not all nine running identities were verified"
        );
        result.insert("verified_components".into(), json!(components));
    }
    let route = host_io.run(&strings(["route", "-n", "get", "192.168.1.1"]), 10.0)?;
    let routed = Regex::new(r"interface:\s+(\S+)")?
        .captures(&route)
        .map(|c| c[1].to_owned())
        .ok_or_else(|| util::Error::new("router LAN has no client route"))?;
    let interface = options
        .interface
        .map_or_else(|| routed.clone(), str::to_owned);
    ensure!(
        Regex::new(r"^en[0-9]+$")?.is_match(&interface),
        "invalid Mac LAN interface"
    );
    ensure!(routed == interface, "router route uses another interface");
    result.insert("client_interface".into(), json!(interface));
    let address = host_io.run(&strings(["ipconfig", "getifaddr", &interface]), 10.0)?;
    let lan = address
        .parse::<std::net::Ipv4Addr>()
        .ok()
        .filter(|ip| ip.octets()[..3] == [192, 168, 1]);
    ensure!(lan.is_some(), "client is not on the expected router LAN");
    if options.static_client {
        result.insert(
            "client_addressing".into(),
            json!("static; DHCP validated by daemon health only"),
        );
    } else {
        let leases = host_io.ssh(host, "cat /tmp/dhcp.leases", 12.0)?;
        ensure!(
            leases
                .lines()
                .any(|line| line.split_whitespace().nth(2) == Some(address.as_str())),
            "client has no DHCP lease on this router boot"
        );
        result.insert("client_dhcp".into(), json!(true));
    }
    let dump: Value = serde_json::from_str(&host_io.ssh(
        host,
        "ubus -S -t 3 call network.interface dump",
        12.0,
    )?)?;
    let interfaces: BTreeMap<&str, &Value> = dump["interface"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|entry| Some((entry["interface"].as_str()?, entry)))
                .collect()
        })
        .unwrap_or_default();
    let required: &[&str] = if options.ipv6 {
        &["loopback", "lan", "wan", "wan6"]
    } else {
        &["loopback", "lan", "wan"]
    };
    for name in required {
        ensure!(
            interfaces
                .get(name)
                .is_some_and(|entry| entry["up"] == true),
            "{name} is not up"
        );
    }
    result.insert("interfaces_up".into(), json!(required));
    let wireless: Value = serde_json::from_str(&host_io.ssh(
        host,
        "ubus -S -t 3 call network.wireless status",
        12.0,
    )?)?;
    let radios = wireless
        .as_object()
        .ok_or_else(|| util::Error::new("expected both radios"))?;
    ensure!(
        radios.keys().map(String::as_str).collect::<BTreeSet<_>>() == ["radio0", "radio1"].into(),
        "expected both radios"
    );
    let port_re = Regex::new(r"^[A-Za-z0-9_.-]+$")?;
    let mut aps = Vec::new();
    for (name, radio) in radios {
        ensure!(
            util_truthy(radio.field("up")?)
                && !util_truthy(radio.field("pending")?)
                && !util_truthy(radio.field("retry_setup_failed")?),
            "{name} is not settled"
        );
        for vif in radio["interfaces"].as_array().into_iter().flatten() {
            if vif["config"].get("mode").and_then(Value::as_str) != Some("ap") {
                continue;
            }
            let port = vif
                .get("ifname")
                .and_then(Value::as_str)
                .unwrap_or_default();
            ensure!(port_re.is_match(port), "invalid AP name");
            let master = host_io.ssh(
                host,
                &format!("readlink /sys/class/net/{port}/master"),
                12.0,
            )?;
            ensure!(master.ends_with("/br-lan"), "{port} is not bridged");
            aps.push(port.to_owned());
        }
    }
    ensure!(aps.len() >= 2, "expected an AP on each band");
    result.insert("ap_bridges".into(), json!(aps));
    let watchdog: Value =
        serde_json::from_str(&host_io.ssh(host, "ubus -S -t 3 call system watchdog", 12.0)?)?;
    ensure!(
        watchdog["status"] == "running",
        "hardware watchdog is not running"
    );
    result.insert("watchdog_running".into(), json!(true));
    let css = "/luci-static/bootstrap/cascade.css";
    let expected_css = host_io
        .ssh(host, &format!("sha256sum /www{css}"), 12.0)?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    // Fetch through curl bound to the router LAN address. A per-application VPN
    // filter on the client can force a raw socket into the tunnel (where
    // 192.168.1.1 is unroutable) while permitting curl.
    for scheme in ["http", "https"] {
        let fetched = host_io.fetch(
            &strings([
                "curl",
                "--interface",
                &address,
                "--noproxy",
                "*",
                "-4",
                "-k",
                "-sS",
                "--connect-timeout",
                "4",
                "--max-time",
                "8",
                &format!("{scheme}://192.168.1.1{css}"),
            ]),
            10.0,
        )?;
        ensure!(
            fetched.code == 0 && util::sha256_bytes(&fetched.stdout) == expected_css,
            "{} response failed validation",
            if scheme == "https" {
                "local HTTPS"
            } else {
                "local HTTP"
            }
        );
    }
    result.insert("local_http_https".into(), json!(true));
    let services: Value =
        serde_json::from_str(&host_io.ssh(host, "ubus -S -t 3 call service list", 12.0)?)?;
    for name in ["dnsmasq", "odhcpd"] {
        let instances = services[name]["instances"].as_object();
        ensure!(
            instances.is_some_and(|i| !i.is_empty() && i.values().all(|v| v["running"] == true)),
            "{name} has a stopped instance"
        );
    }
    // Retain the router-side checks used by historical probes. Deployments
    // additionally require direct client egress.
    let nsout = host_io.ssh(host, "nslookup example.com 127.0.0.1", 12.0)?;
    for family in if options.ipv6 { vec![4, 6] } else { vec![4] } {
        let found = nsout.lines().any(|line| {
            line.contains("Address:")
                && ip_version(line.rsplit("Address:").next().unwrap_or_default().trim())
                    == Some(family)
        });
        ensure!(
            found,
            "router DNS has no IPv{family} answer for example.com"
        );
        result.insert(format!("dns_ipv{family}"), json!(true));
    }
    ensure!(
        host_io
            .ssh(
                host,
                "uclient-fetch -q -T 8 -O /dev/null https://example.com/ && echo OK",
                12.0
            )?
            .contains("OK"),
        "router could not fetch https://example.com"
    );
    result.insert("router_internet_https".into(), json!(true));
    if options.require_client_egress {
        result.extend(client_egress(host_io, &interface, &address, options.ipv6)?);
    }
    ensure!(
        host_io.ssh(host, "cat /proc/sys/kernel/random/boot_id", 12.0)? == boot,
        "router rebooted during probe"
    );
    Ok(Value::Object(result))
}

/// `owrt-tools device-probe [--host H] [--mode M] ...`.
pub fn probe_main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(
        raw,
        &[
            "--host",
            "--mode",
            "--interface",
            "--native-manifest",
            "--host-bundle",
        ],
        &["--ipv4-only", "--static-client", "--require-client-egress"],
    )?;
    args.exact(&[])?;
    let mode = args.value("--mode").unwrap_or("existing");
    ensure!(
        matches!(mode, "existing" | "stock" | "rust" | "native"),
        "--mode must be existing, stock, rust or native"
    );
    let manifest = args.value("--native-manifest").map(PathBuf::from);
    let options = ProbeOptions {
        host: args.value("--host").unwrap_or("openwrt"),
        mode,
        interface: args.value("--interface"),
        ipv6: !args.flag("--ipv4-only"),
        static_client: args.flag("--static-client"),
        native_manifest: manifest.as_deref(),
        host_bundle: args.value("--host-bundle").unwrap_or("/root/r84"),
        require_client_egress: args.flag("--require-client-egress"),
    };
    match probe(&mut RealHost, &options) {
        Ok(result) => {
            println!("{}", util::sorted_line_json(&result));
            Ok(0)
        }
        Err(error) => {
            println!("{}", util::line_json(&json!({"error": error.to_string()})));
            Ok(1)
        }
    }
}

// ---------------------------------------------------------- deploy window

/// SSH runner for [`dnsmasq_runtime`]: `(command, timeout) -> stdout`.
pub type Remote<'a> = dyn FnMut(&str, f64) -> Result<String> + 'a;

fn stat_fields(stat: &str) -> Result<Vec<String>> {
    let rest = stat
        .rsplit_once(')')
        .ok_or_else(|| util::Error::new("malformed /proc stat"))?
        .1;
    let fields: Vec<String> = rest.split_whitespace().map(str::to_owned).collect();
    ensure!(fields.len() > 19, "malformed /proc stat");
    Ok(fields)
}

fn string_list(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// Verifies every supervised instance by executable bytes, not d_path.
pub fn dnsmasq_runtime(
    remote: &mut Remote,
    expected: &str,
    ujail_sha256: &str,
    diagnostics: &Path,
) -> Result<Vec<Value>> {
    let mut evidence = json!({"processes": []});
    let result = dnsmasq_runtime_inner(remote, expected, ujail_sha256, &mut evidence);
    match &result {
        Ok(_) => evidence["passed"] = json!(true),
        Err(error) => {
            evidence["passed"] = json!(false);
            evidence["error"] = json!(error.to_string());
        }
    }
    let mut stream = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(diagnostics)?;
    writeln!(stream, "{}", util::line_json(&evidence))?;
    result
}

fn dnsmasq_runtime_inner(
    remote: &mut Remote,
    expected: &str,
    ujail_sha256: &str,
    evidence: &mut Value,
) -> Result<Vec<Value>> {
    let list = "ubus -S -t 3 call service list '{\"name\":\"dnsmasq\"}'";
    let services: Value = serde_json::from_str(&remote(list, 15.0)?)?;
    let instances = services["dnsmasq"]["instances"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    ensure!(
        !instances.is_empty()
            && instances
                .values()
                .all(|v| v["running"] == true && util_truthy(&v["jail"])),
        "dnsmasq instances are not running under ujail"
    );
    evidence["instances"] = Value::Object(instances.clone());
    let inventory = remote("set -eu\nfor process in /proc/[0-9]*; do\n    value=$(sha256sum \"$process/exe\" 2>/dev/null) || continue\n    \
                            printf '%s %s\\n' \"${process#/proc/}\" \"${value%% *}\"\ndone\n", 30.0)?;
    evidence["inventory"] = json!(inventory);
    let pids: Vec<&str> = util::splitlines(&inventory)
        .into_iter()
        .filter(|line| line.split_whitespace().nth(1) == Some(expected))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    ensure!(
        pids.len() == instances.len() && pids.iter().collect::<BTreeSet<_>>().len() == pids.len(),
        "dnsmasq executable count differs from configured instances"
    );
    let mut matched = BTreeSet::new();
    let mut processes = Vec::new();
    for pid in pids {
        ensure!(
            !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()),
            "invalid runtime PID"
        );
        // FS separates fields while the command lines retain their NULs.
        let fields_text = remote(&RUNTIME_SCRIPT.replace("PID_VALUE", pid), 15.0)?;
        let fields: Vec<&str> = fields_text.split('\x1c').collect();
        ensure!(fields.len() == 12, "invalid runtime snapshot framing");
        let [before, exe, digest, command, status, parent_before, parent_exe, parent_digest, parent_command, parent_after, after, final_digest] =
            fields[..]
        else {
            unreachable!()
        };
        let (first, last) = (stat_fields(before)?, stat_fields(after)?);
        let parent: u64 = first[1].parse()?;
        ensure!(
            first[19] == last[19] && first[1] == last[1],
            "dnsmasq PID changed during capture"
        );
        ensure!(
            stat_fields(parent_before)?[19] == stat_fields(parent_after)?[19],
            "dnsmasq supervisor changed during capture"
        );
        let head = |text: &str| {
            text.split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned()
        };
        ensure!(
            head(digest) == expected && head(final_digest) == expected,
            "dnsmasq runtime executable changed"
        );
        ensure!(
            head(parent_digest) == ujail_sha256,
            "dnsmasq supervisor is not the exact image ujail"
        );
        let names: Vec<&String> = instances
            .iter()
            .filter(|(_, v)| v["pid"].as_u64() == Some(parent))
            .map(|(name, _)| name)
            .collect();
        ensure!(
            names.len() == 1 && !matched.contains(names[0]),
            "dnsmasq process is not a unique supervised instance"
        );
        ensure!(command.ends_with('\0'), "truncated dnsmasq command line");
        let argv: Vec<String> = command[..command.len() - 1]
            .split('\0')
            .map(str::to_owned)
            .collect();
        ensure!(
            Some(&argv) == string_list(&instances[names[0]]["command"]).as_ref(),
            "dnsmasq argv differs from the init submission"
        );
        matched.insert(names[0].clone());
        let row = json!({"instance": names[0], "pid": pid.parse::<u64>()?, "exe": exe.trim(), "sha256": expected, "cmdline": argv,
                         "status": status, "start_ticks": first[19].parse::<u64>()?, "parent_pid": parent,
                         "parent_exe": parent_exe.trim(), "parent_sha256": head(parent_digest),
                         "parent_cmdline": parent_command.trim_end_matches('\0').split('\0').collect::<Vec<_>>(),
                         "parent_start_ticks": stat_fields(parent_before)?[19].parse::<u64>()?});
        evidence["processes"]
            .as_array_mut()
            .unwrap()
            .push(row.clone());
        processes.push(row);
    }
    ensure!(
        matched == instances.keys().cloned().collect(),
        "not every dnsmasq instance was verified"
    );
    let current: Value = serde_json::from_str(&remote(list, 15.0)?)?;
    let current = current["dnsmasq"].obj_field("instances")?;
    ensure!(
        current.keys().collect::<BTreeSet<_>>() == instances.keys().collect()
            && instances
                .iter()
                .all(|(name, value)| current[name]["running"] == true
                    && current[name].get("pid") == value.get("pid")
                    && current[name].get("command") == value.get("command")),
        "dnsmasq instances changed during capture"
    );
    Ok(processes)
}

const RUNTIME_SCRIPT: &str = r#"set -eu
pid=PID_VALUE
parent=$(awk '$1 == "PPid:" { print $2 }' /proc/$pid/status)
field() { printf '\034'; "$@"; }
cat /proc/$pid/stat
field readlink /proc/$pid/exe
field sha256sum /proc/$pid/exe
field cat /proc/$pid/cmdline
field cat /proc/$pid/status
field cat /proc/$parent/stat
field readlink /proc/$parent/exe
field sha256sum /proc/$parent/exe
field cat /proc/$parent/cmdline
field cat /proc/$parent/stat
field cat /proc/$pid/stat
field sha256sum /proc/$pid/exe
"#;

/// External effects of a deployment window (seam for tests).
pub trait Window {
    fn run(&mut self, argv: &[String], timeout: f64) -> Result<Output>;
    fn probe(&mut self, host: &str, interface: &str) -> Result<Value>;
    fn dnsmasq_runtime(
        &mut self,
        ssh: &[String],
        expected: &str,
        ujail: &str,
        diagnostics: &Path,
    ) -> Result<Vec<Value>> {
        let mut remote = |command: &str, timeout: f64| -> Result<String> {
            let mut argv = ssh.to_vec();
            argv.push(command.to_owned());
            let output = self.run(&argv, timeout)?;
            ensure!(
                output.code == 0,
                "SSH command failed: {}",
                truncate(&String::from_utf8_lossy(&output.stderr))
            );
            Ok(output.text())
        };
        dnsmasq_runtime(&mut remote, expected, ujail, diagnostics)
    }
    fn monotonic(&mut self) -> f64;
    fn sleep(&mut self, seconds: f64);
    /// Starts the actual upgrade; only `activate` calls it.
    fn spawn_upgrade(&mut self, argv: &[String], log: &Path) -> Result<std::process::Child>;
    fn driver_sha256(&self) -> Result<String>;
}

fn truncate(text: &str) -> String {
    text.trim().chars().take(180).collect()
}

pub struct RealWindow {
    start: std::time::Instant,
}

impl Window for RealWindow {
    fn run(&mut self, argv: &[String], timeout: f64) -> Result<Output> {
        util::run_timeout(argv, None, seconds(timeout))
    }

    fn probe(&mut self, host: &str, interface: &str) -> Result<Value> {
        probe(
            &mut RealHost,
            &ProbeOptions {
                host,
                interface: Some(interface),
                require_client_egress: true,
                ..Default::default()
            },
        )
    }

    fn monotonic(&mut self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    fn sleep(&mut self, seconds: f64) {
        std::thread::sleep(util::seconds(seconds));
    }

    fn spawn_upgrade(&mut self, argv: &[String], log: &Path) -> Result<std::process::Child> {
        let output = fs::File::create(log)?;
        Ok(std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(std::process::Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output)
            .spawn()?)
    }

    fn driver_sha256(&self) -> Result<String> {
        util::sha256_file(&std::env::current_exe()?)
    }
}

fn sha(path: &Path) -> Result<String> {
    util::sha256_file(path)
}

fn round1(value: f64) -> Value {
    json!((value * 10.0).round() / 10.0)
}

struct Deployment<'a> {
    window: &'a mut dyn Window,
    base: PathBuf,
    label: String,
    ssh: Vec<String>,
    host: String,
    interface: String,
    migration: Option<Value>,
    manifest: Value,
    trial: Value,
    gate: Value,
}

const REMOTE_IMAGE: &str = "/tmp/owrt-native-image.bin";
const REMOTE_CONFIG: &str = "/tmp/owrt-native-config.tar.gz";

impl Deployment<'_> {
    fn remote(&mut self, command: &str, timeout: f64) -> Result<String> {
        let mut argv = self.ssh.clone();
        argv.push(command.to_owned());
        let output = self.window.run(&argv, timeout)?;
        ensure!(
            output.code == 0,
            "SSH command failed: {}",
            truncate(&String::from_utf8_lossy(&output.stderr))
        );
        Ok(output.text())
    }

    fn log(&mut self, event: &str, fields: Value) -> Result<()> {
        let mut row = json!({"at": util::utc_now_iso(), "event": event});
        row.as_object_mut()
            .unwrap()
            .extend(fields.as_object().cloned().unwrap_or_default());
        let line = util::line_json(&row);
        let mut stream = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.base.join(format!("window-{}.jsonl", self.label)))?;
        writeln!(stream, "{line}")?;
        println!("{line}");
        Ok(())
    }

    fn configurations(&mut self, after_boot: bool) -> Result<()> {
        for filename in ["config-before.sha256", "protected-before.sha256"] {
            let mut entries = util::sum_map(&util::read_text(&self.base.join(filename))?)?;
            if let (Some(migration), "config-before.sha256") = (&self.migration, filename) {
                ensure!(
                    entries.contains_key("/etc/config/system"),
                    "migration requires original system configuration"
                );
                ensure!(
                    !entries.contains_key("/etc/owrt-log-settings-v1"),
                    "migration marker is not a configuration exception"
                );
                if after_boot {
                    entries.insert(
                        "/etc/config/system".into(),
                        migration.str_field("system_sha256")?.into(),
                    );
                    entries.insert(
                        "/etc/owrt-log-settings-v1".into(),
                        migration.str_field("marker_sha256")?.into(),
                    );
                }
            }
            let observed = self.remote(
                &format!(
                    "sha256sum {}",
                    entries
                        .keys()
                        .map(|p| quote(p))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
                15.0,
            )?;
            ensure!(
                util::sum_map(&observed)? == entries,
                "configuration changed: {filename}"
            );
        }
        Ok(())
    }

    fn staged_files(&mut self) -> Result<()> {
        let actual = self.remote(&format!("sha256sum {REMOTE_IMAGE} {REMOTE_CONFIG}"), 15.0)?;
        let lines: Vec<&str> = actual.lines().collect();
        let head = |index: usize| {
            lines
                .get(index)
                .and_then(|line| line.split_whitespace().next())
                .unwrap_or_default()
                .to_owned()
        };
        ensure!(
            self.trial["image"]["sha256"] == head(0).as_str(),
            "device image changed"
        );
        ensure!(
            self.trial["archive_sha256"] == head(1).as_str(),
            "device config changed"
        );
        Ok(())
    }

    fn native_identities(&mut self) -> Result<Value> {
        let mut code = String::from("set -eu\nsha256sum -c /usr/share/owrt-control-plane/rust.sha256 >/dev/null\n\
            sha256sum -c /usr/share/owrt-control-plane/stock.sha256 >/dev/null\nfor name in procd ubusd netifd rpcd logd uhttpd; do\n    \
            if [ \"$name\" = procd ]; then pid=1; else pid=$(pidof \"$name\"); fi\n    case \"$pid\" in ''|*[!0-9]*) exit 1;; esac\n    \
            printf '%s %s\\n' \"$name\" \"$(sha256sum /proc/$pid/exe | cut -d' ' -f1)\"\ndone\n");
        if self.manifest["components"].get("odhcpd").is_some() {
            code = code.replace(
                "for name in procd ubusd netifd rpcd logd uhttpd;",
                "for name in procd ubusd netifd rpcd logd uhttpd odhcpd;",
            );
        }
        let mut observed: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in self.remote(&code, 15.0)?.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            ensure!(fields.len() == 2, "malformed runtime identity");
            observed
                .entry(fields[0].into())
                .or_default()
                .push(fields[1].into());
        }
        let diagnostics = self
            .base
            .join(format!("dnsmasq-runtime-{}.jsonl", self.label));
        let expected = self.manifest["components"]["dnsmasq"]
            .str_field("rust_sha256")?
            .to_owned();
        let ujail = self.gate.str_field("ujail_sha256")?.to_owned();
        let dns = self
            .window
            .dnsmasq_runtime(&self.ssh, &expected, &ujail, &diagnostics)?;
        observed.insert(
            "dnsmasq".into(),
            dns.iter()
                .map(|row| row["sha256"].as_str().unwrap_or_default().to_owned())
                .collect(),
        );
        let components = self.manifest.obj_field("components")?.clone();
        for (name, component) in &components {
            if matches!(name.as_str(), "uci" | "fw4" | "reload-config") {
                continue;
            }
            let process = if name == "httpd" {
                "uhttpd"
            } else {
                name.as_str()
            };
            ensure!(
                observed
                    .get(process)
                    .is_some_and(|digests| !digests.is_empty()
                        && digests
                            .iter()
                            .all(|d| component["rust_sha256"] == d.as_str())),
                "running identity mismatch: {name}"
            );
        }
        let paths: Vec<String> = components
            .values()
            .filter_map(|c| c["path"].as_str().map(str::to_owned))
            .collect();
        let rom = self.remote(
            &format!(
                "sha256sum {}",
                paths
                    .iter()
                    .map(|p| format!("/rom{p}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            15.0,
        )?;
        let expected_rom: BTreeMap<String, String> = components
            .values()
            .map(|c| {
                (
                    format!("/rom{}", c["path"].as_str().unwrap_or_default()),
                    c["rust_sha256"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        ensure!(
            util::sum_map(&rom)? == expected_rom,
            "ROM identity mismatch"
        );
        let mut integration = BTreeMap::new();
        for c in self.manifest.obj_field("integration_files")?.values() {
            for prefix in ["", "/rom"] {
                integration.insert(
                    format!("{prefix}{}", c.str_field("path")?),
                    c.str_field("replacement_sha256")?.to_owned(),
                );
            }
        }
        let actual = self.remote(
            &format!(
                "sha256sum {}",
                integration
                    .keys()
                    .map(|p| quote(p))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            15.0,
        )?;
        ensure!(
            util::sum_map(&actual)? == integration,
            "dnsmasq init/ACL identity mismatch"
        );
        let release: Value = serde_json::from_str(
            &self.remote("cat /usr/share/owrt-control-plane/release.json", 15.0)?,
        )?;
        ensure!(
            release["source_commit"] == self.manifest["source_commit"],
            "wrong installed firmware release"
        );
        let mounts: Value =
            serde_json::from_str(&self.remote("ubus -S -t 3 call luci getMountPoints", 15.0)?)?;
        ensure!(
            !mounts["result"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|m| m["mount"]
                    .as_str()
                    .is_some_and(|mount| paths.iter().any(|p| p == mount))),
            "executable bind mount remains"
        );
        self.remote("set -eu\nfor s in log rpcd uhttpd network dnsmasq odhcpd; do /etc/init.d/$s enabled; done\n\
                     for name in uci fw4 reload-config rpcd logd httpd; do\n    test ! -e /etc/owrt-$name.boot-enable\n    \
                     test ! -e /etc/init.d/owrt-$name\ndone\nkill -0 \"$(cat /tmp/owrt-native-guard-lock/pid)\"\n\
                     test ! -e /root/owrt-native-trial/rollback-requested\ntest ! -e /root/owrt-native-trial/c-bridge-used\n\
                     /sbin/fw4 check >/dev/null 2>&1\n", 15.0)?;
        let payload: String = self
            .trial
            .obj_field("payload_sha256")?
            .iter()
            .map(|(path, digest)| format!("{}  /{path}\n", digest.as_str().unwrap_or_default()))
            .collect();
        self.remote(
            &format!("printf %s {} | sha256sum -c - >/dev/null", quote(&payload)),
            60.0,
        )?;
        Ok(
            json!({"runtime_daemons": observed, "dnsmasq_runtime": dns, "ROM_components_verified": components.len(),
                  "dnsmasq_integration_files_verified": self.manifest["integration_files"].as_object().map_or(0, Map::len),
                  "executable_bind_mounts": 0}),
        )
    }
}

pub struct WindowArgs {
    pub phase: String,
    pub directory: PathBuf,
    pub host: String,
    pub interface: String,
    pub previous_boot_id: Option<String>,
    pub label: String,
}

/// Outcome of one observation step.
enum Step {
    Healthy,
    Confirmed,
    Abort,
}

pub fn deploy_window(args: &WindowArgs, window: &mut dyn Window) -> Result<i32> {
    let base = fs::canonicalize(&args.directory)?;
    ensure!(
        Regex::new(r"^[a-z0-9-]+$")?.is_match(&args.label),
        "invalid observation label"
    );
    ensure!(
        args.phase != "observe" || args.previous_boot_id.is_some(),
        "observe requires previous boot ID"
    );
    let gate = util::read_json(&base.join("recovery-gate.json"))?;
    ensure!(
        gate["ready_for_staging"] == true,
        "recovery gate incomplete"
    );
    ensure!(
        is_hex(&gate["rollback_source_commit"], 40),
        "verified rollback source identity is missing"
    );
    ensure!(
        is_hex(&gate["ujail_sha256"], 64),
        "exact candidate image ujail identity is missing"
    );
    let migration = gate.get("log_settings_migration").cloned();
    if let Some(value) = &migration {
        ensure!(
            value.as_object().is_some_and(|m| m
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == ["marker_sha256", "system_sha256"].into()
                && m.values().all(|v| is_hex(v, 64))),
            "invalid log settings migration identity"
        );
    }
    let image = PathBuf::from(gate.str_field("image_path")?);
    let config = base.join("trial-config.tar.gz");
    let trial = util::read_json(&base.join("trial-config.tar.json"))?;
    let manifest = util::read_json(Path::new(gate.str_field("manifest_path")?))?;
    ensure!(
        component_paths(&manifest)?
            == native_paths(manifest.get("deployment_layout").and_then(Value::as_str))?,
        "deployment component set differs from layout"
    );
    let previous_boot = if args.phase == "observe" {
        args.previous_boot_id.clone().unwrap_or_default()
    } else {
        gate.str_field("previous_boot_id")?.to_owned()
    };
    ensure!(is_boot_id(&previous_boot), "invalid previous boot ID");
    ensure!(
        trial["image"]["sha256"] == sha(&image)?.as_str(),
        "local image changed"
    );
    ensure!(
        trial["archive_sha256"] == sha(&config)?.as_str(),
        "configuration archive changed"
    );
    ensure!(
        gate["guard_evidence_sha256"] == sha(&base.join("guard-evidence.tar.gz"))?.as_str(),
        "guard evidence changed"
    );
    for (name, expected) in gate.obj_field("backup_sha256")? {
        ensure!(
            *expected == sha(&base.join(name))?.as_str(),
            "backup changed: {name}"
        );
    }
    let mut ssh = strings([
        "ssh",
        "-n",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=4",
        "-o",
        "ServerAliveInterval=4",
        "-o",
        "ServerAliveCountMax=1",
    ]);
    ssh.push(args.host.clone());
    let mut deployment = Deployment {
        window,
        base: base.clone(),
        label: args.label.clone(),
        ssh,
        host: args.host.clone(),
        interface: args.interface.clone(),
        migration: migration.clone(),
        manifest,
        trial,
        gate,
    };
    let d = &mut deployment;
    if args.phase != "observe" {
        ensure!(
            d.remote("cat /proc/sys/kernel/random/boot_id", 15.0)? == previous_boot,
            "pre-upgrade boot changed"
        );
        d.configurations(false)?;
    }
    if args.phase == "stage" {
        for (local, destination) in [(&image, REMOTE_IMAGE), (&config, REMOTE_CONFIG)] {
            let output = d.window.run(
                &strings([
                    "scp",
                    "-O",
                    "-q",
                    &util::display(local),
                    &format!("{}:{destination}", d.host),
                ]),
                90.0,
            )?;
            ensure!(output.code == 0, "scp exited {}", output.code);
        }
        d.staged_files()?;
        let check = d.remote(
            &format!("/sbin/sysupgrade -T -f {REMOTE_CONFIG} {REMOTE_IMAGE}"),
            60.0,
        )?;
        fs::write(base.join("sysupgrade-test.log"), check + "\n")?;
        let (host, interface) = (d.host.clone(), d.interface.clone());
        let health = d.window.probe(&host, &interface)?;
        let ready = json!({"at": util::utc_now_iso(), "boot_id": health["boot_id"], "image_sha256": sha(&image)?,
                           "config_sha256": sha(&config)?, "sysupgrade_test_passed": true, "driver_sha256": d.window.driver_sha256()?,
                           "client_health": health, "log_settings_migration": migration});
        util::write_json(&base.join("stage-ready.json"), &ready)?;
        d.log(
            "staged_and_checked",
            json!({"image_sha256": sha(&image)?, "client_health": ready["client_health"]}),
        )?;
        return Ok(0);
    }
    let ready = util::read_json(&base.join("stage-ready.json"))?;
    ensure!(
        ready["sysupgrade_test_passed"] == true
            && ready["driver_sha256"] == d.window.driver_sha256()?.as_str(),
        "staging gate changed"
    );
    ensure!(
        ready["image_sha256"] == sha(&image)?.as_str()
            && ready["config_sha256"] == sha(&config)?.as_str(),
        "staged artifacts changed"
    );
    ensure!(
        ready.get("log_settings_migration").filter(|v| !v.is_null()) == migration.as_ref(),
        "staged log settings migration changed"
    );
    let mut upgrade = None;
    if args.phase == "activate" {
        d.staged_files()?;
        let (host, interface) = (d.host.clone(), d.interface.clone());
        d.window.probe(&host, &interface)?;
        let mut stamp = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(base.join("ACTIVATION_STARTED"))?;
        writeln!(stamp, "{}", util::utc_now_iso())?;
        d.log(
            "flash_requested",
            json!({"image_sha256": sha(&image)?, "preserve_config": true}),
        )?;
        let mut argv = d.ssh.clone();
        argv.push(format!(
            "/sbin/sysupgrade -f {REMOTE_CONFIG} {REMOTE_IMAGE}"
        ));
        upgrade = Some(
            d.window
                .spawn_upgrade(&argv, &base.join("sysupgrade-activation.log"))?,
        );
    }
    let start = d.window.monotonic();
    let mut stable: Option<f64> = None;
    let mut verified_boot: Option<String> = None;
    while d.window.monotonic() - start < 850.0 {
        let step = (|| -> Result<Step> {
            let boot = d.remote("cat /proc/sys/kernel/random/boot_id", 15.0)?;
            ensure!(boot != previous_boot, "waiting for new boot");
            let release: Value = serde_json::from_str(
                &d.remote("cat /usr/share/owrt-control-plane/release.json", 15.0)?,
            )?;
            if release["source_commit"] == d.gate["rollback_source_commit"] {
                d.log(
                    "rollback_firmware_detected_requires_final_checks",
                    json!({"boot_id": boot}),
                )?;
                return Ok(Step::Abort);
            }
            let pid1 = d
                .remote("sha256sum /proc/1/exe", 15.0)?
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            if d.manifest["components"]["procd"]["stock_sha256"] == pid1.as_str() {
                let guard = d.remote("cat /root/owrt-native-trial/guard.log", 15.0)?;
                fs::write(d.base.join("guard-after-fallback.log"), guard)?;
                d.log(
                    "C_bridge_detected_not_a_completed_firmware_rollback",
                    json!({"boot_id": boot}),
                )?;
                bail!("C bridge is requesting the complete rollback");
            }
            let (host, interface) = (d.host.clone(), d.interface.clone());
            let health = d.window.probe(&host, &interface)?;
            ensure!(
                health["boot_id"] == boot.as_str(),
                "boot changed during health probe"
            );
            if verified_boot.as_deref() != Some(boot.as_str()) {
                let identity = d.native_identities()?;
                d.configurations(true)?;
                util::write_json(
                    &d.base.join(format!("native-identity-{}.json", d.label)),
                    &identity,
                )?;
                verified_boot = Some(boot.clone());
                stable = None;
            }
            if stable.is_none() {
                stable = Some(d.window.monotonic());
            }
            let held = d.window.monotonic() - stable.unwrap_or_default();
            let elapsed = d.window.monotonic() - start;
            d.log("health_pass", json!({"elapsed_s": round1(elapsed), "continuous_s": round1(held), "health": health}))?;
            if held < 180.0 {
                return Ok(Step::Healthy);
            }
            d.native_identities()?;
            d.configurations(true)?;
            let token = d.trial.str_field("token")?.to_owned();
            d.remote(
                &format!(
                    "/bin/sh /root/owrt-native-trial/native_trial_guard.sh confirm {} {}",
                    quote(&token),
                    quote(&boot)
                ),
                40.0,
            )?;
            let mut result = json!({"status": "native_image_healthy_and_client_confirmed", "boot_id": boot, "observation_label": d.label,
                                    "continuous_client_health_s": held, "image_sha256": sha(&image)?,
                                    "source_commit": d.manifest["source_commit"], "health": health,
                                    "automatic_guard_remains_armed": true, "physical_power_cycle_tested": false});
            if let Some(migration) = &d.migration {
                result["log_settings_migration"] = migration.clone();
            }
            util::write_json(&d.base.join(format!("result-{}.json", d.label)), &result)?;
            d.log("confirmed", json!({"result": result}))?;
            Ok(Step::Confirmed)
        })();
        match step {
            Ok(Step::Confirmed) => {
                if let Some(child) = upgrade.as_mut() {
                    if child.try_wait()?.is_none() {
                        let _ = child.kill();
                    }
                }
                return Ok(0);
            }
            Ok(Step::Abort) => return Ok(1),
            Ok(Step::Healthy) => {}
            Err(error) => {
                stable = None;
                let elapsed = d.window.monotonic() - start;
                d.log(
                    "health_not_confirmed",
                    json!({"elapsed_s": round1(elapsed), "error": error.to_string()}),
                )?;
            }
        }
        d.window.sleep(10.0);
    }
    d.log(
        "window_expired",
        json!({"automatic_recovery_left_armed": true}),
    )?;
    Ok(1)
}

/// `owrt-tools native-deploy-window stage|activate|observe DIR ...`.
pub fn deploy_main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(
        raw,
        &["--host", "--interface", "--previous-boot-id", "--label"],
        &[],
    )?;
    let [phase, directory] = args
        .exact(&["PHASE", "DIRECTORY"])?
        .try_into()
        .expect("two positionals");
    ensure!(
        matches!(phase.as_str(), "stage" | "activate" | "observe"),
        "phase must be stage, activate or observe"
    );
    let options = WindowArgs {
        phase,
        directory: PathBuf::from(directory),
        host: args.value("--host").unwrap_or("openwrt").into(),
        interface: args.value("--interface").unwrap_or("en0").into(),
        previous_boot_id: args.value("--previous-boot-id").map(str::to_owned),
        label: args.value("--label").unwrap_or("initial").into(),
    };
    deploy_window(
        &options,
        &mut RealWindow {
            start: std::time::Instant::now(),
        },
    )
}

// ------------------------------------------------------------ trial prepare

/// One archive member's shape for [`validate_members`].
pub struct MemberInfo {
    pub name: String,
    pub kind: tar::EntryType,
}

/// Rejects ambiguous paths and archive links that could redirect extraction.
pub fn validate_members(members: &[MemberInfo], reserved: &[String]) -> Result<()> {
    let mut names = BTreeSet::new();
    let mut links = BTreeSet::new();
    for member in members {
        let name = member
            .name
            .trim_start_matches('/')
            .trim_end_matches('/')
            .to_owned();
        ensure!(
            !name.is_empty() && !name.split('/').any(|part| part == ".." || part == "."),
            "{name}"
        );
        ensure!(
            name.chars().all(|c| c as u32 >= 32 && c as u32 != 127),
            "{name:?}"
        );
        ensure!(!name.starts_with('-'), "{name}");
        ensure!(!names.contains(&name) && !name.contains("//"), "{name}");
        ensure!(
            member.kind.is_file() || member.kind.is_dir() || member.kind.is_symlink(),
            "{name}"
        );
        ensure!(!name.ends_with(".boot-enable"), "{name}");
        ensure!(
            !reserved
                .iter()
                .any(|path| name == *path || name.starts_with(&format!("{path}/"))),
            "{name}"
        );
        if member.kind.is_symlink() {
            links.insert(name.clone());
        }
        names.insert(name);
    }
    for name in names.iter().chain(reserved) {
        let mut parent = Path::new(name).parent();
        while let Some(path) = parent.filter(|p| !p.as_os_str().is_empty()) {
            ensure!(!links.contains(&util::display(path)), "{name}");
            parent = path.parent();
        }
    }
    Ok(())
}

struct Original {
    header: tar::Header,
    name: String,
    link: Option<PathBuf>,
    data: Vec<u8>,
}

fn read_members(path: &Path) -> Result<Vec<Original>> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(fs::File::open(path)?));
    let mut members = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.to_string_lossy().into_owned();
        let link = entry.link_name()?.map(|l| l.into_owned());
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        members.push(Original {
            header: entry.header().clone(),
            name,
            link,
            data,
        });
    }
    Ok(members)
}

pub struct TrialArgs {
    pub config: PathBuf,
    pub manifest: PathBuf,
    pub bounded: PathBuf,
    pub output: PathBuf,
    pub rootfs: PathBuf,
    pub rollback_image: PathBuf,
    pub rollback_sha256: String,
    pub rollback_version: String,
}

fn payload_header(kind: tar::EntryType, mode: u32, size: u64) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(size);
    header
}

pub fn trial_prepare(args: &TrialArgs) -> Result<Value> {
    ensure!(
        Regex::new(r"^v[0-9]+\.[0-9]+\.[0-9]+$")?.is_match(&args.rollback_version),
        "invalid rollback version"
    );
    ensure!(!args.output.exists(), "output exists");
    let manifest = util::read_json(&args.manifest)?;
    let paths = native_paths(manifest.get("deployment_layout").and_then(Value::as_str))?;
    ensure!(
        component_paths(&manifest)? == paths,
        "component paths differ from layout"
    );
    ensure!(
        manifest.obj_field("integration_files")?.len() == 2,
        "expected two integration files"
    );
    let rollback_image = fs::read(&args.rollback_image)?;
    ensure!(
        util::sha256_bytes(&rollback_image) == args.rollback_sha256,
        "rollback image hash differs"
    );
    let original_config = fs::read(&args.config)?;
    let original = read_members(&args.config)?;
    let original_names: Vec<String> = original
        .iter()
        .map(|m| {
            m.name
                .trim_start_matches('/')
                .trim_end_matches('/')
                .to_owned()
        })
        .collect();
    let member_list = (original_names.join("\n") + "\n").into_bytes();
    let repo = util::repo();
    let base = "root/owrt-native-trial/";
    let token = util::uuid4()?;
    let files: Vec<&Value> = manifest
        .obj_field("components")?
        .values()
        .chain(manifest.obj_field("integration_files")?.values())
        .collect();
    let release_path = args
        .rootfs
        .join("usr/share/owrt-control-plane/release.json");
    let image_manifest = util::read_json(&release_path)?;
    for key in ["source_commit", "components", "integration_files"] {
        ensure!(
            image_manifest.get(key) == manifest.get(key),
            "candidate rootfs {key} differs from the manifest"
        );
    }
    let stock = util::read_text(
        &args
            .rootfs
            .join("usr/share/owrt-control-plane/stock.sha256"),
    )?;
    let observed = util::sum_map(&stock)?;
    ensure!(
        util::splitlines(&stock).len() == files.len() && observed.len() == files.len(),
        "stock manifest count differs"
    );
    let expected: BTreeMap<String, String> = files
        .iter()
        .map(|c| {
            Ok((
                c.str_field("recovery_path")?.to_owned(),
                c.str_field("stock_sha256")?.to_owned(),
            ))
        })
        .collect::<Result<_>>()?;
    ensure!(
        observed == expected,
        "stock manifest differs from the release"
    );
    for (path, digest) in &observed {
        ensure!(
            sha(&args.rootfs.join(path.trim_start_matches('/')))? == *digest,
            "recovery file differs: {path}"
        );
    }
    let mut recovery = stock.clone();
    recovery += &format!(
        "{}  /usr/sbin/owrt-recover-c\n",
        sha(&args.rootfs.join("usr/sbin/owrt-recover-c"))?
    );
    recovery += &format!(
        "{}  /usr/share/owrt-control-plane/stock.sha256\n",
        util::sha256_bytes(stock.as_bytes())
    );
    let rollback = format!("{}  /{base}rollback.bin\n{}  /{base}rollback-config.tar.gz\n{}  /{base}rollback-members.txt\n",
                           args.rollback_sha256, util::sha256_bytes(&original_config), util::sha256_bytes(&member_list));
    let payload: Vec<(String, Vec<u8>, u32)> = vec![
        (
            format!("{base}native_trial_guard.sh"),
            fs::read(repo.join("tools/native_trial_guard.sh"))?,
            0o700,
        ),
        (format!("{base}bounded"), fs::read(&args.bounded)?, 0o700),
        (
            format!("{base}armed"),
            format!("{token}\n").into_bytes(),
            0o600,
        ),
        (
            format!("{base}recovery.sha256"),
            recovery.into_bytes(),
            0o600,
        ),
        (
            format!("{base}rollback.sha256"),
            rollback.into_bytes(),
            0o600,
        ),
        (format!("{base}rollback.bin"), rollback_image.clone(), 0o600),
        (
            format!("{base}rollback-config.tar.gz"),
            original_config.clone(),
            0o600,
        ),
        (format!("{base}rollback-members.txt"), member_list, 0o600),
        (
            "etc/init.d/owrt-native-trial".into(),
            fs::read(repo.join("tools/native_trial.init"))?,
            0o755,
        ),
    ];
    let link = "etc/rc.d/S01owrt-native-trial";
    let mut hashes = Map::new();
    for (name, data, _) in &payload {
        hashes.insert(name.clone(), json!(util::sha256_bytes(data)));
    }
    let base_dir = base.trim_end_matches('/');
    let mut reserved = vec![base_dir.to_owned()];
    reserved.extend(payload.iter().map(|(name, _, _)| name.clone()));
    reserved.extend([
        link.to_owned(),
        "root/owrt-native-rollback-receipt".to_owned(),
    ]);
    reserved.extend(files.iter().filter_map(|c| {
        c["path"]
            .as_str()
            .map(|p| p.trim_start_matches('/').to_owned())
    }));
    let infos: Vec<MemberInfo> = original
        .iter()
        .map(|m| MemberInfo {
            name: m.name.clone(),
            kind: m.header.entry_type(),
        })
        .collect();
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&args.output)?;
        util::set_mode(&args.output, 0o600)?;
        validate_members(&infos, &reserved)?;
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            file,
            flate2::Compression::default(),
        ));
        let mut names = BTreeSet::new();
        for member in &original {
            let name = member.name.trim_start_matches('/').to_owned();
            ensure!(
                !name.split('/').any(|part| part == "..") && names.insert(name.clone()),
                "{name}"
            );
            ensure!(
                !payload.iter().any(|(p, _, _)| *p == name)
                    && name != link
                    && name != base_dir
                    && !name.starts_with(base),
                "{name}"
            );
            ensure!(!name.ends_with(".boot-enable"), "{name}");
            let mut header = member.header.clone();
            match &member.link {
                Some(target) if member.header.entry_type().is_symlink() => {
                    builder.append_link(&mut header, &name, target)?
                }
                _ => builder.append_data(&mut header, &name, member.data.as_slice())?,
            }
        }
        builder.append_data(
            &mut payload_header(tar::EntryType::Directory, 0o700, 0),
            base_dir,
            std::io::empty(),
        )?;
        for (name, data, mode) in &payload {
            builder.append_data(
                &mut payload_header(tar::EntryType::Regular, *mode, data.len() as u64),
                name,
                data.as_slice(),
            )?;
        }
        builder.append_link(
            &mut payload_header(tar::EntryType::Symlink, 0o777, 0),
            link,
            "../init.d/owrt-native-trial",
        )?;
        builder.into_inner()?.finish()?;
    }
    // Re-read both archives: every original member and payload entry must
    // survive exactly.
    let written: BTreeMap<String, Original> = read_members(&args.output)?
        .into_iter()
        .map(|m| (m.name.clone(), m))
        .collect();
    for member in &original {
        let copy = written
            .get(member.name.trim_start_matches('/'))
            .ok_or_else(|| util::Error::new(format!("lost {}", member.name)))?;
        let shape = |m: &Original| -> Result<(u8, u32, u64, u64, Option<PathBuf>)> {
            Ok((
                m.header.entry_type().as_byte(),
                m.header.mode()?,
                m.header.uid()?,
                m.header.gid()?,
                m.link.clone(),
            ))
        };
        ensure!(
            shape(member)? == shape(copy)?,
            "member metadata changed: {}",
            member.name
        );
        if member.header.entry_type().is_file() {
            ensure!(
                member.data == copy.data,
                "member content changed: {}",
                member.name
            );
        }
    }
    for (name, data, mode) in &payload {
        let entry = written
            .get(name)
            .ok_or_else(|| util::Error::new(format!("payload missing: {name}")))?;
        ensure!(
            entry.data == *data
                && (
                    entry.header.uid()?,
                    entry.header.gid()?,
                    entry.header.mode()?
                ) == (0, 0, *mode),
            "payload differs: {name}"
        );
    }
    ensure!(
        written.get(link).and_then(|m| m.link.clone())
            == Some(PathBuf::from("../init.d/owrt-native-trial")),
        "guard start link differs"
    );
    let result = json!({"image": manifest["image"], "token": token, "archive_sha256": sha(&args.output)?,
                        "original_config_archive_sha256": util::sha256_bytes(&original_config),
                        "original_members_preserved": original.len(), "payload_sha256": hashes, "guard_start_link": link,
                        "first_confirmation_timeout_s": 600, "accepted_health_failure_timeout_s": 300, "unhealthy_boot_limit": 3,
                        "confirmation_required_each_boot": true, "rollback_image_sha256": args.rollback_sha256,
                        "rollback_image_bytes": rollback_image.len(), "rollback_version": args.rollback_version,
                        "recovery_rootfs_manifest_sha256": sha(&release_path)?});
    let record = args.output.with_extension("json");
    ensure!(!record.exists(), "record exists: {}", record.display());
    util::write_json(&record, &result)?;
    util::set_mode(&record, 0o600)?;
    println!(
        "Prepared {}; all {} original backup members preserved",
        args.output.display(),
        original.len()
    );
    Ok(result)
}

/// `owrt-tools native-trial-prepare CONFIG MANIFEST BOUNDED OUTPUT --rootfs R
/// --rollback-image I --rollback-sha256 H --rollback-version V`.
pub fn trial_main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(
        raw,
        &[
            "--rootfs",
            "--rollback-image",
            "--rollback-sha256",
            "--rollback-version",
        ],
        &[],
    )?;
    let [config, manifest, bounded, output] = args
        .exact(&["CONFIG", "MANIFEST", "BOUNDED", "OUTPUT"])?
        .try_into()
        .expect("four positionals");
    trial_prepare(&TrialArgs {
        config: config.into(),
        manifest: manifest.into(),
        bounded: bounded.into(),
        output: output.into(),
        rootfs: args.required("--rootfs")?.into(),
        rollback_image: args.required("--rollback-image")?.into(),
        rollback_sha256: args.required("--rollback-sha256")?.into(),
        rollback_version: args.required("--rollback-version")?.into(),
    })?;
    Ok(0)
}

#[cfg(test)]
mod tests;

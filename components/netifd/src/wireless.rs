//! `network.wireless`.
//!
//! netifd hosts a ucode VM that loads `/lib/netifd/wireless.uc`, which
//! publishes this object. The parts of it that decide what the object looks
//! like to a caller do not need the VM, and they are here: the handler
//! discovery, the merged attribute schema built from it, and the projection
//! of `/etc/config/wireless`.
//!
//! Bringing radios up is the handler script's job and needs real hardware, so
//! that half is not reproduced -- see R45.

use std::path::{Path, PathBuf};

use owrt_ubus::json::{self as json, Json};

/// `utils.uc`'s attribute type codes.
pub const TYPE_ARRAY: u32 = 1;
pub const TYPE_STRING: u32 = 3;
pub const TYPE_INT: u32 = 5;
pub const TYPE_BOOL: u32 = 7;

/// `attr_validate`: the name a type code is reported under. An unknown code
/// returns `None` and wireless.uc's `if (val != null)` then drops the
/// attribute from `get_validate` -- it stays in the schema for the status
/// projection, it just has no validation expression to print.
pub fn type_name(t: u32) -> Option<&'static str> {
    Some(match t {
        TYPE_STRING => "string",
        TYPE_ARRAY => "list(string)",
        TYPE_INT => "uinteger",
        TYPE_BOOL => "bool",
        _ => return None,
    })
}

/// `network_config_attr`, spread into both `iface` and `vlan`.
const NETWORK_CONFIG_ATTR: &[(&str, u32)] = &[
    ("network", TYPE_ARRAY),
    ("network_vlan", TYPE_ARRAY),
    ("bridge_isolate", TYPE_BOOL),
    ("isolate", TYPE_BOOL),
    ("proxy_arp", TYPE_BOOL),
    ("multicast_to_unicast", TYPE_BOOL),
];

/// The four kinds of `default_config_attr`, in that object's key order --
/// `get_validate` iterates it with `for (let kind in ...)`, so this order is
/// the order the reply's sections come out in. The second element is the name
/// the section is reported under: `iface` is published as `interface`.
pub const KINDS: &[(&str, &str)] = &[
    ("device", "device"),
    ("iface", "interface"),
    ("station", "station"),
    ("vlan", "vlan"),
];

/// `default_config_attr[kind]`, in declaration order. Order matters: it is
/// the base of the merge below, and ucode objects keep insertion order.
pub fn default_attrs(kind: &str) -> Vec<(String, u32)> {
    let mut v: Vec<(String, u32)> = Vec::new();
    let mut push = |n: &str, t: u32| v.push((n.to_string(), t));
    match kind {
        "device" => {
            push("disabled", TYPE_BOOL);
            push("type", TYPE_STRING);
        }
        "iface" => {
            for (n, t) in NETWORK_CONFIG_ATTR {
                push(n, *t);
            }
            push("device", TYPE_STRING);
            push("mode", TYPE_STRING);
            push("radio_macaddr", TYPE_ARRAY);
        }
        "station" => {
            push("iface", TYPE_STRING);
            push("mac", TYPE_STRING);
            push("key", TYPE_STRING);
            push("vid", TYPE_STRING);
        }
        "vlan" => {
            for (n, t) in NETWORK_CONFIG_ATTR {
                push(n, *t);
            }
            push("iface", TYPE_STRING);
            push("name", TYPE_STRING);
            push("vid", TYPE_STRING);
        }
        _ => {}
    }
    v
}

/// `utils.uc:handler_attributes`. The defaults go in first, then each dumped
/// entry: a name already present keeps its position and takes the new type,
/// a new name is appended. So the result is neither sorted nor purely the
/// handler's order, and both halves of that matter -- `mac80211` redeclares
/// `disabled` and `device`, and the C prints them where the defaults put
/// them, with the handler's type.
///
/// An entry's name may carry its validation expression after a colon
/// (`split(cur[0], ":", 2)`), which is what `get_validate` prints instead of
/// the type name.
fn merge_attrs(kind: &str, dumped: &[(String, u32)]) -> (Attrs, Validators) {
    let mut attrs = default_attrs(kind);
    let mut validate: Vec<(String, String)> = Vec::new();
    for (raw, ty) in dumped {
        let (name, expr) = match raw.split_once(':') {
            Some((n, e)) => (n.to_string(), Some(e.to_string())),
            None => (raw.clone(), None),
        };
        if let Some(e) = expr {
            match validate.iter_mut().find(|(n, _)| *n == name) {
                Some(slot) => slot.1 = e,
                None => validate.push((name.clone(), e)),
            }
        }
        match attrs.iter_mut().find(|(n, _)| *n == name) {
            Some(slot) => slot.1 = *ty,
            None => attrs.push((name, *ty)),
        }
    }
    (attrs, validate)
}

/// A kind's attributes, in reply order.
pub type Attrs = Vec<(String, u32)>;
/// A kind's explicit validation expressions.
pub type Validators = Vec<(String, String)>;

/// One `/lib/netifd/wireless/<name>.sh`.
#[derive(Clone, Debug, Default)]
pub struct Handler {
    pub name: String,
    pub script: PathBuf,
    /// Keyed by `default_config_attr`'s kind (`iface`, not `interface`).
    pub attrs: Vec<(String, Vec<(String, u32)>)>,
    pub validate: Vec<(String, Vec<(String, String)>)>,
}

impl Handler {
    pub fn attrs_of(&self, kind: &str) -> &[(String, u32)] {
        self.attrs
            .iter()
            .find(|(k, _)| k == kind)
            .map(|(_, v)| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn validate_of(&self, kind: &str) -> &[(String, String)] {
        self.validate
            .iter()
            .find(|(k, _)| k == kind)
            .map(|(_, v)| v.as_slice())
            .unwrap_or(&[])
    }

    /// `get_validate`'s per-handler body: every attribute that has a printable
    /// validation expression, in schema order.
    pub fn validate_info(&self) -> Vec<(&str, Vec<(String, String)>)> {
        KINDS
            .iter()
            .map(|(kind, reported)| {
                let v = self.validate_of(kind);
                let body = self
                    .attrs_of(kind)
                    .iter()
                    .filter_map(|(name, ty)| {
                        let expr = match v.iter().find(|(n, _)| n == name) {
                            Some((_, e)) => e.clone(),
                            None => type_name(*ty)?.to_string(),
                        };
                        Some((name.clone(), expr))
                    })
                    .collect();
                (*reported, body)
            })
            .collect()
    }
}

fn handler_from(script: &Path, j: &Json) -> Option<Handler> {
    let name = j.get("name")?.as_str()?.to_string();
    let mut h = Handler {
        name,
        script: script.to_path_buf(),
        ..Default::default()
    };
    for (kind, _) in KINDS {
        let mut dumped: Vec<(String, u32)> = Vec::new();
        if let Some(list) = j.get(kind).and_then(|l| l.as_array()) {
            for entry in list {
                let Some(pair) = entry.as_array() else {
                    continue;
                };
                let Some(attr) = pair.first().and_then(|a| a.as_str()) else {
                    continue;
                };
                let Some(Json::Int(code)) = pair.get(1) else {
                    continue;
                };
                dumped.push((attr.to_string(), *code as u32));
            }
        }
        let (attrs, validate) = merge_attrs(kind, &dumped);
        h.attrs.push((kind.to_string(), attrs));
        h.validate.push((kind.to_string(), validate));
    }
    Some(h)
}

/// Every handler in `dir`, discovered the way netifd discovers them: run each
/// script as `./<name> "" dump` with the directory as the working directory
/// -- they source `/lib/netifd/netifd-wireless.sh` relatively -- and read the
/// JSON it prints.
pub fn discover(dir: &Path) -> Vec<Handler> {
    let mut out: Vec<Handler> = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut names: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    names.sort();
    for path in names {
        let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        let Ok(o) = std::process::Command::new(format!("./{file}"))
            .arg("")
            .arg("dump")
            .current_dir(dir)
            .output()
        else {
            continue;
        };
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(h) = json::parse(line)
                .ok()
                .as_ref()
                .and_then(|j| handler_from(&path, j))
            {
                out.push(h);
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireless_debug_redacts_options_and_cached_payloads() {
        let secret = "wpa-key-that-must-not-be-logged";
        let opts = vec![("key".into(), Val::Str(secret.into()))];
        let sub = Sub {
            section: "station".into(),
            opts: opts.clone(),
        };
        let vif = Vif {
            section: "lan".into(),
            opts: opts.clone(),
            stas: vec![sub.clone()],
            status_config: secret.as_bytes().to_vec(),
            ..Default::default()
        };
        let radio = Radio {
            name: "radio0".into(),
            opts,
            vifs: vec![vif.clone()],
            status_config: secret.as_bytes().to_vec(),
        };
        let encoded = format!("{:?}", secret.as_bytes());
        for debug in [
            format!("{sub:?}"),
            format!("{vif:?}"),
            format!("{radio:?}"),
            format!("{radio:#?}"),
        ] {
            assert!(!debug.contains(secret), "credential leaked: {debug}");
            assert!(
                !debug.contains(&encoded),
                "encoded credential leaked: {debug}"
            );
            assert!(!debug.contains("status_config"));
        }
        assert_eq!(radio.status_config, secret.as_bytes());
        assert_eq!(vif.opts[0].1, Val::Str(secret.into()));
    }

    fn h(dump: &str) -> Handler {
        handler_from(Path::new("/x.sh"), &json::parse(dump).unwrap()).unwrap()
    }

    #[test]
    fn the_type_codes_are_utils_ucs() {
        assert_eq!(type_name(TYPE_STRING), Some("string"));
        assert_eq!(type_name(TYPE_ARRAY), Some("list(string)"));
        assert_eq!(type_name(TYPE_INT), Some("uinteger"));
        assert_eq!(type_name(TYPE_BOOL), Some("bool"));
        assert_eq!(type_name(2), None);
    }

    #[test]
    fn every_kind_is_present() {
        let x = h(r#"{"name":"mac80211"}"#);
        for (kind, _) in KINDS {
            assert!(!x.attrs_of(kind).is_empty(), "{kind}");
        }
    }

    // The merge is the whole point of this module, and getting it wrong is
    // invisible until a caller diffs the reply: mac80211 redeclares `disabled`
    // and `device`, and the C keeps the default's POSITION with the handler's
    // TYPE.
    #[test]
    fn a_redeclared_attribute_keeps_its_position_and_takes_the_new_type() {
        let x = h(r#"{"name":"mac80211","device":[["acs_chan_bias",3],["disabled",7]]}"#);
        let d = x.attrs_of("device");
        assert_eq!(d[0].0, "disabled");
        assert_eq!(d[1].0, "type");
        assert_eq!(d[2].0, "acs_chan_bias");

        let x = h(r#"{"name":"mac80211","iface":[["device",1],["ssid",3]]}"#);
        let names: Vec<&str> = x
            .attrs_of("iface")
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(names[6], "device");
        assert_eq!(x.attrs_of("iface")[6].1, TYPE_ARRAY);
        assert_eq!(names.last(), Some(&"ssid"));
    }

    #[test]
    fn a_validator_rides_on_the_name_after_a_colon() {
        let x = h(r#"{"name":"m","device":[["chanbw:range(5,20)",5]]}"#);
        assert_eq!(x.attrs_of("device").last().unwrap().0, "chanbw");
        assert_eq!(
            x.validate_of("device"),
            [("chanbw".into(), "range(5,20)".into())]
        );
        let info = x.validate_info();
        assert_eq!(info[0].0, "device");
        assert_eq!(
            info[0].1.last().unwrap(),
            &("chanbw".into(), "range(5,20)".into())
        );
    }

    #[test]
    fn an_unknown_type_code_is_dropped_from_get_validate_only() {
        let x = h(r#"{"name":"m","station":[["odd",42]]}"#);
        assert!(x.attrs_of("station").iter().any(|(n, _)| n == "odd"));
        let info = x.validate_info();
        let station = &info.iter().find(|(k, _)| *k == "station").unwrap().1;
        assert!(!station.iter().any(|(n, _)| n == "odd"));
    }

    fn confdir(text: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "netifd-wl-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("wireless"), text).unwrap();
        dir.to_string_lossy().into_owned()
    }

    fn mac80211() -> Vec<Handler> {
        vec![h(
            r#"{"name":"mac80211","device":[["path",3],["disabled",7]],
                   "iface":[["ssid",3],["encryption",3],["radios",1]]}"#,
        )]
    }

    // Each of these was a real difference against the C before it was fixed;
    // r59 catches them too, but only where the device rootfs is reachable.
    #[test]
    fn a_radio_needs_a_type_a_handler_claims() {
        let hs = mac80211();
        let c = confdir(
            "config wifi-device 'good'\n\toption type 'mac80211'\n\n\
             config wifi-device 'untyped'\n\toption path 'x'\n\n\
             config wifi-device 'unknown'\n\toption type 'nosuchhandler'\n",
        );
        let names: Vec<String> = load(&c, &hs).into_iter().map(|r| r.name).collect();
        assert_eq!(names, ["good"]);
    }

    #[test]
    fn disabled_keeps_a_device_and_drops_an_iface() {
        let hs = mac80211();
        let c = confdir(
            "config wifi-device 'radio0'\n\toption type 'mac80211'\n\toption disabled '1'\n\n\
             config wifi-iface 'off'\n\toption device 'radio0'\n\toption disabled 'true'\n",
        );
        let r = load(&c, &hs);
        assert_eq!(r.len(), 1, "a disabled wifi-device is still reported");
        assert!(r[0].vifs.is_empty());
    }

    // `parse_bool` takes 1/0/true/false and nothing else, so UCI's `on` --
    // true everywhere else in netifd -- leaves the radio enabled here.
    #[test]
    fn on_is_not_a_boolean_to_parse_bool() {
        let hs = mac80211();
        let c = confdir(
            "config wifi-device 'radio0'\n\toption type 'mac80211'\n\toption disabled 'on'\n\n\
             config wifi-iface 'ap'\n\toption device 'radio0'\n\toption ssid 'x'\n",
        );
        let r = load(&c, &hs);
        assert!(!r[0].disabled());
        assert_eq!(
            r[0].vifs.len(),
            1,
            "the iface survives an unparsable disabled"
        );
        // and it reaches the caller as a present-but-empty key
        assert!(status_json(&r, &hs, RadioState::default(), &[]).contains("\"disabled\":null"));
    }

    #[test]
    fn one_iface_lands_under_every_device_it_names() {
        let hs = mac80211();
        let c = confdir(
            "config wifi-device 'radio0'\n\toption type 'mac80211'\n\toption radio '0'\n\n\
             config wifi-device 'radio1'\n\toption type 'mac80211'\n\toption radio '1'\n\n\
             config wifi-iface 'both'\n\toption device 'radio0 radio1'\n\toption ssid 'x'\n\n\
             config wifi-iface 'orphan'\n\toption device 'radio9'\n",
        );
        let r = load(&c, &hs);
        assert_eq!(r[0].vifs.len(), 1);
        assert_eq!(r[1].vifs.len(), 1);
        assert_eq!(
            r[0].vifs[0].radios,
            [0, 1],
            "radios covers every named device"
        );
    }

    // `config.radios` is assigned after parse_attribute_list, so it is last
    // even though the schema puts `radios` earlier.
    #[test]
    fn radios_is_always_present_and_always_last() {
        let hs = mac80211();
        let c = confdir(
            "config wifi-device 'radio0'\n\toption type 'mac80211'\n\n\
             config wifi-iface 'ap'\n\toption device 'radio0'\n\toption ssid 'x'\n",
        );
        let j = status_json(&load(&c, &hs), &hs, RadioState::default(), &[]);
        assert!(j.contains(r#""ssid":"x","radios":[]"#), "{j}");
    }

    #[test]
    fn iface_is_reported_as_interface() {
        let x = h(r#"{"name":"m"}"#);
        let reported: Vec<&str> = x.validate_info().iter().map(|(k, _)| *k).collect();
        assert_eq!(reported, ["device", "interface", "station", "vlan"]);
    }
}

// ---------------------------------------------------------------------------
// The projection of /etc/config/wireless
// ---------------------------------------------------------------------------

/// A UCI option as netifd's ucode sees it: `option` is a scalar, `list` is an
/// array, and the type parsers below turn either into the declared type.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Str(String),
    List(Vec<String>),
}

/// The projected value of one attribute, in the shape `parse_attribute_list`
/// leaves it. `Bool(None)` is `parse_bool` returning nothing for a spelling it
/// does not accept -- UCI's `yes`/`on`/`enabled` are not among them, which is
/// a real difference from every other netifd option.
#[derive(Clone, Debug, PartialEq)]
pub enum Projected {
    Str(String),
    Array(Vec<String>),
    Int(i64),
    Bool(bool),
    Undefined,
}

fn parse_bool(v: &str) -> Option<bool> {
    match v {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

fn project(v: &Val, ty: u32) -> Projected {
    match (ty, v) {
        (TYPE_ARRAY, Val::List(l)) => Projected::Array(l.clone()),
        (TYPE_ARRAY, Val::Str(s)) => {
            Projected::Array(s.split_whitespace().map(|x| x.to_string()).collect())
        }
        // no parser runs for a list under a scalar type: ucode hands the array
        // straight through, which is how `device` prints as `["radio0"]`
        (_, Val::List(l)) => Projected::Array(l.clone()),
        (TYPE_STRING, Val::Str(s)) => Projected::Str(s.clone()),
        (TYPE_INT, Val::Str(s)) => Projected::Int(s.trim().parse().unwrap_or(0)),
        (TYPE_BOOL, Val::Str(s)) => match parse_bool(s) {
            Some(b) => Projected::Bool(b),
            None => Projected::Undefined,
        },
        (_, Val::Str(s)) => Projected::Str(s.clone()),
    }
}

/// `parse_attribute_list`: walk the schema in order, keep the attributes the
/// section actually sets. The schema's order is the reply's order.
pub fn attribute_list(opts: &[(String, Val)], spec: &[(String, u32)]) -> Vec<(String, Projected)> {
    spec.iter()
        .filter_map(|(name, ty)| {
            let v = opts.iter().find(|(n, _)| n == name)?;
            Some((name.clone(), project(&v.1, *ty)))
        })
        .collect()
}

/// One `config wifi-vlan` or `config wifi-station`, attached to a vif.
#[derive(Clone, Default)]
pub struct Sub {
    pub section: String,
    pub opts: Vec<(String, Val)>,
}

/// One `config wifi-iface`.
#[derive(Clone, Default)]
pub struct Vif {
    pub section: String,
    pub opts: Vec<(String, Val)>,
    pub vlans: Vec<Sub>,
    pub stas: Vec<Sub>,
    /// `config.radios`: the `option radio` index of each device the iface
    /// names. Set unconditionally after the schema attributes, so it is the
    /// last key in the reply even when it is empty.
    pub radios: Vec<i64>,
    /// Immutable config table, rebuilt with the radio generation by load.
    pub status_config: Vec<u8>,
}

/// One `config wifi-device`.
#[derive(Clone, Default)]
pub struct Radio {
    pub name: String,
    pub opts: Vec<(String, Val)>,
    pub vifs: Vec<Vif>,
    /// Dynamic state and handler ifnames are never stored here.
    pub status_config: Vec<u8>,
}

// Options and cached blobmsg tables can contain WPA/SAE keys. Summarize
// those collections rather than printing either text or encoded credentials.
impl std::fmt::Debug for Sub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sub")
            .field("section", &self.section)
            .field("option_count", &self.opts.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Vif {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vif")
            .field("section", &self.section)
            .field("option_count", &self.opts.len())
            .field("vlans", &self.vlans)
            .field("stas", &self.stas)
            .field("radios", &self.radios)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Radio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Radio")
            .field("name", &self.name)
            .field("option_count", &self.opts.len())
            .field("vifs", &self.vifs)
            .finish_non_exhaustive()
    }
}

impl Radio {
    /// `option type`, which selects the handler.
    pub fn kind(&self) -> Option<&str> {
        self.opts
            .iter()
            .find(|(n, _)| n == "type")
            .and_then(|(_, v)| match v {
                Val::Str(s) => Some(s.as_str()),
                Val::List(l) => l.first().map(|s| s.as_str()),
            })
    }

    pub fn disabled(&self) -> bool {
        self.opts
            .iter()
            .find(|(n, _)| n == "disabled")
            .map(|(_, v)| project(v, TYPE_BOOL) == Projected::Bool(true))
            .unwrap_or(false)
    }
}

/// Read `<confdir>/wireless` into radios, following `wireless.uc`'s own
/// filtering, all of which is visible in a caller's `status`:
///
///   * a section with `disabled` set to something `parse_bool` accepts as true
///     is skipped -- except a `wifi-device`, which is kept and reported;
///   * a `wifi-device` with no `type`, or a type no handler claims, never
///     becomes a radio at all;
///   * a `wifi-iface` whose device's *projected* `disabled` is truthy is
///     dropped, so `on` (which `parse_bool` does not accept) keeps it while
///     `true` does not;
///   * `device` is an array, so one `wifi-iface` can appear under several
///     radios, and one naming no known radio appears nowhere.
pub fn load(confdir: &str, handlers: &[Handler]) -> Vec<Radio> {
    let mut radios = load_config(confdir, handlers);
    for radio in &mut radios {
        cache_status_config(radio, handlers);
    }
    radios
}

/// Read a fresh configuration before the daemon reconciles it with the old
/// generation. Status caches are populated or transferred after that decision.
pub fn load_config(confdir: &str, handlers: &[Handler]) -> Vec<Radio> {
    let mut ctx = owrt_uci::context::Context::new();
    ctx.confdir = confdir.to_string();
    let Ok(idx) = owrt_uci::file::load(&mut ctx, "wireless") else {
        return Vec::new();
    };
    let pkg = &ctx.root[idx];
    let val = |o: &owrt_uci::model::Opt| match &o.value {
        owrt_uci::model::OptionValue::Str(v) => Val::Str(String::from_utf8_lossy(v).into_owned()),
        owrt_uci::model::OptionValue::List(v) => Val::List(
            v.iter()
                .map(|x| String::from_utf8_lossy(x).into_owned())
                .collect(),
        ),
    };
    let opts_of = |s: &owrt_uci::model::Section| -> Vec<(String, Val)> {
        s.options.iter().map(|o| (o.name.clone(), val(o))).collect()
    };
    let scalar = |o: &[(String, Val)], n: &str| -> Option<String> {
        o.iter().find(|(k, _)| k == n).map(|(_, v)| match v {
            Val::Str(s) => s.clone(),
            Val::List(l) => l.join(" "),
        })
    };
    // `parse_bool(data.disabled)`, on the raw option
    let raw_disabled = |o: &[(String, Val)]| -> bool {
        scalar(o, "disabled")
            .and_then(|v| parse_bool(&v))
            .unwrap_or(false)
    };

    let mut radios: Vec<Radio> = Vec::new();
    let mut radio_idx: Vec<(String, i64)> = Vec::new();
    for s in pkg.sections.iter().filter(|s| s.ty == "wifi-device") {
        let opts = opts_of(s);
        // a disabled wifi-device is still reported
        let Some(kind) = scalar(&opts, "type").filter(|t| !t.is_empty()) else {
            continue;
        };
        if !handlers.iter().any(|h| h.name == kind) {
            continue;
        }
        if let Some(n) = scalar(&opts, "radio").and_then(|v| v.trim().parse::<i64>().ok()) {
            radio_idx.push((s.name.clone(), n));
        }
        radios.push(Radio {
            name: s.name.clone(),
            opts,
            ..Default::default()
        });
    }

    for s in pkg.sections.iter().filter(|s| s.ty == "wifi-iface") {
        let opts = opts_of(s);
        if raw_disabled(&opts) {
            continue;
        }
        let dev_names: Vec<String> = scalar(&opts, "device")
            .map(|v| v.split_whitespace().map(|x| x.to_string()).collect())
            .unwrap_or_default();
        // `config.radios`, computed once from every named device and then set
        // on the vif under each of them
        let radios_of: Vec<i64> = dev_names
            .iter()
            .filter_map(|d| radio_idx.iter().find(|(n, _)| n == d).map(|(_, i)| *i))
            .collect();
        for d in &dev_names {
            let Some(r) = radios.iter_mut().find(|r| r.name == *d) else {
                continue;
            };
            if r.disabled() {
                continue;
            }
            r.vifs.push(Vif {
                section: s.name.clone(),
                opts: opts.clone(),
                radios: radios_of.clone(),
                vlans: Vec::new(),
                stas: Vec::new(),
                status_config: Vec::new(),
            });
        }
    }

    // `wifi-vlan` and `wifi-station` name the wifi-iface SECTIONS they belong
    // to in `iface`, as an array; an empty list means every vif. A disabled
    // one is dropped like any non-device section.
    for s in pkg
        .sections
        .iter()
        .filter(|s| s.ty == "wifi-vlan" || s.ty == "wifi-station")
    {
        let opts = opts_of(s);
        if raw_disabled(&opts) {
            continue;
        }
        let want: Vec<String> = scalar(&opts, "iface")
            .map(|v| v.split_whitespace().map(|x| x.to_string()).collect())
            .unwrap_or_default();
        for r in radios.iter_mut() {
            for v in r.vifs.iter_mut() {
                if !want.is_empty() && !want.contains(&v.section) {
                    continue;
                }
                let sub = Sub {
                    section: s.name.clone(),
                    opts: opts.clone(),
                };
                if s.ty == "wifi-vlan" {
                    v.vlans.push(sub);
                } else {
                    v.stas.push(sub);
                }
            }
        }
    }
    radios
}

// ---------------------------------------------------------------------------
// The two read methods
// ---------------------------------------------------------------------------

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            '\r' => o.push_str("\\r"),
            _ => o.push(c),
        }
    }
    o
}

fn arr(items: &[String]) -> String {
    let body: Vec<String> = items.iter().map(|s| format!("\"{}\"", esc(s))).collect();
    format!("[{}]", body.join(","))
}

fn projected(v: &Projected) -> Option<String> {
    Some(match v {
        Projected::Str(s) => format!("\"{}\"", esc(s)),
        Projected::Array(l) => arr(l),
        Projected::Int(n) => n.to_string(),
        Projected::Bool(b) => b.to_string(),
        // `parse_bool` returned nothing. ucode still assigns, so the key is
        // there with no value -- the C prints `"disabled": null`.
        Projected::Undefined => "null".to_string(),
    })
}

fn obj(fields: &[(String, String)]) -> String {
    let body: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("\"{}\":{}", esc(k), v))
        .collect();
    format!("{{{}}}", body.join(","))
}

fn attr_obj(opts: &[(String, Val)], spec: &[(String, u32)]) -> String {
    let fields: Vec<(String, String)> = attribute_list(opts, spec)
        .into_iter()
        .filter_map(|(k, v)| projected(&v).map(|v| (k, v)))
        .collect();
    obj(&fields)
}

/// What `network.wireless status` reports for a radio whose handler never ran.
/// The four state booleans are the only fields that depend on the radio having
/// been brought up; everything else is the config projection.
#[derive(Clone, Copy, Debug)]
pub struct RadioState {
    pub up: bool,
    pub pending: bool,
    pub autostart: bool,
    pub retry_setup_failed: bool,
}

impl Default for RadioState {
    fn default() -> Self {
        // `wdev_create` sets autostart; a setup that never succeeded leaves
        // state "down" and retry_setup_failed set.
        RadioState {
            up: false,
            pending: false,
            autostart: true,
            retry_setup_failed: true,
        }
    }
}

/// `status`, as compact JSON. Report ifnames received through handler notify.
pub fn status_json(
    radios: &[Radio],
    handlers: &[Handler],
    st: RadioState,
    ifnames: &[(String, String)],
) -> String {
    let mut out: Vec<(String, String)> = Vec::new();
    for r in radios {
        let h = r.kind().and_then(|k| handlers.iter().find(|h| h.name == k));
        let dev_spec = h.map(|h| h.attrs_of("device")).unwrap_or(&[]);
        let if_spec = h.map(|h| h.attrs_of("iface")).unwrap_or(&[]);
        let vlan_spec = h.map(|h| h.attrs_of("vlan")).unwrap_or(&[]);
        let sta_spec = h.map(|h| h.attrs_of("station")).unwrap_or(&[]);

        let ifaces: Vec<String> = r
            .vifs
            .iter()
            .map(|v| {
                let mut cfg: Vec<(String, String)> = attribute_list(&v.opts, if_spec)
                    .into_iter()
                    .filter_map(|(k, p)| projected(&p).map(|p| (k, p)))
                    .collect();
                let list: Vec<String> = v.radios.iter().map(|n| n.to_string()).collect();
                cfg.retain(|(k, _)| k != "radios");
                cfg.push(("radios".into(), format!("[{}]", list.join(","))));
                let mut fields: Vec<(String, String)> = vec![
                    ("section".into(), format!("\"{}\"", esc(&v.section))),
                    ("config".into(), obj(&cfg)),
                ];
                // `get_status_data` appends `ifname` only once the handler has
                // reported one, so it is absent until a radio comes up
                if let Some((_, n)) = ifnames.iter().find(|(sec, _)| *sec == v.section) {
                    fields.push(("ifname".into(), format!("\"{}\"", esc(n))));
                }
                let sub_list = |subs: &[Sub], spec: &[(String, u32)], vlan: bool| -> String {
                    let items: Vec<String> = subs
                        .iter()
                        .map(|sub| {
                            let mut fields = vec![
                                ("section".into(), format!("\"{}\"", esc(&sub.section))),
                                ("config".into(), attr_obj(&sub.opts, spec)),
                            ];
                            let key = if vlan {
                                format!("{}/{}", v.section, sub.section)
                            } else {
                                sub.section.clone()
                            };
                            if let Some((_, name)) =
                                ifnames.iter().find(|(section, _)| *section == key)
                            {
                                fields.push(("ifname".into(), format!("\"{}\"", esc(name))));
                            }
                            obj(&fields)
                        })
                        .collect();
                    format!("[{}]", items.join(","))
                };
                fields.push(("vlans".into(), sub_list(&v.vlans, vlan_spec, true)));
                fields.push(("stations".into(), sub_list(&v.stas, sta_spec, false)));
                obj(&fields)
            })
            .collect();

        out.push((
            r.name.clone(),
            obj(&[
                ("up".into(), st.up.to_string()),
                ("pending".into(), st.pending.to_string()),
                ("autostart".into(), st.autostart.to_string()),
                ("disabled".into(), r.disabled().to_string()),
                (
                    "retry_setup_failed".into(),
                    st.retry_setup_failed.to_string(),
                ),
                ("config".into(), attr_obj(&r.opts, dev_spec)),
                ("interfaces".into(), format!("[{}]", ifaces.join(","))),
            ]),
        ));
    }
    obj(&out)
}

/// The status projection in wire order, borrowing the configuration. Handler
/// commands still use their existing JSON contract; only the ubus reply skips
/// the temporary JSON strings and parse tree.
pub fn status_into_blob(
    b: &mut owrt_ubus::blob::BlobBuf,
    r: &Radio,
    handlers: &[Handler],
    st: RadioState,
    ifnames: &[(String, String)],
) {
    let h = r.kind().and_then(|k| handlers.iter().find(|h| h.name == k));
    let spec = |kind| h.map(|h| h.attrs_of(kind)).unwrap_or(&[]);
    let radio = b.msg_open_table(&r.name);
    b.msg_bool("up", st.up);
    b.msg_bool("pending", st.pending);
    b.msg_bool("autostart", st.autostart);
    b.msg_bool("disabled", r.disabled());
    b.msg_bool("retry_setup_failed", st.retry_setup_failed);
    if r.status_config.is_empty() {
        config_into_blob(b, &r.opts, spec("device"), None);
    } else {
        b.put_raw_fields(&r.status_config);
    }
    let interfaces = b.msg_open_array("interfaces");
    for v in &r.vifs {
        let iface = b.msg_open_table("");
        b.msg_string("section", &v.section);
        if v.status_config.is_empty() {
            config_into_blob(b, &v.opts, spec("iface"), Some(&v.radios));
        } else {
            b.put_raw_fields(&v.status_config);
        }
        if let Some((_, name)) = ifnames.iter().find(|(section, _)| *section == v.section) {
            b.msg_string("ifname", name);
        }
        for (name, subs, kind) in [
            ("vlans", &v.vlans, "vlan"),
            ("stations", &v.stas, "station"),
        ] {
            let list = b.msg_open_array(name);
            for sub in subs {
                let item = b.msg_open_table("");
                b.msg_string("section", &sub.section);
                let config = b.msg_open_table("config");
                attrs_into_blob(b, &sub.opts, spec(kind), false);
                b.msg_close(config);
                let key = if kind == "vlan" {
                    format!("{}/{}", v.section, sub.section)
                } else {
                    sub.section.clone()
                };
                if let Some((_, name)) = ifnames.iter().find(|(section, _)| *section == key) {
                    b.msg_string("ifname", name);
                }
                b.msg_close(item);
            }
            b.msg_close(list);
        }
        b.msg_close(iface);
    }
    b.msg_close(interfaces);
    b.msg_close(radio);
}

fn config_into_blob(
    b: &mut owrt_ubus::blob::BlobBuf,
    opts: &[(String, Val)],
    spec: &[(String, u32)],
    radios: Option<&[i64]>,
) {
    let config = b.msg_open_table("config");
    attrs_into_blob(b, opts, spec, radios.is_some());
    if let Some(radios) = radios {
        let list = b.msg_open_array("radios");
        for n in radios {
            status_integer(b, "", *n);
        }
        b.msg_close(list);
    }
    b.msg_close(config);
}

pub fn cache_status_config(radio: &mut Radio, handlers: &[Handler]) {
    let handler = radio
        .kind()
        .and_then(|kind| handlers.iter().find(|h| h.name == kind));
    let spec = |kind| handler.map(|h| h.attrs_of(kind)).unwrap_or(&[]);
    let mut b = owrt_ubus::blob::BlobBuf::new();
    config_into_blob(&mut b, &radio.opts, spec("device"), None);
    radio.status_config = b.payload().to_vec();
    for vif in &mut radio.vifs {
        b.reset();
        config_into_blob(&mut b, &vif.opts, spec("iface"), Some(&vif.radios));
        vif.status_config = b.payload().to_vec();
    }
}

fn attrs_into_blob(
    b: &mut owrt_ubus::blob::BlobBuf,
    opts: &[(String, Val)],
    spec: &[(String, u32)],
    skip_radios: bool,
) {
    for (name, ty) in spec {
        if skip_radios && name == "radios" {
            continue;
        }
        let Some((_, value)) = opts.iter().find(|(key, _)| key == name) else {
            continue;
        };
        match (ty, value) {
            (_, Val::List(items)) => {
                let list = b.msg_open_array(name);
                for item in items {
                    b.msg_string("", item);
                }
                b.msg_close(list);
            }
            (&TYPE_ARRAY, Val::Str(value)) => {
                let list = b.msg_open_array(name);
                for item in value.split_whitespace() {
                    b.msg_string("", item);
                }
                b.msg_close(list);
            }
            (&TYPE_INT, Val::Str(value)) => {
                status_integer(b, name, value.trim().parse().unwrap_or(0));
            }
            (&TYPE_BOOL, Val::Str(value)) => {
                match parse_bool(value) {
                    Some(value) => b.msg_bool(name, value),
                    None => b.msg_null(name),
                };
            }
            (_, Val::Str(value)) => {
                b.msg_string(name, value);
            }
        }
    }
}

#[cfg(test)]
mod status_blob_tests {
    use super::*;
    use owrt_ubus::blob::BlobBuf;

    #[test]
    fn reloading_rebuilds_config_and_radio_associations() {
        let dir = std::env::temp_dir().join(format!("netifd-status-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let handlers = vec![Handler {
            name: "test".into(),
            attrs: vec![
                ("device".into(), vec![("channel".into(), TYPE_INT)]),
                ("iface".into(), vec![("ssid".into(), TYPE_STRING)]),
            ],
            ..Default::default()
        }];
        let mut previous = Vec::new();
        for (index, devices) in [(1, "radio0"), (2, "radio0 radio1")] {
            std::fs::write(dir.join("wireless"), format!(
                "config wifi-device 'radio0'\n option type 'test'\n option radio '{index}'\n option channel '{index}'\n\
                 config wifi-device 'radio1'\n option type 'test'\n option radio '7'\n\
                 config wifi-iface 'ap'\n option device '{devices}'\n option ssid 'value-{index}'\n"
            )).unwrap();
            let radios = load(&dir.to_string_lossy(), &handlers);
            assert_eq!(radios.len(), 2);
            assert!(radios.iter().all(|radio| !radio.status_config.is_empty()));
            let unencoded = load_config(&dir.to_string_lossy(), &handlers);
            assert!(unencoded.iter().all(|radio| radio.status_config.is_empty()
                && radio.vifs.iter().all(|vif| vif.status_config.is_empty())));
            assert!(radios
                .iter()
                .zip(&unencoded)
                .all(|(old, fresh)| same_config(old, fresh)));
            let mut uncached_reply = BlobBuf::new();
            for radio in &unencoded {
                status_into_blob(
                    &mut uncached_reply,
                    radio,
                    &handlers,
                    RadioState::default(),
                    &[],
                );
            }
            assert_eq!(radios[0].vifs[0].radios[0], index);
            let mut actual = BlobBuf::new();
            for radio in &radios {
                status_into_blob(&mut actual, radio, &handlers, RadioState::default(), &[]);
            }
            let mut expected = BlobBuf::new();
            json_text_into_blob(
                &mut expected,
                &status_json(&radios, &handlers, RadioState::default(), &[]),
            );
            assert_eq!(actual.payload(), expected.payload());
            assert_eq!(actual.payload(), uncached_reply.payload());
            assert_ne!(actual.payload(), previous);
            previous = actual.payload().to_vec();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn direct_status_matches_json_wire_bytes() {
        let attrs: Vec<_> = [
            ("text", TYPE_STRING),
            ("list", TYPE_ARRAY),
            ("number", TYPE_INT),
            ("flag", TYPE_BOOL),
            ("unknown", 99),
            ("radios", TYPE_STRING),
        ]
        .into_iter()
        .map(|(n, t)| (n.into(), t))
        .collect();
        let handler = Handler {
            name: "test".into(),
            attrs: ["device", "iface", "vlan", "station"]
                .into_iter()
                .map(|kind| (kind.into(), attrs.clone()))
                .collect(),
            ..Default::default()
        };
        for flag in ["0", "1", "true", "false", "on", "", "TRUE"] {
            for list in [
                Val::Str(" alpha\tbeta\nγ ".into()),
                Val::List(vec!["a b".into(), "".into()]),
            ] {
                for number in [
                    "-1",
                    " 42 ",
                    "9223372036854775807",
                    "9223372036854775808",
                    "bad",
                ] {
                    let opts = vec![
                        (
                            "text".into(),
                            Val::Str("quote\" slash\\ newline\n tab\t cr\r 中文".into()),
                        ),
                        ("list".into(), list.clone()),
                        ("number".into(), Val::Str(number.into())),
                        ("flag".into(), Val::Str(flag.into())),
                        ("unknown".into(), Val::List(vec!["kept".into()])),
                        ("radios".into(), Val::Str("replaced".into())),
                    ];
                    let sub = Sub {
                        section: "sub".into(),
                        opts: opts.clone(),
                    };
                    let mut radio = Radio {
                        name: "radio0".into(),
                        opts: opts.clone(),
                        vifs: vec![Vif {
                            section: "vif".into(),
                            opts,
                            radios: vec![0, 7],
                            vlans: vec![sub.clone()],
                            stas: vec![sub],
                            ..Default::default()
                        }],
                        ..Default::default()
                    };
                    radio.opts.push(("type".into(), Val::Str("test".into())));
                    radio.opts.push(("disabled".into(), Val::Str(flag.into())));
                    cache_status_config(&mut radio, std::slice::from_ref(&handler));
                    for bits in 0..16 {
                        let state = RadioState {
                            up: bits & 1 != 0,
                            pending: bits & 2 != 0,
                            autostart: bits & 4 != 0,
                            retry_setup_failed: bits & 8 != 0,
                        };
                        for ifnames in [
                            vec![],
                            vec![
                                ("vif".into(), "phy0-ap0".into()),
                                ("vif/sub".into(), "phy0-ap0.10".into()),
                                ("sub".into(), "station0".into()),
                            ],
                        ] {
                            let mut expected = BlobBuf::new();
                            json_text_into_blob(
                                &mut expected,
                                &status_json(
                                    std::slice::from_ref(&radio),
                                    std::slice::from_ref(&handler),
                                    state,
                                    &ifnames,
                                ),
                            );
                            let mut actual = BlobBuf::new();
                            status_into_blob(
                                &mut actual,
                                &radio,
                                std::slice::from_ref(&handler),
                                state,
                                &ifnames,
                            );
                            assert_eq!(
                                actual.payload(),
                                expected.payload(),
                                "flag={flag} number={number} bits={bits}"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// `get_validate`, as compact JSON: the whole schema, keyed by radio.
pub fn get_validate_json(radios: &[Radio], handlers: &[Handler]) -> String {
    let mut out: Vec<(String, String)> = Vec::new();
    for r in radios {
        let Some(h) = r.kind().and_then(|k| handlers.iter().find(|h| h.name == k)) else {
            continue;
        };
        let body: Vec<(String, String)> = h
            .validate_info()
            .into_iter()
            .map(|(kind, attrs)| {
                let fields: Vec<(String, String)> = attrs
                    .into_iter()
                    .map(|(n, e)| (n, format!("\"{}\"", esc(&e))))
                    .collect();
                (kind.to_string(), obj(&fields))
            })
            .collect();
        out.push((r.name.clone(), obj(&body)));
    }
    obj(&out)
}

/// The diagnostic entry point behind `--dump-wireless`: both read methods for
/// a given config and handler directory, so a differential can compare them
/// with the C's replies without this build having to register the object.
pub fn dump(confdir: &str, handlerdir: &str) -> String {
    let handlers = discover(Path::new(handlerdir));
    let radios = load(confdir, &handlers);
    format!(
        "{{\"status\":{},\"get_validate\":{}}}",
        status_json(&radios, &handlers, RadioState::default(), &[]),
        get_validate_json(&radios, &handlers)
    )
}

// ---------------------------------------------------------------------------
// Driving the handler script
// ---------------------------------------------------------------------------

/// `wireless.uc`'s notify commands.
pub const NOTIFY_UP: i64 = 0;
pub const NOTIFY_SET_DATA: i64 = 1;
pub const NOTIFY_PROCESS_ADD: i64 = 2;
pub const NOTIFY_SET_RETRY: i64 = 4;

/// `DEFAULT_RETRY`. A radio gets this many retries after its first setup, so
/// four setup attempts in all before `retry_setup_failed` sticks.
pub const DEFAULT_RETRY: u32 = 3;

/// `wdev.state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WState {
    Down,
    Setup,
    Teardown,
    Up,
}

/// `is_equal(this.data, data)`: whether a radio's configuration is unchanged,
/// including the interfaces, vlans and stations hanging off it. Anything this
/// says is equal must be left completely alone by a reload.
pub fn same_config(a: &Radio, b: &Radio) -> bool {
    let subs = |x: &[Sub]| -> Vec<(String, Vec<(String, Val)>)> {
        x.iter()
            .map(|s| (s.section.clone(), s.opts.clone()))
            .collect()
    };
    a.name == b.name
        && a.opts == b.opts
        && a.vifs.len() == b.vifs.len()
        && a.vifs.iter().zip(b.vifs.iter()).all(|(x, y)| {
            x.section == y.section
                && x.opts == y.opts
                && x.radios == y.radios
                && subs(&x.vlans) == subs(&y.vlans)
                && subs(&x.stas) == subs(&y.stas)
        })
}

/// The JSON handed to the handler as its fourth argument. Same projections as
/// `status`, arranged the way `wdev_config_init` arranges them: interfaces
/// keyed by a two-digit index from 1, and `vlans`/`stas` as objects rather
/// than the arrays `status` reports.
pub fn handler_json(radio: &Radio, handlers: &[Handler], device_data: &str) -> String {
    let h = radio
        .kind()
        .and_then(|k| handlers.iter().find(|h| h.name == k));
    let dev_spec = h.map(|h| h.attrs_of("device")).unwrap_or(&[]);
    let if_spec = h.map(|h| h.attrs_of("iface")).unwrap_or(&[]);

    let vlan_spec = h.map(|h| h.attrs_of("vlan")).unwrap_or(&[]);
    let sta_spec = h.map(|h| h.attrs_of("station")).unwrap_or(&[]);
    let mut ifaces: Vec<(String, String)> = Vec::new();
    for (n, v) in radio.vifs.iter().enumerate() {
        // wdev_config_init numbers children independently within each vif.
        let mut vlan_idx = 0usize;
        let mut sta_idx = 0usize;
        let mut cfg: Vec<(String, String)> = attribute_list(&v.opts, if_spec)
            .into_iter()
            .filter_map(|(k, p)| projected(&p).map(|p| (k, p)))
            .collect();
        let list: Vec<String> = v.radios.iter().map(|x| x.to_string()).collect();
        cfg.retain(|(k, _)| k != "radios");
        cfg.push(("radios".into(), format!("[{}]", list.join(","))));
        let mut vlans: Vec<(String, String)> = Vec::new();
        for sub in &v.vlans {
            vlan_idx += 1;
            vlans.push((
                format!("{vlan_idx:02}"),
                obj(&[
                    ("name".into(), format!("\"{}\"", esc(&sub.section))),
                    ("config".into(), attr_obj(&sub.opts, vlan_spec)),
                ]),
            ));
        }
        let mut stas: Vec<(String, String)> = Vec::new();
        for sub in &v.stas {
            sta_idx += 1;
            stas.push((
                format!("{sta_idx:02}"),
                obj(&[
                    ("name".into(), format!("\"{}\"", esc(&sub.section))),
                    ("config".into(), attr_obj(&sub.opts, sta_spec)),
                ]),
            ));
        }
        ifaces.push((
            format!("{:02}", n + 1),
            obj(&[
                ("name".into(), format!("\"{}\"", esc(&v.section))),
                ("config".into(), obj(&cfg)),
                ("vlans".into(), obj(&vlans)),
                ("stas".into(), obj(&stas)),
            ]),
        ));
    }

    obj(&[
        ("config".into(), attr_obj(&radio.opts, dev_spec)),
        ("interfaces".into(), obj(&ifaces)),
        // `__run_next_handler`: `wdev.handler_config.data =
        // wdev.handler_data[wdev.name] ?? {}`. The device-level record the
        // handler set through notify comes back to it on the next setup AND on
        // teardown, which is how a handler keeps a token across a reconf.
        ("data".into(), device_data.to_string()),
    ])
}

/// The device-level `handler_data` record, in `wdev_set_data`'s shape:
/// `{...cur, ...data, type, config}` where `cur` is `{name: wdev.name}` for a
/// device-level notify, so `config` comes out null.
pub fn device_data_record(radio: &str, fields: &[(String, String)]) -> String {
    let mut out: Vec<(String, String)> = vec![("name".into(), format!("\"{}\"", esc(radio)))];
    for (k, v) in fields {
        if k == "name" {
            continue;
        }
        out.push((k.clone(), v.clone()));
    }
    out.push(("type".into(), "\"device\"".into()));
    out.push(("config".into(), "null".into()));
    obj(&out)
}

#[cfg(test)]
mod handler_tests {
    use super::*;

    fn setup_case() -> (Vec<Handler>, Vec<Radio>) {
        let hs = vec![handler_from(
            Path::new("/x.sh"),
            &json::parse(
                r#"{"name":"mac80211","device":[["channel",3],["band",3],["path",3]],
                    "iface":[["ssid",3],["encryption",3]]}"#,
            )
            .unwrap(),
        )
        .unwrap()];
        let dir = std::env::temp_dir().join(format!("netifd-hj-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("wireless"),
            "config wifi-device 'radio0'\n\toption type 'mac80211'\n\
             \toption path 'platform/soc/18000000.wifi'\n\toption band '2g'\n\
             \toption channel '1'\n\n\
             config wifi-iface 'default_radio0'\n\toption device 'radio0'\n\
             \toption network 'lan'\n\toption mode 'ap'\n\toption ssid 'probe'\n\
             \toption encryption 'none'\n",
        )
        .unwrap();
        let radios = load(&dir.to_string_lossy(), &hs);
        (hs, radios)
    }

    // Byte for byte what the C hands the handler, measured with a recording
    // stub in place of mac80211.sh. The whitespace differs (the C pretty-prints
    // with spaces); everything else -- key order, the two-digit interface key,
    // `vlans`/`stas` as objects, `device` as a bare string here where `status`
    // reports an array -- is asserted.
    #[test]
    fn the_handler_json_matches_what_the_c_sends() {
        let (hs, radios) = setup_case();
        let got = handler_json(&radios[0], &hs, "{}");
        let want = concat!(
            r#"{"config":{"type":"mac80211","channel":"1","band":"2g","#,
            r#""path":"platform/soc/18000000.wifi"},"#,
            r#""interfaces":{"01":{"name":"default_radio0","config":{"network":["lan"],"#,
            r#""device":"radio0","mode":"ap","ssid":"probe","encryption":"none","#,
            r#""radios":[]},"vlans":{},"stas":{}}},"data":{}}"#
        );
        assert_eq!(got, want);
    }

    #[test]
    fn the_retry_budget_is_three_so_four_setups() {
        assert_eq!(DEFAULT_RETRY, 3);
    }
}

/// Write a parsed JSON value into a blobmsg buffer under `name`. The status
/// and get_validate projections are built and tested as JSON text against the
/// C's replies, so this converts that verified text rather than duplicating
/// the ordering logic in blobmsg calls.
/// ucode's ubus integer encoder uses INT32 for the signed 32-bit range.
/// The numeric JSON value alone does not describe this wire contract.
fn status_integer(b: &mut owrt_ubus::blob::BlobBuf, name: &str, value: i64) {
    if let Ok(value) = i32::try_from(value) {
        b.msg_u32(name, value as u32);
    } else {
        b.msg_i64(name, value);
    }
}

pub fn json_into_blob(b: &mut owrt_ubus::blob::BlobBuf, name: &str, v: &Json) {
    match v {
        Json::Null => {
            b.msg_null(name);
        }
        Json::Bool(x) => {
            b.msg_bool(name, *x);
        }
        Json::Int(n) => {
            status_integer(b, name, *n);
        }
        Json::Float(f) => {
            b.msg_double(name, *f);
        }
        Json::Str(s) => {
            b.msg_string(name, s);
        }
        Json::Bytes(s) => {
            b.msg_string_bytes(name, s);
        }
        Json::Array(items) => {
            let c = b.msg_open_array(name);
            for it in items {
                json_into_blob(b, "", it);
            }
            b.msg_close(c);
        }
        Json::Object(items) => {
            let c = b.msg_open_table(name);
            for (k, it) in items {
                json_into_blob(b, k, it);
            }
            b.msg_close(c);
        }
    }
}

/// Parse one of this module's JSON emitters and write its fields at the top
/// level of `b`.
pub fn json_text_into_blob(b: &mut owrt_ubus::blob::BlobBuf, text: &str) {
    let Ok(Json::Object(items)) = json::parse(text) else {
        return;
    };
    for (k, v) in &items {
        json_into_blob(b, k, v);
    }
}

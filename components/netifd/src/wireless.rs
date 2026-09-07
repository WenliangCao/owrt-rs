//! `network.wireless`.
//!
//! netifd hosts a ucode VM that loads `/lib/netifd/wireless.uc`, which
//! publishes this object. The parts that do not need the VM are here: the
//! handler discovery (the same "run the script with `dump` and parse each
//! line" pattern the protocol handlers use), the validation schema built from
//! it, and the status projection of `/etc/config/wireless`.
//!
//! Bringing radios up is the handler script's job and needs real hardware, so
//! it is not reproduced -- see R45.

use std::io;
use std::path::{Path, PathBuf};

use owrt_ubus::json::Json;

/// `utils.uc`'s attribute type codes.
pub const TYPE_ARRAY: u32 = 1;
pub const TYPE_STRING: u32 = 3;
pub const TYPE_INT: u32 = 5;
pub const TYPE_BOOL: u32 = 7;

/// `attr_validate`: the name a type code is reported under, unless the
/// handler gave an explicit validation expression for that attribute.
pub fn type_name(t: u32) -> Option<&'static str> {
    Some(match t {
        TYPE_STRING => "string",
        TYPE_ARRAY => "list(string)",
        TYPE_INT => "uinteger",
        TYPE_BOOL => "bool",
        _ => return None,
    })
}

/// `network_config_attr`, shared by `iface` and `vlan`.
const NETWORK_CONFIG_ATTR: &[(&str, u32)] = &[
    ("network", TYPE_ARRAY),
    ("network_vlan", TYPE_ARRAY),
    ("bridge_isolate", TYPE_BOOL),
    ("isolate", TYPE_BOOL),
    ("proxy_arp", TYPE_BOOL),
    ("multicast_to_unicast", TYPE_BOOL),
];

/// `default_config_attr`: what every handler has, whatever it declares.
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

/// The four attribute kinds, in `default_config_attr` order. `iface` is
/// reported as `interface`.
pub const KINDS: &[(&str, &str)] =
    &[("device", "device"), ("iface", "interface"), ("station", "station"), ("vlan", "vlan")];

/// One wireless device handler, as its `dump` describes it.
#[derive(Clone, Debug, Default)]
pub struct Handler {
    pub name: String,
    pub script: PathBuf,
    /// kind -> [(attribute, type code)], already merged over the defaults.
    pub attrs: Vec<(String, Vec<(String, u32)>)>,
    /// kind -> [(attribute, validation expression)] the handler gave.
    pub validate: Vec<(String, Vec<(String, String)>)>,
}

impl Handler {
    pub fn attrs_for(&self, kind: &str) -> &[(String, u32)] {
        self.attrs
            .iter()
            .find(|(k, _)| k == kind)
            .map(|(_, v)| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn validate_for(&self, kind: &str, attr: &str) -> Option<&str> {
        self.validate
            .iter()
            .find(|(k, _)| k == kind)?
            .1
            .iter()
            .find(|(a, _)| a == attr)
            .map(|(_, v)| v.as_str())
    }
}

/// `handler_load`: run every script in the directory as `./<script> "" dump`
/// with that directory as the working directory, and parse each line of its
/// output as a JSON object.
pub fn discover(dir: &Path) -> Vec<Handler> {
    let mut out: Vec<Handler> = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    let mut scripts: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "sh"))
        .collect();
    scripts.sort();
    for script in scripts {
        let Ok(text) = run_dump(dir, &script) else { continue };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(j) = owrt_ubus::json::parse(line) else { continue };
            let Some(h) = handler_from(&script, &j) else { continue };
            out.push(h);
        }
    }
    out
}

fn run_dump(dir: &Path, script: &Path) -> io::Result<String> {
    let name = script.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    let o = std::process::Command::new(format!("./{name}"))
        .arg("")
        .arg("dump")
        .current_dir(dir)
        .output()?;
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

fn handler_from(script: &Path, j: &Json) -> Option<Handler> {
    let name = j.get("name")?.as_str()?.to_string();
    let mut h = Handler { name, script: script.to_path_buf(), ..Default::default() };
    for (kind, _) in KINDS {
        // the handler's own attributes, then whatever it did not declare
        let mut attrs: Vec<(String, u32)> = Vec::new();
        let mut validate: Vec<(String, String)> = Vec::new();
        if let Some(list) = j.get(kind).and_then(|l| l.as_array()) {
            for entry in list {
                let Some(pair) = entry.as_array() else { continue };
                let Some(attr) = pair.first().and_then(|a| a.as_str()).map(|s| s.to_string())
                else {
                    continue;
                };
                // `[name, code]`, and `[name, code, "validation"]` when the
                // handler gave an explicit expression
                let code = match pair.get(1) {
                    Some(Json::Int(n)) => *n as u32,
                    _ => continue,
                };
                if let Some(Json::Str(v)) = pair.get(2) {
                    validate.push((attr.clone(), v.clone()));
                }
                attrs.push((attr, code));
            }
        }
        for (n, t) in default_attrs(kind) {
            if !attrs.iter().any(|(a, _)| *a == n) {
                attrs.push((n, t));
            }
        }
        // an avl tree keyed by name, so the schema prints sorted
        attrs.sort_by(|a, b| a.0.cmp(&b.0));
        h.attrs.push((kind.to_string(), attrs));
        h.validate.push((kind.to_string(), validate));
    }
    Some(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_type_code_maps_to_the_name_the_schema_prints() {
        assert_eq!(type_name(TYPE_STRING), Some("string"));
        assert_eq!(type_name(TYPE_ARRAY), Some("list(string)"));
        assert_eq!(type_name(TYPE_INT), Some("uinteger"));
        assert_eq!(type_name(TYPE_BOOL), Some("bool"));
        assert_eq!(type_name(2), None);
    }

    #[test]
    fn the_defaults_are_merged_under_what_the_handler_declares() {
        let j = owrt_ubus::json::parse(
            r#"{"name":"mac80211","device":[["band",3],["disabled",5]]}"#,
        )
        .unwrap();
        let h = handler_from(Path::new("/x/mac80211.sh"), &j).unwrap();
        let dev = h.attrs_for("device");
        // declared wins over the default: `disabled` is a bool by default
        assert_eq!(dev.iter().find(|(a, _)| a == "disabled").unwrap().1, 5);
        // and the default that was not declared is still there
        assert_eq!(dev.iter().find(|(a, _)| a == "type").unwrap().1, TYPE_STRING);
        // sorted by name
        let names: Vec<&str> = dev.iter().map(|(a, _)| a.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn every_kind_is_present_even_when_the_handler_declares_none() {
        let j = owrt_ubus::json::parse(r#"{"name":"mac80211"}"#).unwrap();
        let h = handler_from(Path::new("/x/mac80211.sh"), &j).unwrap();
        for (kind, _) in KINDS {
            assert!(!h.attrs_for(kind).is_empty(), "{kind} is empty");
        }
    }
}

//! UCI section access in the shape ucode's `uci.cursor()` yields: one JSON
//! object per section carrying `.anonymous`, `.type`, `.name`, `.index` and
//! the option values (string or array of strings). Real configs are loaded
//! through `owrt_uci` (libuci semantics: confdir, `/var/run/uci` override,
//! `/tmp/.uci` deltas, `cfgXXXXXX` anonymous names); the upstream test-suite
//! JSON fixtures keep their own loader.

use owrt_ubus::json::Json;
use owrt_uci::{Context, OptionValue, Package};

pub struct Config {
    pub sections: Vec<Json>,
}

fn set_key(obj: &mut Vec<(String, Json)>, key: &str, value: Json) {
    if let Some(slot) = obj.iter_mut().find(|(k, _)| k == key) {
        slot.1 = value;
    } else {
        obj.push((key.to_owned(), value));
    }
}

impl Config {
    pub fn empty() -> Config {
        Config {
            sections: Vec::new(),
        }
    }

    /// Sections of one type in file order (ucode `cursor.foreach`).
    pub fn of_type<'a>(&'a self, ty: &'a str) -> impl Iterator<Item = &'a Json> + 'a {
        self.sections
            .iter()
            .filter(move |s| s.get(".type").and_then(Json::as_str) == Some(ty))
    }

    pub fn by_name(&self, name: &str) -> Option<&Json> {
        self.sections
            .iter()
            .find(|s| s.get(".name").and_then(Json::as_str) == Some(name))
    }

    /// uc_uci_to_section() over every section of a loaded package.  The
    /// package is consumed: section and option names move into the JSON
    /// objects instead of being copied.
    pub fn from_package(p: Package) -> Config {
        let sections = p
            .sections
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                let mut o: Vec<(String, Json)> = Vec::with_capacity(4 + s.options.len());
                o.push((".anonymous".into(), Json::Bool(s.anonymous)));
                o.push((".type".into(), Json::Str(s.ty)));
                o.push((".name".into(), Json::Str(s.name)));
                o.push((".index".into(), Json::Int(i as i64)));
                for opt in s.options {
                    let v = match &opt.value {
                        // libuci values are raw bytes; the ruleset is text (DEVIATION: non-UTF-8 -> U+FFFD)
                        OptionValue::Str(v) => Json::Str(String::from_utf8_lossy(v).into_owned()),
                        OptionValue::List(items) => Json::Array(
                            items
                                .iter()
                                .map(|v| Json::Str(String::from_utf8_lossy(v).into_owned()))
                                .collect(),
                        ),
                    };
                    o.push((opt.name, v));
                }
                Json::Object(o)
            })
            .collect();
        Config { sections }
    }

    /// `cursor.load(name)`: uci_load with `confdir`; `name` may be a path.
    /// A failed load leaves the cursor without the package, so `foreach`
    /// yields nothing: the empty config.
    pub fn load(confdir: &str, name: &str) -> Config {
        let mut ctx = Context::new();
        ctx.set_confdir(confdir);
        match owrt_uci::file::load(&mut ctx, name) {
            Ok(idx) => Config::from_package(ctx.root.swap_remove(idx)),
            Err(_) => Config::empty(),
        }
    }

    /// Parse UCI config text with libuci's parser (fixture files).
    pub fn parse_text(name: &str, text: &str) -> Config {
        let mut ctx = Context::new();
        let mut reader = std::io::Cursor::new(text.as_bytes());
        match owrt_uci::parse::import(&mut ctx, &mut reader, Some(name), None, true) {
            Ok(Some(idx)) => Config::from_package(ctx.root.swap_remove(idx)),
            _ => Config::empty(),
        }
    }

    /// Load the upstream mock format: `{ "<type>": [ {section}, ... ] }`.
    pub fn from_mock(v: &Json) -> Config {
        let mut sections: Vec<Vec<(String, Json)>> = Vec::new();
        let mut used: Vec<String> = Vec::new();
        let Json::Object(groups) = v else {
            return Config::empty();
        };
        for (stype, group) in groups {
            let items: Vec<&Json> = match group {
                Json::Object(_) => vec![group],
                Json::Array(a) => a.iter().collect(),
                _ => continue,
            };
            for (idx, sobj) in items.into_iter().enumerate() {
                let Json::Object(fields) = sobj else { continue };
                let named = sobj
                    .get(".name")
                    .and_then(Json::as_str)
                    .filter(|n| !used.contains(&n.to_string()))
                    .map(str::to_owned);
                let (sid, anonymous) = match named {
                    Some(n) => (n, false),
                    None => (
                        format!("cfg{}{:04x}", stype.len() % 10, sections.len() * 31 + idx),
                        true,
                    ),
                };
                used.push(sid.clone());
                let mut sec: Vec<(String, Json)> =
                    vec![(".index".into(), Json::Int(sections.len() as i64))];
                for (k, val) in fields {
                    set_key(&mut sec, k, val.clone());
                }
                set_key(&mut sec, ".name", Json::Str(sid));
                set_key(&mut sec, ".type", Json::Str(stype.clone()));
                set_key(&mut sec, ".anonymous", Json::Bool(anonymous));
                sections.push(sec);
            }
        }
        Config {
            sections: sections.into_iter().map(Json::Object).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text() {
        let c = Config::parse_text(
            "firewall",
            "\nconfig defaults\n\toption input 'REJECT'\n\n# c\nconfig zone 'lan'\n\toption name 'lan'\n\tlist network 'lan'\n\tlist network 'guest'\n\toption x \"a\\\"b c\"\n",
        );
        assert_eq!(c.sections.len(), 2);
        let z = c.by_name("lan").unwrap();
        assert_eq!(z.get(".type").and_then(Json::as_str), Some("zone"));
        assert_eq!(
            z.get("network").and_then(Json::as_array).map(|a| a.len()),
            Some(2)
        );
        assert_eq!(z.get("x").and_then(Json::as_str), Some("a\"b c"));
        let d = &c.sections[0];
        assert_eq!(d.get(".anonymous"), Some(&Json::Bool(true)));
        // libuci's cfg%02x%04x name for the first anonymous section
        assert_eq!(d.get(".name").and_then(Json::as_str), Some("cfg01e63d"));
        assert_eq!(d.get(".index"), Some(&Json::Int(0)));
        assert_eq!(c.of_type("zone").count(), 1);
        // strict parser: a malformed line makes the whole load fail
        assert!(Config::parse_text("x", "config zone\n\toption\n")
            .sections
            .is_empty());
    }

    #[test]
    fn mock() {
        let j = owrt_ubus::json::parse(
            r#"{"zone":[{"name":"a"},{".name":"z2","name":"b"}],"defaults":{"input":"ACCEPT"}}"#,
        )
        .unwrap();
        let c = Config::from_mock(&j);
        assert_eq!(c.sections.len(), 3);
        assert_eq!(
            c.sections[1].get(".name").and_then(Json::as_str),
            Some("z2")
        );
        assert_eq!(c.sections[1].get(".anonymous"), Some(&Json::Bool(false)));
        assert_eq!(
            c.sections[2].get(".type").and_then(Json::as_str),
            Some("defaults")
        );
        assert_eq!(c.sections[2].get(".index"), Some(&Json::Int(2)));
    }
}

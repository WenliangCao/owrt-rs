//! UCI section access: parses `/etc/config/*` text files and the upstream
//! test-suite JSON fixtures into the same shape ucode's `uci.cursor()` yields:
//! one JSON object per section carrying `.type`, `.name`, `.anonymous`,
//! `.index` and the option values (string or array of strings).

use owrt_ubus::json::Json;

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
        Config { sections: Vec::new() }
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

    /// Parse UCI config file text.
    pub fn parse_text(text: &str) -> Config {
        let mut sections: Vec<Vec<(String, Json)>> = Vec::new();
        let mut anon = 0usize;
        for line in text.lines() {
            let toks = tokenize(line);
            if toks.is_empty() {
                continue;
            }
            match toks[0].as_str() {
                "config" | "c" if toks.len() >= 2 => {
                    let ty = toks[1].clone();
                    let (name, anonymous) = match toks.get(2) {
                        Some(n) if !n.is_empty() => (n.clone(), false),
                        _ => {
                            anon += 1;
                            (format!("cfg{:06x}", anon), true)
                        }
                    };
                    sections.push(vec![
                        (".index".into(), Json::Int(sections.len() as i64)),
                        (".type".into(), Json::Str(ty)),
                        (".name".into(), Json::Str(name)),
                        (".anonymous".into(), Json::Bool(anonymous)),
                    ]);
                }
                "option" | "o" if toks.len() >= 2 => {
                    if let Some(sec) = sections.last_mut() {
                        let v = toks.get(2).cloned().unwrap_or_default();
                        set_key(sec, &toks[1], Json::Str(v));
                    }
                }
                "list" | "l" if toks.len() >= 2 => {
                    if let Some(sec) = sections.last_mut() {
                        let v = Json::Str(toks.get(2).cloned().unwrap_or_default());
                        match sec.iter_mut().find(|(k, _)| k == &toks[1]) {
                            Some((_, Json::Array(items))) => items.push(v),
                            Some(slot) => {
                                let old = std::mem::replace(&mut slot.1, Json::Null);
                                slot.1 = Json::Array(vec![old, v]);
                            }
                            None => sec.push((toks[1].clone(), Json::Array(vec![v]))),
                        }
                    }
                }
                _ => {}
            }
        }
        Config {
            sections: sections.into_iter().map(Json::Object).collect(),
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
                    None => (format!("cfg{}{:04x}", stype.len() % 10, sections.len() * 31 + idx), true),
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

/// Split one UCI line into tokens honouring single/double quotes and
/// backslash escapes; `#` at token start begins a comment.
fn tokenize(line: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
            chars.next();
        }
        match chars.peek() {
            None | Some('#') => break,
            _ => {}
        }
        let mut tok = String::new();
        let mut quote: Option<char> = None;
        while let Some(c) = chars.next() {
            match quote {
                Some(q) if c == q => quote = None,
                Some('"') if c == '\\' => {
                    if let Some(n) = chars.next() {
                        tok.push(n);
                    }
                }
                Some(_) => tok.push(c),
                None => match c {
                    '\'' | '"' => quote = Some(c),
                    '\\' => {
                        if let Some(n) = chars.next() {
                            tok.push(n);
                        }
                    }
                    c if c.is_whitespace() => break,
                    _ => tok.push(c),
                },
            }
        }
        toks.push(tok);
    }
    toks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text() {
        let c = Config::parse_text(
            "\nconfig defaults\n\toption input 'REJECT'\n\n# c\nconfig zone 'lan'\n\toption name 'lan'\n\tlist network 'lan'\n\tlist network 'guest'\n\toption x \"a\\\"b c\"\n",
        );
        assert_eq!(c.sections.len(), 2);
        let z = c.by_name("lan").unwrap();
        assert_eq!(z.get(".type").and_then(Json::as_str), Some("zone"));
        assert_eq!(z.get("network").and_then(Json::as_array).map(|a| a.len()), Some(2));
        assert_eq!(z.get("x").and_then(Json::as_str), Some("a\"b c"));
        let d = &c.sections[0];
        assert_eq!(d.get(".anonymous"), Some(&Json::Bool(true)));
        assert_eq!(c.of_type("zone").count(), 1);
    }

    #[test]
    fn mock() {
        let j = owrt_ubus::json::parse(
            r#"{"zone":[{"name":"a"},{".name":"z2","name":"b"}],"defaults":{"input":"ACCEPT"}}"#,
        )
        .unwrap();
        let c = Config::from_mock(&j);
        assert_eq!(c.sections.len(), 3);
        assert_eq!(c.sections[1].get(".name").and_then(Json::as_str), Some("z2"));
        assert_eq!(c.sections[1].get(".anonymous"), Some(&Json::Bool(false)));
        assert_eq!(c.sections[2].get(".type").and_then(Json::as_str), Some("defaults"));
        assert_eq!(c.sections[2].get(".index"), Some(&Json::Int(2)));
    }
}

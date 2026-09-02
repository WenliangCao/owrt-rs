//! Minimal UCI config file reader (text syntax only) for `getConntrackHelpers`.

pub struct Section {
    pub ty: String,
    pub opts: Vec<(String, String)>,
}

impl Section {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.opts.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

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

pub fn parse(text: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    for line in text.lines() {
        let t = tokenize(line);
        match t.first().map(String::as_str) {
            Some("config") if t.len() >= 2 => sections.push(Section { ty: t[1].clone(), opts: Vec::new() }),
            Some("option") | Some("list") if t.len() >= 2 => {
                if let Some(s) = sections.last_mut() {
                    s.opts.push((t[1].clone(), t.get(2).cloned().unwrap_or_default()));
                }
            }
            _ => {}
        }
    }
    sections
}

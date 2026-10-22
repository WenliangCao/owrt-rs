//! uhttpd auth.c: httpd.conf realms, Basic authentication and passwd references.

use std::ffi::CString;

pub struct Realm {
    pub path: String,
    user: String,
    password: String,
}

impl std::fmt::Debug for Realm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Realm")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Realm {
    pub fn new(path: String, user: String, password: String) -> Option<Self> {
        let password = if let Some(account) = password.strip_prefix("$p$").filter(|s| !s.is_empty())
        {
            let resolved = account_password("/etc/shadow", account)
                .or_else(|| account_password("/etc/passwd", account));
            match resolved {
                Some(p) if p.is_empty() || p.starts_with('$') => p,
                _ => "$".into(), // locked/missing account: crypt can never match
            }
        } else {
            password
        };
        if password.is_empty() {
            return None;
        }
        Some(Self {
            path,
            user,
            password,
        })
    }
}

fn account_password(file: &str, account: &str) -> Option<String> {
    std::fs::read_to_string(file)
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            (fields.next()? == account)
                .then(|| fields.next().map(str::to_owned))
                .flatten()
        })
}

fn equal(a: &[u8], b: &[u8]) -> bool {
    let mut difference = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        difference |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    difference == 0
}

fn matches_password(password: &str, stored: &str) -> bool {
    if !stored.starts_with('$') && equal(password.as_bytes(), stored.as_bytes()) {
        return true;
    }
    let (Ok(password), Ok(salt)) = (CString::new(password), CString::new(stored)) else {
        return false;
    };
    owrt_platform::text::with_crypt(&password, &salt, |result| equal(result, stored.as_bytes()))
}

fn basic(header: &str) -> Option<(String, String)> {
    if !header.get(..6)?.eq_ignore_ascii_case("Basic ") {
        return None;
    }
    // uh_b64decode ignores characters outside the base64 alphabet.
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for b in header[6..].bytes() {
        let n = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        bits = (bits << 6) | u32::from(n);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    let text = String::from_utf8(out).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_owned(), pass.to_owned()))
}

/// None: no protected realm, Some(credentials): authenticated, Err: 401.
pub fn check(
    realms: &[Realm],
    path: &str,
    header: Option<&str>,
) -> Result<Option<(String, String)>, ()> {
    let credentials = header.and_then(basic);
    let mut protected = false;
    for realm in realms {
        if !path
            .as_bytes()
            .get(..realm.path.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(realm.path.as_bytes()))
        {
            continue;
        }
        protected = true;
        let Some((user, password)) = &credentials else {
            break;
        };
        if user != &realm.user {
            continue;
        }
        return if matches_password(password, &realm.password) {
            Ok(credentials)
        } else {
            Err(())
        };
    }
    if protected {
        Err(())
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_omits_credentials() {
        for password in ["plaintext-secret", "$1$salt$hash-secret"] {
            let realm =
                Realm::new("/private".into(), "username-secret".into(), password.into()).unwrap();
            for debug in [format!("{realm:?}"), format!("{realm:#?}")] {
                assert!(debug.contains("/private"));
                assert!(!debug.contains("username-secret"));
                assert!(!debug.contains(password));
            }
        }
    }

    #[test]
    fn configured_paths_require_credentials_and_do_not_accept_hashes_as_passwords() {
        let realm = Realm::new("/private".into(), "user".into(), "secret".into()).unwrap();
        let realms = [realm];
        assert!(check(&realms, "/private/file", None).is_err());
        assert!(check(&realms, "/PRIVATE/file", Some("Basic dXNlcjp3cm9uZw==")).is_err());
        assert_eq!(
            check(&realms, "/private", Some("Basic dXNlcjpzZWNyZXQ=")),
            Ok(Some(("user".into(), "secret".into())))
        );
        assert_eq!(check(&realms, "/public", None), Ok(None));
        assert!(!matches_password("$1$salt$hash", "$1$salt$hash"));
        assert!(!matches_password("anything", "$"));
    }
}

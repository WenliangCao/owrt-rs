//! `inittab.c`: /etc/inittab parsing and the seven action handlers.
//!
//! The C matches each line against the unanchored POSIX regex
//! `([a-zA-Z0-9]*):([a-zA-Z0-9]*):([a-zA-Z0-9]*):(.*)` -- leftmost match, so
//! leading garbage before a valid `id:runlvl:action:process` shape is
//! skipped, `#` comments and non-matching lines are dropped, and any of the
//! first three fields may be empty. The process field is split on spaces
//! into at most 7 arguments (MAX_ARGS 8 with the NULL).
//!
//! Handler behaviour worth stating because it is not what one would guess:
//!
//! - `askfirst`/`askconsole` prepend `/sbin/askfirst` to the argv.
//! - every respawning kind respawns after a fixed 500 ms -- but only while
//!   `/dev/<id>` can still be opened. An entry with an EMPTY id therefore
//!   runs once and never respawns (`dev_exist("")` is an ENOENT), which is
//!   the shipping behaviour for `::respawn:` lines.
//! - `askconsole` resolves the console from the kernel cmdline; finding a
//!   SECOND `console=` argument makes it fall back to /dev/console or
//!   /sys/class/tty/console/active rather than using the first.
//! - `sysinit`/`shutdown` do not fork a child of their own: they queue
//!   `<rc.d>/<pattern>*` on the width-1 serial runqueue.

use crate::sys;

pub const ASK: &str = "/sbin/askfirst";
/// `a->respawn = 500` in every respawning handler.
pub const RESPAWN_MS: i64 = 500;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Sysinit,
    Shutdown,
    Askfirst,
    Askconsole,
    Respawn,
    Askconsolelate,
    Respawnlate,
}

impl Kind {
    fn from_name(s: &str) -> Option<Kind> {
        match s {
            "sysinit" => Some(Kind::Sysinit),
            "shutdown" => Some(Kind::Shutdown),
            "askfirst" => Some(Kind::Askfirst),
            "askconsole" => Some(Kind::Askconsole),
            "respawn" => Some(Kind::Respawn),
            "askconsolelate" => Some(Kind::Askconsolelate),
            "respawnlate" => Some(Kind::Respawnlate),
            _ => None,
        }
    }

    /// `handler->multi`: sysinit and shutdown run only the FIRST matching
    /// entry; everything else runs all of them.
    pub fn multi(self) -> bool {
        !matches!(self, Kind::Sysinit | Kind::Shutdown)
    }
}

#[derive(Debug)]
pub struct Action {
    pub id: String,
    pub kind: Kind,
    pub argv: Vec<String>,
    pub pid: Option<i32>,
    /// `a->respawn`: -1 after `procd_inittab_kill`, else the delay.
    pub respawn_ms: i64,
    /// Monotonic deadline for the pending respawn, from `child_exit`.
    pub respawn_at: Option<i64>,
}

/// One line, matched the way the C's unanchored regex matches: from the
/// leftmost position where `alnum*:alnum*:alnum*:` fits.
fn parse_line(line: &str) -> Option<(String, String, Vec<String>)> {
    let line = line.trim_end();
    if line.starts_with('#') {
        return None;
    }
    let b = line.as_bytes();
    'start: for s in 0..=b.len() {
        let mut i = s;
        let mut fields: Vec<&str> = Vec::new();
        for _ in 0..3 {
            let f0 = i;
            while i < b.len() && b[i].is_ascii_alphanumeric() {
                i += 1;
            }
            if i >= b.len() || b[i] != b':' {
                continue 'start;
            }
            fields.push(&line[f0..i]);
            i += 1;
        }
        let process = &line[i..];
        let argv: Vec<String> = process
            .split(' ')
            .filter(|t| !t.is_empty())
            .take(7)
            .map(str::to_string)
            .collect();
        return Some((fields[0].to_string(), fields[2].to_string(), argv));
    }
    None
}

/// `procd_inittab()`: parse the file into actions. Unknown handlers are
/// logged and dropped, like `add_action`'s -1.
pub fn parse(path: &str) -> Vec<Action> {
    let Ok(text) = std::fs::read_to_string(path) else {
        log!(sys::LOG_ERR, "Failed to open {path}");
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((id, action, argv)) = parse_line(line) else {
            continue;
        };
        let Some(kind) = Kind::from_name(&action) else {
            log!(sys::LOG_ERR, "Unknown init handler {action}");
            continue;
        };
        out.push(Action {
            id,
            kind,
            argv,
            pid: None,
            respawn_ms: 0,
            respawn_at: None,
        });
    }
    out
}

/// `askfirst`'s argv shift: /sbin/askfirst in front, once.
pub fn prepend_ask(argv: &mut Vec<String>) {
    if argv.first().map(String::as_str) != Some(ASK) {
        argv.insert(0, ASK.to_string());
        argv.truncate(8);
    }
}

/// `askconsole`'s console resolution. `Some(tty)` names the console (already
/// split at the comma); `None` means no console was found anywhere.
pub fn resolve_console() -> Option<String> {
    let first = sys::cmdline_val("console", 0);
    let tty = match first {
        // A second console= on the cmdline makes the C IGNORE the first and
        // fall back, because of the get_cmdline_val_offset(.., 1) test.
        Some(_) if sys::cmdline_val("console", 1).is_some() => None,
        Some(t) => Some(t),
        None => None,
    };
    let tty = tty.or_else(|| {
        if sys::dev_exist("console") {
            Some("console".to_string())
        } else {
            sys::active_console()
        }
    })?;
    Some(tty.split(',').next().unwrap_or("").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_device_inittab_shape_parses() {
        assert_eq!(
            parse_line("::sysinit:/etc/init.d/rcS S boot"),
            Some((
                String::new(),
                "sysinit".into(),
                vec!["/etc/init.d/rcS".into(), "S".into(), "boot".into()]
            ))
        );
        assert_eq!(
            parse_line("tty1::askfirst:/usr/libexec/login.sh"),
            Some((
                "tty1".into(),
                "askfirst".into(),
                vec!["/usr/libexec/login.sh".into()]
            ))
        );
    }

    #[test]
    fn comments_and_non_matching_lines_are_dropped() {
        assert_eq!(parse_line("# ::sysinit:/bin/true"), None);
        assert_eq!(parse_line("no colons here"), None);
        assert_eq!(parse_line(""), None);
    }

    #[test]
    fn the_match_is_leftmost_not_anchored() {
        // "x!" cannot start a match; the first valid shape starts at "y".
        let (id, action, argv) = parse_line("x!y::respawn:/bin/foo").expect("matches at y");
        assert_eq!((id.as_str(), action.as_str()), ("y", "respawn"));
        assert_eq!(argv, vec!["/bin/foo".to_string()]);
    }

    #[test]
    fn the_process_field_is_capped_at_seven_arguments() {
        let (_, _, argv) = parse_line("::respawn:a b c d e f g h i").unwrap();
        assert_eq!(argv.len(), 7);
        assert_eq!(argv.last().map(String::as_str), Some("g"));
    }

    #[test]
    fn prepend_ask_is_idempotent() {
        let mut v = vec!["/usr/libexec/login.sh".to_string()];
        prepend_ask(&mut v);
        prepend_ask(&mut v);
        assert_eq!(
            v,
            vec![ASK.to_string(), "/usr/libexec/login.sh".to_string()]
        );
    }

    #[test]
    fn unknown_handlers_are_dropped_by_parse() {
        let dir = std::env::temp_dir().join(format!("inittab-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("inittab");
        std::fs::write(
            &p,
            "::sysinit:/bin/true\n::bogus:/bin/false\ntty1::respawn:/bin/sh\n",
        )
        .unwrap();
        let acts = parse(p.to_str().unwrap());
        assert_eq!(acts.len(), 2);
        assert_eq!(acts[0].kind, Kind::Sysinit);
        assert_eq!(acts[1].kind, Kind::Respawn);
        assert_eq!(acts[1].id, "tty1");
        std::fs::remove_dir_all(&dir).ok();
    }
}

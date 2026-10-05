//! Logging destinations from the image's option.c and musl facility table.
use super::{Directive, Error};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

#[derive(Clone, Debug, Default)]
pub struct LoggingConfig {
    /// An explicit facility overrides daemon/local0 selected by process mode.
    pub facility: Option<i32>,
    /// None uses /dev/log; "-" duplicates the inherited standard error.
    pub file: Option<PathBuf>,
}

impl LoggingConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        match directive.name.as_slice() {
            b"log-facility" => {
                let value = directive
                    .argument
                    .as_ref()
                    .ok_or(Error("bad log facility"))?
                    .decoded();
                if value.contains(&b'/') || value == b"-" {
                    self.file = Some(PathBuf::from(OsString::from_vec(value)));
                } else {
                    self.facility = Some(facility(&value).ok_or(Error("bad log facility"))?);
                }
            }
            // The exact target was built with NO_ID; option.c accepts this
            // Boolean but does not add identity records in either state.
            b"no-ident" => {}
            _ => return Ok(false),
        }
        Ok(true)
    }
}

fn facility(value: &[u8]) -> Option<i32> {
    // musl SYSLOG_NAMES, including its security alias and internal mark.
    let names: &[(&[u8], i32)] = &[
        (b"kern", 0),
        (b"user", 8),
        (b"mail", 16),
        (b"daemon", 24),
        (b"auth", 32),
        (b"security", 32),
        (b"syslog", 40),
        (b"lpr", 48),
        (b"news", 56),
        (b"uucp", 64),
        (b"cron", 72),
        (b"authpriv", 80),
        (b"ftp", 88),
        (b"local0", 128),
        (b"local1", 136),
        (b"local2", 144),
        (b"local3", 152),
        (b"local4", 160),
        (b"local5", 168),
        (b"local6", 176),
        (b"local7", 184),
        (b"mark", 192),
    ];
    names
        .iter()
        .find_map(|(name, number)| value.eq_ignore_ascii_case(name).then_some(*number))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facility_and_file_from_different_origins_are_independent() {
        let mut config = LoggingConfig::default();
        for line in [
            b"log-facility=/tmp/log".as_slice(),
            b"log-facility=SECURITY",
        ] {
            config
                .apply(&crate::config::lex_line(line).unwrap().unwrap())
                .unwrap();
        }
        assert_eq!(config.facility, Some(32));
        assert_eq!(config.file, Some("/tmp/log".into()));
        assert_eq!(facility(b"mark"), Some(192));
        for invalid in [b"".as_slice(), b"local8", b"24", b"audit"] {
            assert_eq!(facility(invalid), None);
        }
    }
}

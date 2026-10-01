//! Exact option.c enable-ubus state. Parsing does not open a connection.
use super::{validate_directive, Directive, Error};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum UbusConfig {
    #[default]
    Disabled,
    /// None retains opt_string_alloc's NULL for an explicit empty argument.
    /// Object names are opaque C-string bytes, not DNS names or UTF-8.
    Enabled { name: Option<Vec<u8>> },
}

impl UbusConfig {
    /// Repetition and CLI/file precedence belong to loader::load's tracker.
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        if validate_directive(directive)?.name != "enable-ubus" {
            return Ok(false);
        }
        let name = match &directive.argument {
            None => Some(b"dnsmasq".to_vec()),
            Some(argument) => {
                let bytes = argument.decoded();
                (!bytes.is_empty()).then_some(bytes)
            }
        };
        *self = Self::Enabled { name };
        Ok(true)
    }

    /// The C parser accepts an empty name, but ubus_init later dereferences
    /// NULL after connecting. Retain its parsed state and reject activation
    /// explicitly instead of substituting a default name or reproducing UB.
    pub fn object_name(&self) -> Result<Option<&[u8]>, Error> {
        match self {
            Self::Disabled => Ok(None),
            Self::Enabled { name: Some(name) } => Ok(Some(name)),
            Self::Enabled { name: None } => Err(Error("empty enable-ubus object name")),
        }
    }
}

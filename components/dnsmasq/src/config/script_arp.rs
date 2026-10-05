//! `option.c:388,516`: no-argument ARP callback flag.
use super::{Directive, Error};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScriptArpConfig {
    pub enabled: bool,
}

impl ScriptArpConfig {
    pub fn apply(&mut self, directive: &Directive) -> Result<bool, Error> {
        if directive.name != b"script-arp" {
            return Ok(false);
        }
        if directive.argument.is_some() {
            return Err(Error("extraneous parameter"));
        }
        self.enabled = true;
        Ok(true)
    }
}

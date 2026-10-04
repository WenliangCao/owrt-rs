//! PXE service/prompt/vendor grammar, option.c:4423-4538,4718-4730.

use super::dhcp::TagPredicate;
use super::{EncodedArg, Error};
use crate::dhcp::pxe::Service;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PxeConfig {
    /// Only pxe-service and pxe-prompt enable the PXE engine/listener.
    pub enabled: bool,
    /// Declaration order, unlike ordinary reverse-ordered DHCP options.
    pub services: Vec<Service>,
    /// Reverse declaration order; first custom list replaces PXEClient.
    pub vendors: Vec<Vec<u8>>,
    custom_vendors: bool,
    next_type: u16,
}

impl Default for PxeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            services: Vec::new(),
            vendors: vec![b"PXEClient".to_vec()],
            custom_vendors: false,
            next_type: 32768,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PxePrompt {
    pub tags: TagPredicate,
    /// Suboption10 data: timeout byte followed by text, without a NUL.
    pub data: Vec<u8>,
}

impl PxeConfig {
    pub fn add_service(&mut self, argument: &EncodedArg) -> Result<(), Error> {
        let (filter, rest) = leading_tags(argument)?;
        let (architecture, rest) = rest.split_once(b',');
        let rest = rest.ok_or(Error("error"))?;
        let architecture = architecture.encoded();
        const NAMES: [&[u8]; 12] = [
            b"x86PC",
            b"PC98",
            b"IA64_EFI",
            b"Alpha",
            b"Arc_x86",
            b"Intel_Lean_Client",
            b"IA32_EFI",
            b"x86-64_EFI",
            b"Xscale_EFI",
            b"BC_EFI",
            b"ARM32_EFI",
            b"ARM64_EFI",
        ];
        let architecture = match NAMES
            .iter()
            .position(|name| name.eq_ignore_ascii_case(architecture))
        {
            Some(value) => value as u16,
            None => integer(&EncodedArg::command_line(architecture).decoded())?
                .ok_or(Error("error"))? as u16,
        };
        let (menu, tail) = rest.split_once(b',');
        let menu = menu.decoded();
        if menu.is_empty() {
            // C stores NULL then calls strlen in pxe_opts. Do not reproduce
            // that undefined runtime path; syntax-only C evidence is retained.
            return Err(Error("empty PXE menu"));
        }
        let mut service_type = 0;
        let mut basename = None;
        let mut server = Ipv4Addr::UNSPECIFIED;
        let mut server_name = None;
        let mut automatic = false;
        if let Some(tail) = tail {
            let (boot, host) = tail.split_once(b',');
            match integer(&boot.decoded())? {
                Some(number) => service_type = number as u16,
                None => {
                    service_type = self.next_type;
                    automatic = true;
                    basename = Some(boot.decoded());
                }
            }
            if let Some(host) = host {
                // C tries inet_pton before unhide_metas on this field.
                if let Some(address) = std::str::from_utf8(host.encoded())
                    .ok()
                    .and_then(|value| value.parse().ok())
                {
                    server = address;
                } else {
                    let name = host.decoded();
                    server_name = (!name.is_empty()).then_some(name);
                }
            }
        }
        self.services.push(Service {
            architecture,
            service_type,
            menu,
            basename,
            server,
            server_name,
            filter: filter.tags().to_vec(),
        });
        if automatic {
            self.next_type = self.next_type.wrapping_add(1);
        }
        self.enabled = true;
        Ok(())
    }

    pub fn add_vendors(&mut self, argument: &EncodedArg) -> Result<(), Error> {
        let values: Vec<_> = argument
            .split(b',')
            .into_iter()
            .map(|value| value.decoded())
            .collect();
        if values.iter().any(Vec::is_empty) {
            // NULL is passed to strlen by is_pxe_client in the reference.
            return Err(Error("empty PXE vendor"));
        }
        if !self.custom_vendors {
            self.vendors.clear();
            self.custom_vendors = true;
        }
        for value in values {
            self.vendors.insert(0, value);
        }
        Ok(())
    }

    pub fn parse_prompt(&mut self, argument: &EncodedArg) -> Result<PxePrompt, Error> {
        let (tags, argument) = leading_tags(argument)?;
        let (prompt, timeout) = argument.split_once(b',');
        let prompt = prompt.decoded();
        // Vendor suboption payload must fit inside option43 with a two-byte
        // suboption header. C's prompt shortcut omits this check and can emit
        // a wrapped outer length; retain only syntax evidence for that input.
        if prompt.len() > 251 {
            return Err(Error("PXE prompt too long"));
        }
        let timeout = timeout
            .map(|value| integer(&value.decoded()))
            .transpose()?
            .flatten()
            .map_or(255, |value| value as u8);
        let mut data = Vec::with_capacity(prompt.len() + 1);
        data.push(timeout);
        data.extend_from_slice(&prompt);
        self.enabled = true;
        Ok(PxePrompt { tags, data })
    }
}

fn leading_tags(argument: &EncodedArg) -> Result<(TagPredicate, EncodedArg), Error> {
    let mut tags = Vec::new();
    let mut rest = argument.clone();
    while rest.encoded().starts_with(b"tag:") || rest.encoded().starts_with(b"net:") {
        let (tag, tail) = rest.split_once(b',');
        let decoded = tag.decoded();
        if decoded.len() == 4 {
            return Err(Error("empty DHCP tag predicate"));
        }
        tags.push(decoded[4..].to_vec());
        rest = tail.ok_or(Error("error"))?;
    }
    Ok((TagPredicate::from_tags(tags), rest))
}

fn integer(value: &[u8]) -> Result<Option<u32>, Error> {
    if !value.iter().all(u8::is_ascii_digit) {
        return Ok(None);
    }
    value
        .iter()
        .try_fold(0u32, |number, byte| {
            number
                .checked_mul(10)
                .and_then(|number| number.checked_add(u32::from(*byte - b'0')))
                .filter(|number| *number <= i32::MAX as u32)
                .ok_or(Error("PXE integer exceeds defined C int range"))
        })
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arg(value: &[u8]) -> EncodedArg {
        EncodedArg::command_line(value)
    }

    #[test]
    fn services_preserve_order_and_assign_ids_only_to_basenames() {
        let mut config = PxeConfig::default();
        for value in [
            b"x86PC,local".as_slice(),
            b"tag:boot,7,first,efi,192.0.2.1",
            b"65543,numeric,65537",
            b"ARM64_EFI,next,netboot.example,host.example",
        ] {
            config.add_service(&arg(value)).unwrap();
        }
        assert_eq!(
            config
                .services
                .iter()
                .map(|service| service.service_type)
                .collect::<Vec<_>>(),
            [0, 32768, 1, 32769]
        );
        assert_eq!(config.services[2].architecture, 7);
        assert_eq!(config.services[1].filter, [b"boot".to_vec()]);
        assert_eq!(
            config.services[3].server_name.as_deref(),
            Some(b"host.example".as_slice())
        );
        assert!(config.enabled);
    }

    #[test]
    fn vendor_lists_replace_default_and_do_not_enable() {
        let mut config = PxeConfig::default();
        config.add_vendors(&arg(b"PXEClient,iPXE")).unwrap();
        config.add_vendors(&arg(b"custom")).unwrap();
        assert_eq!(
            config.vendors,
            [b"custom".to_vec(), b"iPXE".to_vec(), b"PXEClient".to_vec()]
        );
        assert!(!config.enabled);
        assert!(config.add_vendors(&arg(b"valid,")).is_err());
    }

    #[test]
    fn prompt_timeout_matches_c_byte_conversion_and_string_rules() {
        let mut config = PxeConfig::default();
        for (text, expected) in [
            (b"boot".as_slice(), 255),
            (b"boot,-1", 255),
            (b"boot,invalid", 255),
            (b"boot,", 0),
            (b"boot,256", 0),
            (b"boot,257", 1),
        ] {
            let prompt = config.parse_prompt(&arg(text)).unwrap();
            assert_eq!(prompt.data[0], expected);
            assert_eq!(&prompt.data[1..], b"boot");
        }
        assert!(config.parse_prompt(&arg(b"tag:only")).is_err());
        assert_eq!(config.parse_prompt(&arg(b"")).unwrap().data, [255]);
        assert_eq!(config.parse_prompt(&arg(&[b'a'; 251])).unwrap().data.len(), 252);
        assert!(config.parse_prompt(&arg(&[b'a'; 252])).is_err());
    }
}

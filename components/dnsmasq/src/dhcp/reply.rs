//! Bounded DHCPv4/BOOTP reply construction.
//!
//! This module is deliberately socket independent.  The caller has already
//! selected a `state::Reply` and supplies any context-dependent options.  We
//! only apply the wire mutations performed by `rfc2131.c` and `dhcp-protocol.h`:
//! `clear_packet`, the mandatory reply options, bounded `free_space` placement,
//! and `dhcp_packet_size`.  Configuration option selection, destination
//! routing, and lease side effects remain outside this boundary.

pub use super::packet::VendorOption as ReplyOption;
use super::packet::{encode_bootp_vendor, Packet, VendorError};
use super::state::{Outcome, Reply};
use std::net::Ipv4Addr;

const OP_REPLY: u8 = 2;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_SERVER_IDENTIFIER: u8 = 54;
const OPTION_LEASE_TIME: u8 = 51;
const OPTION_MESSAGE: u8 = 56;
const OPTION_OVERLOAD: u8 = 52;
const OPTION_RAPID_COMMIT: u8 = 80;
const OPTION_T1: u8 = 58;
const OPTION_T2: u8 = 59;
const OPTION_END: u8 = 255;
const OPTION_PAD: u8 = 0;
const MIN_PACKET_SIZE: usize = 300;
const OPTIONS_OFFSET: usize = 240;
const FILE_OFFSET: usize = 108;
const FILE_LEN: usize = 128;
const SNAME_OFFSET: usize = 44;
const SNAME_LEN: usize = 64;
const BROADCAST_FLAG: u16 = 0x8000;

/// Result of a successful wire build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyEncoding {
    /// Number of bytes to send.  As in `dhcp_packet_size`, this is at least
    /// 300 for both DHCP and BOOTP replies.
    pub len: usize,
    /// Number of options skipped after all available regions were exhausted.
    pub omitted: usize,
    /// DHCP option-overload bits: bit 0 means `file`, bit 1 means `sname`.
    /// BOOTP replies always report zero.
    pub overload: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// `Reply::Ignore` has no wire response.
    NoReply,
    /// The output buffer cannot hold the request's advertised response size.
    BufferTooSmall { required: usize, available: usize },
    /// The supplied option is not a valid DHCP TLV for this boundary.
    InvalidOption { code: u8 },
    /// A DHCP option value exceeds its one-byte wire length field.
    OptionTooLong { code: u8, length: usize },
    /// A BOOTP option sequence contains a malformed PAD/END value.
    Bootp(VendorError),
}

impl From<VendorError> for ReplyError {
    fn from(error: VendorError) -> Self {
        Self::Bootp(error)
    }
}

/// Build a reply for a state-machine outcome.  `Outcome::removed` and
/// `Outcome::lost_names` are intentionally not consulted: those side effects
/// are committed by the state layer before the caller transmits this packet.
pub fn build_outcome(
    request: Packet<'_>,
    outcome: &Outcome,
    options: &[ReplyOption<'_>],
    output: &mut [u8],
) -> Result<ReplyEncoding, ReplyError> {
    build_reply(request, outcome.reply, options, output)
}

/// Build one BOOTP/DHCP reply into `output`.
///
/// The fixed header is copied from the request, then changed to BOOTREPLY and
/// cleared in the same places as `clear_packet`.  DHCP options use the C
/// `p + len + 3 < end` fit test.  When the primary area fills, an overload TLV
/// is reserved and options are attempted in `file` and then `sname`; options
/// that still do not fit are counted and skipped, matching `free_space`.
/// This deterministic wrapper uses zero renewal fuzz; live callers use
/// `build_reply_with_fuzz` through the runtime's entropy boundary.
pub fn build_reply(
    request: Packet<'_>,
    reply: Reply,
    options: &[ReplyOption<'_>],
    output: &mut [u8],
) -> Result<ReplyEncoding, ReplyError> {
    // This default follows the ordinary dnsmasq path: do_options can use
    // filename/server-name only when the request contains a parameter request
    // list, and NAK never enters do_options. Callers that have already
    // evaluated `--dhcp-no-override` can use `build_reply_with_overload` to
    // make that policy explicit.
    let allow_overload = request.option(55, 0).is_some() && !matches!(reply, Reply::Nak { .. });
    build_reply_with_overload(request, reply, options, allow_overload, output)
}

/// Build a reply while explicitly selecting whether `file`/`sname` may carry
/// option-overload data. This is the integration hook for the caller's
/// `dhcp-no-override`/requested-options policy; it does not bypass the bounded
/// `free_space` checks.
pub fn build_reply_with_overload(
    request: Packet<'_>,
    reply: Reply,
    options: &[ReplyOption<'_>],
    allow_overload: bool,
    output: &mut [u8],
) -> Result<ReplyEncoding, ReplyError> {
    build_reply_with_fuzz(request, reply, options, allow_overload, 0, output)
}

/// Build a reply with an injected C `rand16()` value. Only an ACK to a
/// renewing/rebinding REQUEST consumes the value; OFFER, SELECTING,
/// INIT-REBOOT and rapid commit use zero fuzz. Options 58/59 are selected
/// configuration overrides, not additional raw wire options.
pub fn build_reply_with_fuzz(
    request: Packet<'_>,
    reply: Reply,
    options: &[ReplyOption<'_>],
    allow_overload: bool,
    fuzz: u16,
    output: &mut [u8],
) -> Result<ReplyEncoding, ReplyError> {
    if reply == Reply::Ignore {
        return Err(ReplyError::NoReply);
    }

    let bootp = matches!(reply, Reply::Bootp { .. });
    let required = if bootp {
        MIN_PACKET_SIZE
    } else {
        request.response_capacity().max(MIN_PACKET_SIZE)
    };
    if output.len() < required {
        return Err(ReplyError::BufferTooSmall {
            required,
            available: output.len(),
        });
    }

    // Validate caller data before changing the output. BOOTP reuses the
    // separately C-tested vend serializer, with no allocation or option cap.
    let mut vendor = [0; 64];
    let vendor_encoding = if bootp {
        Some(encode_bootp_vendor(options, &mut vendor)?)
    } else {
        if !matches!(reply, Reply::Nak { .. }) {
            for option in options {
                validate_dhcp_option(*option, reply)?;
            }
        }
        None
    };

    output[..required].fill(0);
    output[..44].copy_from_slice(&request.bytes()[..44]);
    output[0] = OP_REPLY;
    output[20..24].fill(0); // clear_packet: discard request siaddr.
                            // C preserves the cookie for BOOTP too, including non-RFC1048 cookies.
    if let Some(cookie) = request.bytes().get(236..240) {
        output[236..240].copy_from_slice(cookie);
    }
    match reply {
        Reply::Offer { address, .. }
        | Reply::Bootp { address, .. }
        | Reply::Ack { address, .. } => put_ipv4(&mut output[16..20], address),
        Reply::Nak { .. } => output[16..20].fill(0),
        // clear_packet does not clear yiaddr on the INFORM path.
        Reply::Inform { .. } | Reply::Ignore => {}
    }
    put_ipv4(&mut output[12..16], request.effective_ciaddr());
    if matches!(
        reply,
        Reply::Nak {
            broadcast: true,
            ..
        }
    ) {
        let flags = request.flags() | BROADCAST_FLAG;
        output[10..12].copy_from_slice(&flags.to_be_bytes());
        output[12..16].fill(0);
    }

    if let Some(encoding) = vendor_encoding {
        // Preserve cookie bytes from the request, as clear_packet does.
        output[240..300].copy_from_slice(&vendor[4..]);
        return Ok(ReplyEncoding {
            len: MIN_PACKET_SIZE,
            omitted: encoding.omitted,
            overload: 0,
        });
    }

    let mut writer = OptionWriter::new(&mut output[..required]);
    append_mandatory(&mut writer, reply, broken_string_option(request))?;
    // do_options temporarily blocks file/sname when no PRL is present.
    // NAK does not call do_options at all.
    writer.allow_overload(allow_overload && !matches!(reply, Reply::Nak { .. }));
    if !matches!(reply, Reply::Nak { .. }) {
        if let Reply::Offer { lease_time, .. } | Reply::Ack { lease_time, .. } = reply {
            if lease_time != u32::MAX {
                append_lease_timers(
                    &mut writer,
                    lease_time,
                    options,
                    if needs_renewal_fuzz(request, reply) {
                        fuzz
                    } else {
                        0
                    },
                )?;
            }
        }
        for option in options {
            // do_options handles T1/T2 internally and excludes them from
            // the ordinary configured-options loop, even for INFORM.
            if !matches!(option.code, OPTION_T1 | OPTION_T2) {
                writer.append(*option)?;
            }
        }
    }
    let (end, omitted, overload) = writer.finish();
    Ok(ReplyEncoding {
        len: end.max(MIN_PACKET_SIZE),
        omitted,
        overload,
    })
}

pub(crate) fn needs_renewal_fuzz(request: Packet<'_>, reply: Reply) -> bool {
    matches!(reply, Reply::Ack { .. })
        && request.message_type() == 3
        && request.requested_address().is_none()
}

fn append_lease_timers(
    writer: &mut OptionWriter<'_>,
    lease_time: u32,
    options: &[ReplyOption<'_>],
    fuzz: u16,
) -> Result<(), ReplyError> {
    let configured = |code, default| {
        options
            .iter()
            .find(|option| option.code == code)
            .map(|option| u32::from_be_bytes(option.value.try_into().expect("validated timer")))
            .filter(|value| *value > 2 && *value < lease_time)
            .unwrap_or(default)
    };
    let mut t1 = configured(OPTION_T1, lease_time / 2);
    // Keep C unsigned-int arithmetic, including the large-lease wraparound.
    let mut t2 = configured(OPTION_T2, lease_time.wrapping_mul(7) / 8);
    if t2 <= t1 {
        t1 = t2.wrapping_sub(1);
    }
    let mut fuzz = u32::from(fuzz);
    while fuzz > t1 / 8 {
        fuzz /= 2;
    }
    t1 = t1.wrapping_sub(fuzz);
    t2 = t2.wrapping_sub(fuzz);
    writer.append(ReplyOption {
        code: OPTION_T1,
        value: &t1.to_be_bytes(),
    })?;
    writer.append(ReplyOption {
        code: OPTION_T2,
        value: &t2.to_be_bytes(),
    })
}

/// `rfc2131.c` calls `option_put_string(..., borken_opt)` for a NAK.  The
/// spelling is historical: clients that send a trailing NUL in option 81 (or
/// option 12 when option 81 is absent) require that NUL in the response text.
/// Option 81 has precedence over option 12, even when its decoded hostname is
/// empty or invalid.
fn broken_string_option(request: Packet<'_>) -> bool {
    if let Some(value) = request.option(81, 3) {
        return value.first().is_some_and(|flags| flags & 0x04 == 0)
            && value[3..].last() == Some(&0);
    }
    request
        .option(12, 1)
        .is_some_and(|value| value.last() == Some(&0))
}

fn append_mandatory(
    writer: &mut OptionWriter<'_>,
    reply: Reply,
    broken_string: bool,
) -> Result<(), ReplyError> {
    match reply {
        Reply::Offer {
            lease_time, server, ..
        } => {
            writer.append(ReplyOption {
                code: OPTION_MESSAGE_TYPE,
                value: &[2],
            })?;
            let server = server.octets();
            writer.append(ReplyOption {
                code: OPTION_SERVER_IDENTIFIER,
                value: &server,
            })?;
            let lease = lease_time.to_be_bytes();
            writer.append(ReplyOption {
                code: OPTION_LEASE_TIME,
                value: &lease,
            })?;
        }
        Reply::Ack {
            lease_time,
            server,
            rapid_commit,
            ..
        } => {
            writer.append(ReplyOption {
                code: OPTION_MESSAGE_TYPE,
                value: &[5],
            })?;
            let server = server.octets();
            writer.append(ReplyOption {
                code: OPTION_SERVER_IDENTIFIER,
                value: &server,
            })?;
            let lease = lease_time.to_be_bytes();
            writer.append(ReplyOption {
                code: OPTION_LEASE_TIME,
                value: &lease,
            })?;
            if rapid_commit {
                writer.append(ReplyOption {
                    code: OPTION_RAPID_COMMIT,
                    value: &[],
                })?;
            }
        }
        Reply::Inform {
            lease_time, server, ..
        } => {
            writer.append(ReplyOption {
                code: OPTION_MESSAGE_TYPE,
                value: &[5],
            })?;
            let server = server.octets();
            writer.append(ReplyOption {
                code: OPTION_SERVER_IDENTIFIER,
                value: &server,
            })?;
            if let Some(lease_time) = lease_time {
                let lease = lease_time.to_be_bytes();
                writer.append(ReplyOption {
                    code: OPTION_LEASE_TIME,
                    value: &lease,
                })?;
            }
        }
        Reply::Nak { reason, server, .. } => {
            writer.append(ReplyOption {
                code: OPTION_MESSAGE_TYPE,
                value: &[6],
            })?;
            let server = server.octets();
            writer.append(ReplyOption {
                code: OPTION_SERVER_IDENTIFIER,
                value: &server,
            })?;
            let message = reason.message().as_bytes();
            if broken_string {
                let mut terminated = [0u8; 256];
                terminated[..message.len()].copy_from_slice(message);
                writer.append(ReplyOption {
                    code: OPTION_MESSAGE,
                    value: &terminated[..message.len() + 1],
                })?;
            } else {
                writer.append(ReplyOption {
                    code: OPTION_MESSAGE,
                    value: message,
                })?;
            }
        }
        Reply::Bootp { .. } | Reply::Ignore => {}
    }
    Ok(())
}

fn validate_dhcp_option(option: ReplyOption<'_>, reply: Reply) -> Result<(), ReplyError> {
    if matches!(option.code, OPTION_PAD | OPTION_END | OPTION_OVERLOAD) {
        return Err(ReplyError::InvalidOption { code: option.code });
    }
    if option.value.len() > u8::MAX as usize {
        return Err(ReplyError::OptionTooLong {
            code: option.code,
            length: option.value.len(),
        });
    }
    if matches!(option.code, OPTION_T1 | OPTION_T2) && option.value.len() != 4 {
        return Err(ReplyError::InvalidOption { code: option.code });
    }
    if is_mandatory_code(reply, option.code) {
        return Err(ReplyError::InvalidOption { code: option.code });
    }
    Ok(())
}

fn is_mandatory_code(reply: Reply, code: u8) -> bool {
    if matches!(reply, Reply::Bootp { .. } | Reply::Ignore) {
        return false;
    }
    matches!(code, OPTION_MESSAGE_TYPE | OPTION_SERVER_IDENTIFIER)
        || matches!(reply, Reply::Offer { .. } | Reply::Ack { .. }) && code == OPTION_LEASE_TIME
        || matches!(
            reply,
            Reply::Inform {
                lease_time: Some(_),
                ..
            }
        ) && code == OPTION_LEASE_TIME
        || matches!(
            reply,
            Reply::Ack {
                rapid_commit: true,
                ..
            }
        ) && code == OPTION_RAPID_COMMIT
        || matches!(reply, Reply::Nak { .. }) && code == OPTION_MESSAGE
}

fn put_ipv4(dst: &mut [u8], address: Ipv4Addr) {
    dst.copy_from_slice(&address.octets());
}

struct OptionWriter<'a> {
    packet: &'a mut [u8],
    primary: usize,
    primary_end: usize,
    file: usize,
    sname: usize,
    overload_offset: Option<usize>,
    allow_overload: bool,
    overload: u8,
    omitted: usize,
}

impl<'a> OptionWriter<'a> {
    fn new(packet: &'a mut [u8]) -> Self {
        let primary_end = packet.len();
        Self {
            packet,
            primary: OPTIONS_OFFSET,
            primary_end,
            file: FILE_OFFSET,
            sname: SNAME_OFFSET,
            overload_offset: None,
            allow_overload: false,
            overload: 0,
            omitted: 0,
        }
    }

    fn allow_overload(&mut self, enabled: bool) {
        self.allow_overload = enabled;
        if enabled {
            // do_options reserves the TLV before appending caller options.
            self.primary_end -= 3;
        }
    }

    fn append(&mut self, option: ReplyOption<'_>) -> Result<(), ReplyError> {
        if option.value.len() > u8::MAX as usize {
            return Err(ReplyError::OptionTooLong {
                code: option.code,
                length: option.value.len(),
            });
        }
        let needed = option.value.len() + 2;
        if self.fits(self.primary, self.primary_end, needed) {
            self.write_at(self.primary, option);
            self.primary += needed;
            return Ok(());
        }

        if !self.allow_overload {
            self.omitted += 1;
            return Ok(());
        }
        self.ensure_overload();
        if self.overload_offset.is_none() {
            self.omitted += 1;
            return Ok(());
        }
        if self.overload & 1 == 0 {
            self.overload |= 1;
            if self.fits(self.file, FILE_OFFSET + FILE_LEN, needed) {
                self.write_at(self.file, option);
                self.file += needed;
                self.set_overload();
                return Ok(());
            }
        } else if self.fits(self.file, FILE_OFFSET + FILE_LEN, needed) {
            self.write_at(self.file, option);
            self.file += needed;
            return Ok(());
        }

        self.overload |= 2;
        if self.fits(self.sname, SNAME_OFFSET + SNAME_LEN, needed) {
            self.write_at(self.sname, option);
            self.sname += needed;
            self.set_overload();
            return Ok(());
        }
        self.omitted += 1;
        Ok(())
    }

    fn fits(&self, position: usize, end: usize, needed: usize) -> bool {
        position
            .checked_add(needed)
            .and_then(|value| value.checked_add(1))
            .is_some_and(|value| value < end)
    }

    fn ensure_overload(&mut self) {
        if self.overload_offset.is_none() && self.primary + 3 < self.packet.len() {
            let offset = self.primary;
            self.packet[offset..offset + 3].copy_from_slice(&[OPTION_OVERLOAD, 1, 0]);
            self.primary += 3;
            self.overload_offset = Some(offset);
        }
    }

    fn set_overload(&mut self) {
        if let Some(offset) = self.overload_offset {
            self.packet[offset + 2] = self.overload;
        }
    }

    fn write_at(&mut self, position: usize, option: ReplyOption<'_>) {
        self.packet[position] = option.code;
        self.packet[position + 1] = option.value.len() as u8;
        self.packet[position + 2..position + 2 + option.value.len()].copy_from_slice(option.value);
    }

    fn finish(mut self) -> (usize, usize, u8) {
        self.set_overload();
        if self.primary < self.packet.len() {
            self.packet[self.primary] = OPTION_END;
            self.primary += 1;
        }
        if self.overload & 1 != 0 && self.file < FILE_OFFSET + FILE_LEN {
            self.packet[self.file] = OPTION_END;
            self.file += 1;
        }
        if self.overload & 2 != 0 && self.sname < SNAME_OFFSET + SNAME_LEN {
            self.packet[self.sname] = OPTION_END;
            self.sname += 1;
        }
        (
            self.primary.max(self.file).max(self.sname),
            self.omitted,
            self.overload,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::packet::{Packet, COOKIE};
    use crate::dhcp::state::Refusal;

    fn request(options: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 240];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[4..8].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        bytes[236..240].copy_from_slice(&COOKIE);
        bytes.extend_from_slice(options);
        bytes
    }

    #[test]
    fn offer_contains_header_and_mandatory_options() {
        let bytes = request(&[53, 1, 1, 255]);
        let packet = Packet::parse(&bytes).unwrap();
        let mut output = vec![0xaa; 548];
        let result = build_reply(
            packet,
            Reply::Offer {
                address: Ipv4Addr::new(192, 0, 2, 42),
                lease_time: 600,
                context: 0,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            &[],
            &mut output,
        )
        .unwrap();
        assert_eq!(result.len, 300);
        assert_eq!(output[0], OP_REPLY);
        assert_eq!(&output[16..20], &[192, 0, 2, 42]);
        assert_eq!(&output[236..240], &[99, 130, 83, 99]);
        assert_eq!(&output[240..243], &[53, 1, 2]);
        assert_eq!(&output[243..249], &[54, 4, 192, 0, 2, 1]);
        assert_eq!(&output[249..255], &[51, 4, 0, 0, 2, 88]);
        assert_eq!(
            option_value(&output, OPTION_T1),
            Some(300u32.to_be_bytes().as_slice())
        );
        assert_eq!(
            option_value(&output, OPTION_T2),
            Some(525u32.to_be_bytes().as_slice())
        );
    }

    #[test]
    fn timers_apply_c_overrides_and_bounded_shared_renewal_fuzz() {
        let bytes = request(&[53, 1, 3, 255]);
        let packet = Packet::parse(&bytes).unwrap();
        let ack = Reply::Ack {
            address: Ipv4Addr::new(192, 0, 2, 42),
            lease_time: 600,
            context: 0,
            server: Ipv4Addr::new(192, 0, 2, 1),
            rapid_commit: false,
        };
        let mut output = vec![0; 548];
        // C halves 65535 to 31 (<=300/8), then subtracts it from both timers.
        build_reply_with_fuzz(packet, ack, &[], false, 65535, &mut output).unwrap();
        assert_eq!(
            option_value(&output, OPTION_T1),
            Some(269u32.to_be_bytes().as_slice())
        );
        assert_eq!(
            option_value(&output, OPTION_T2),
            Some(494u32.to_be_bytes().as_slice())
        );
        let options = [
            ReplyOption {
                code: OPTION_T1,
                value: &599u32.to_be_bytes(),
            },
            ReplyOption {
                code: OPTION_T2,
                value: &3u32.to_be_bytes(),
            },
        ];
        build_reply_with_fuzz(packet, ack, &options, false, 65535, &mut output).unwrap();
        // Configured T2=3 lowers T1 to 2; the fuzz loop reaches zero.
        assert_eq!(
            option_value(&output, OPTION_T1),
            Some(2u32.to_be_bytes().as_slice())
        );
        assert_eq!(
            option_value(&output, OPTION_T2),
            Some(3u32.to_be_bytes().as_slice())
        );
        assert_eq!(output[267], OPTION_END);
    }

    #[test]
    fn timers_exclude_inform_and_infinite_leases() {
        let bytes = request(&[53, 1, 8, 55, 1, 51, 255]);
        let packet = Packet::parse(&bytes).unwrap();
        let mut output = vec![0; 548];
        let options = [ReplyOption {
            code: OPTION_T1,
            value: &30u32.to_be_bytes(),
        }];
        for reply in [
            Reply::Inform {
                lease_time: Some(60),
                context: Some(0),
                server: Ipv4Addr::LOCALHOST,
            },
            Reply::Offer {
                address: Ipv4Addr::LOCALHOST,
                lease_time: u32::MAX,
                context: 0,
                server: Ipv4Addr::LOCALHOST,
            },
        ] {
            build_reply(packet, reply, &options, &mut output).unwrap();
            assert!(option_value(&output, OPTION_LEASE_TIME).is_some());
            assert!(option_value(&output, OPTION_T1).is_none());
            assert!(option_value(&output, OPTION_T2).is_none());
        }
    }

    #[test]
    fn malformed_configured_timer_is_rejected_before_output_mutation() {
        let bytes = request(&[53, 1, 1, 255]);
        let packet = Packet::parse(&bytes).unwrap();
        let mut output = vec![0xaa; 548];
        let reply = Reply::Offer {
            address: Ipv4Addr::LOCALHOST,
            lease_time: 60,
            context: 0,
            server: Ipv4Addr::LOCALHOST,
        };
        assert_eq!(
            build_reply(
                packet,
                reply,
                &[ReplyOption {
                    code: OPTION_T1,
                    value: &[1, 2, 3]
                }],
                &mut output
            ),
            Err(ReplyError::InvalidOption { code: OPTION_T1 })
        );
        assert!(output.iter().all(|byte| *byte == 0xaa));
    }

    #[test]
    fn ack_rapid_commit_and_nak_broadcast() {
        let request_bytes = request(&[53, 1, 1, 255]);
        let packet = Packet::parse(&request_bytes).unwrap();
        let mut output = vec![0; 548];
        let ack = build_reply(
            packet,
            Reply::Ack {
                address: Ipv4Addr::new(192, 0, 2, 4),
                lease_time: 1,
                context: 0,
                server: Ipv4Addr::new(192, 0, 2, 1),
                rapid_commit: true,
            },
            &[],
            &mut output,
        )
        .unwrap();
        assert_eq!(ack.overload, 0);
        assert!(output[240..ack.len].windows(2).any(|w| w == [80, 0]));

        let nak = build_reply(
            packet,
            Reply::Nak {
                reason: Refusal::WrongNetwork,
                broadcast: true,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            &[],
            &mut output,
        )
        .unwrap();
        assert_eq!(
            u16::from_be_bytes([output[10], output[11]]) & BROADCAST_FLAG,
            BROADCAST_FLAG
        );
        assert_eq!(&output[16..20], &[0, 0, 0, 0]);
        assert!(output[240..nak.len].windows(2).any(|w| w == [56, 13]));
    }

    #[test]
    fn full_primary_uses_file_then_sname_and_counts_overflow() {
        let request_bytes = request(&[53, 1, 1, 55, 0, 255]);
        let packet = Packet::parse(&request_bytes).unwrap();
        let value = [7u8; 100];
        let options = [
            ReplyOption {
                code: 1,
                value: &value,
            },
            ReplyOption {
                code: 2,
                value: &value,
            },
            ReplyOption {
                code: 3,
                value: &value,
            },
            ReplyOption {
                code: 4,
                value: &value,
            },
        ];
        let mut output = vec![0; 548];
        let result = build_reply(
            packet,
            Reply::Inform {
                lease_time: None,
                context: None,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            &options,
            &mut output,
        )
        .unwrap();
        assert_eq!(result.overload, 3);
        let overload = output[240..548]
            .windows(2)
            .position(|window| window == [OPTION_OVERLOAD, 1])
            .map(|position| position + 240)
            .unwrap();
        assert_eq!(output[overload + 2], 3);
        assert_eq!(output[108], 3);
        assert_eq!(output[44], OPTION_END);
        assert!(result.omitted >= 1);
    }

    #[test]
    fn bootp_uses_cookie_and_fixed_vendor_length() {
        let request_bytes = request(&[][..]);
        let packet = Packet::parse(&request_bytes).unwrap();
        let mut output = vec![0; 300];
        let result = build_reply(
            packet,
            Reply::Bootp {
                address: Ipv4Addr::new(198, 51, 100, 5),
                context: 0,
            },
            &[ReplyOption {
                code: 1,
                value: &[255, 255, 255, 0],
            }],
            &mut output,
        )
        .unwrap();
        assert_eq!(result.len, 300);
        assert_eq!(&output[236..240], &COOKIE);
        assert_eq!(&output[240..246], &[1, 4, 255, 255, 255, 0]);
        assert_eq!(output[246], OPTION_END);
    }

    #[test]
    fn clears_next_server_and_rejects_duplicate_mandatory_option() {
        let mut request_bytes = request(&[53, 1, 1, 255]);
        request_bytes[20..24].copy_from_slice(&[198, 51, 100, 9]);
        let packet = Packet::parse(&request_bytes).unwrap();
        let mut output = vec![0; 548];
        let error = build_reply(
            packet,
            Reply::Offer {
                address: Ipv4Addr::new(192, 0, 2, 42),
                lease_time: 600,
                context: 0,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            &[ReplyOption {
                code: OPTION_SERVER_IDENTIFIER,
                value: &[192, 0, 2, 9],
            }],
            &mut output,
        )
        .unwrap_err();
        assert_eq!(
            error,
            ReplyError::InvalidOption {
                code: OPTION_SERVER_IDENTIFIER
            }
        );

        build_reply(
            packet,
            Reply::Offer {
                address: Ipv4Addr::new(192, 0, 2, 42),
                lease_time: 600,
                context: 0,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            &[],
            &mut output,
        )
        .unwrap();
        assert_eq!(&output[20..24], &[0, 0, 0, 0]);
    }

    #[test]
    fn advertised_capacity_is_a_hard_output_boundary() {
        let bytes = request(&[53, 1, 1, 57, 2, 0x05, 0xdc, 255]);
        let packet = Packet::parse(&bytes).unwrap();
        let mut output = vec![0; 1471];
        assert_eq!(
            build_reply(
                packet,
                Reply::Offer {
                    address: Ipv4Addr::new(192, 0, 2, 42),
                    lease_time: 60,
                    context: 0,
                    server: Ipv4Addr::new(192, 0, 2, 1),
                },
                &[],
                &mut output,
            ),
            Err(ReplyError::BufferTooSmall {
                required: 1472,
                available: 1471,
            })
        );
    }

    #[test]
    fn absent_parameter_request_list_blocks_overload_regions() {
        let request_bytes = request(&[53, 1, 1, 255]);
        let packet = Packet::parse(&request_bytes).unwrap();
        let value = [7u8; 255];
        let options = [
            ReplyOption {
                code: 1,
                value: &value,
            },
            ReplyOption {
                code: 2,
                value: &value,
            },
        ];
        let mut output = vec![0; 548];
        let result = build_reply(
            packet,
            Reply::Inform {
                lease_time: None,
                context: None,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            &options,
            &mut output,
        )
        .unwrap();
        assert_eq!(result.overload, 0);
        assert_eq!(result.omitted, 1);
        assert_eq!(output[44], 0);
        assert_eq!(output[108], 0);
    }

    fn option_value(packet: &[u8], code: u8) -> Option<&[u8]> {
        let mut position = 240;
        while position < packet.len() {
            match packet[position] {
                0 => position += 1,
                255 => return None,
                found if position + 1 < packet.len() => {
                    let length = packet[position + 1] as usize;
                    let end = position + 2 + length;
                    if end > packet.len() {
                        return None;
                    }
                    if found == code {
                        return Some(&packet[position + 2..end]);
                    }
                    position = end;
                }
                _ => return None,
            }
        }
        None
    }

    #[test]
    fn nak_message_preserves_broken_client_terminator() {
        for request_options in [
            &[53, 1, 3, 81, 4, 0, 0, 0, 0, 255][..],
            &[53, 1, 3, 12, 2, b'x', 0, 255][..],
        ] {
            let request_bytes = request(request_options);
            let packet = Packet::parse(&request_bytes).unwrap();
            let mut output = vec![0; 548];
            build_reply(
                packet,
                Reply::Nak {
                    reason: Refusal::WrongNetwork,
                    broadcast: false,
                    server: Ipv4Addr::new(192, 0, 2, 1),
                },
                &[],
                &mut output,
            )
            .unwrap();
            assert_eq!(
                option_value(&output, OPTION_MESSAGE),
                Some(b"wrong network\0".as_slice())
            );
        }
    }

    #[test]
    fn fqdn_option_takes_precedence_over_trailing_hostname_nul() {
        let request_options = [
            53, 1, 3, // DHCPREQUEST
            81, 4, 4, 0, 0, 0, // encoded FQDN, no broken terminator
            12, 2, b'x', 0, 255,
        ];
        let request_bytes = request(&request_options);
        let packet = Packet::parse(&request_bytes).unwrap();
        let mut output = vec![0; 548];
        build_reply(
            packet,
            Reply::Nak {
                reason: Refusal::WrongNetwork,
                broadcast: false,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            &[],
            &mut output,
        )
        .unwrap();
        assert_eq!(
            option_value(&output, OPTION_MESSAGE),
            Some(b"wrong network".as_slice())
        );
    }

    #[test]
    fn nak_does_not_run_do_options_or_emit_selected_options() {
        let request_bytes = request(&[53, 1, 3, 55, 1, 1, 255]);
        let packet = Packet::parse(&request_bytes).unwrap();
        let mut output = vec![0; 548];
        build_reply(
            packet,
            Reply::Nak {
                reason: Refusal::WrongNetwork,
                broadcast: false,
                server: Ipv4Addr::new(192, 0, 2, 1),
            },
            &[ReplyOption {
                code: 1,
                value: &[255, 255, 255, 0],
            }],
            &mut output,
        )
        .unwrap();
        assert!(option_value(&output, 1).is_none());
    }
}

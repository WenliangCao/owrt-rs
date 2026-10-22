//! TFTP protocol primitives traced to the patched 2.93 `src/tftp.c`.
//!
//! Socket, interface, file-permission and helper ownership belongs to the service
//! layer. These routines do not open files or listen on the network.

pub const DEFAULT_BLOCK_SIZE: usize = 512;
pub const MAX_WINDOW: u32 = 32;
pub const TRANSFER_TIMEOUT: u64 = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Octet,
    Netascii,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    Truncated,
    WriteUnsupported,
    InvalidFilename,
    InvalidMode,
    InvalidBufferSize,
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "truncated TFTP request",
            Self::WriteUnsupported => "TFTP write requests are unsupported",
            Self::InvalidFilename => "invalid TFTP filename",
            Self::InvalidMode => "invalid TFTP transfer mode",
            Self::InvalidBufferSize => "invalid TFTP packet buffer size",
        })
    }
}

impl std::error::Error for RequestError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Options {
    pub block_size: usize,
    pub window_size: u32,
    pub timeout: u32,
    pub send_block_size: bool,
    pub send_transfer_size: bool,
    pub send_timeout: bool,
    pub send_window_size: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            window_size: 1,
            timeout: 2,
            send_block_size: false,
            send_transfer_size: false,
            send_timeout: false,
            send_window_size: false,
        }
    }
}

impl Options {
    pub fn needs_ack(&self) -> bool {
        self.send_block_size
            || self.send_transfer_size
            || self.send_timeout
            || self.send_window_size
    }

    /// `get_block()` emits options in this fixed order, regardless of RRQ order.
    /// C advertises the low 32 bits of file size, including for files over 4 GiB.
    pub fn write_ack(&self, file_size: u64, output: &mut Vec<u8>) {
        output.clear();
        output.extend_from_slice(&6u16.to_be_bytes());
        for (enabled, name, value) in [
            (
                self.send_block_size,
                &b"blksize"[..],
                self.block_size as u32,
            ),
            (self.send_transfer_size, &b"tsize"[..], file_size as u32),
            (self.send_timeout, &b"timeout"[..], self.timeout),
            (self.send_window_size, &b"windowsize"[..], self.window_size),
        ] {
            if enabled {
                output.extend_from_slice(name);
                output.push(0);
                // Ten decimal digits suffice for u32; no per-option allocation.
                let mut digits = [0; 10];
                let mut start = digits.len();
                let mut value = value;
                loop {
                    start -= 1;
                    digits[start] = b'0' + (value % 10) as u8;
                    value /= 10;
                    if value == 0 {
                        break;
                    }
                }
                output.extend_from_slice(&digits[start..]);
                output.push(0);
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReadRequest<'a> {
    pub filename: &'a [u8],
    pub mode: Mode,
    pub options: Options,
}

fn next_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let end = input.iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }
    let value = &input[..end];
    *input = &input[end + 1..];
    Some(value)
}

/// Exact image musl `atoi`: leading whitespace, optional sign and decimal
/// prefix. Accumulation wraps to 32 bits, then C converts the result to unsigned.
fn option_number(mut input: &[u8]) -> u32 {
    while input
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'..=b'\r'))
    {
        input = &input[1..];
    }
    let negative = input.first() == Some(&b'-');
    if negative || input.first() == Some(&b'+') {
        input = &input[1..];
    }
    let mut value = 0u32;
    for &b in input.iter().take_while(|b| b.is_ascii_digit()) {
        value = value.wrapping_mul(10).wrapping_add(u32::from(b - b'0'));
    }
    if negative {
        value = value.wrapping_neg();
    }
    value
}

/// `tftp_request()` lines 369–444: unknown opcodes are silently ignored;
/// incomplete/empty option pairs terminate parsing without rejecting the RRQ.
pub fn parse_request(
    packet: &[u8],
    packet_buffer_size: usize,
    mtu: Option<u32>,
    ipv6: bool,
    no_block_size: bool,
) -> Result<Option<ReadRequest<'_>>, RequestError> {
    if packet.len() < 2 {
        return Err(RequestError::Truncated);
    }
    match u16::from_be_bytes([packet[0], packet[1]]) {
        2 => return Err(RequestError::WriteUnsupported),
        1 => (),
        _ => return Ok(None),
    }
    if packet_buffer_size < 516 {
        return Err(RequestError::InvalidBufferSize);
    }
    let mut remaining = &packet[2..];
    let filename = next_string(&mut remaining).ok_or(RequestError::InvalidFilename)?;
    let mode = next_string(&mut remaining).ok_or(RequestError::InvalidMode)?;
    let mode = if mode.eq_ignore_ascii_case(b"octet") {
        Mode::Octet
    } else if mode.eq_ignore_ascii_case(b"netascii") {
        Mode::Netascii
    } else {
        return Err(RequestError::InvalidMode);
    };
    let mut options = Options::default();
    while let Some(name) = next_string(&mut remaining) {
        let Some(arg) = next_string(&mut remaining) else {
            break;
        };
        // C evaluates atoi even for unknown options, but its result is unused.
        if name.eq_ignore_ascii_case(b"blksize") && !no_block_size {
            let mut value = (option_number(arg) as usize)
                .max(1)
                .min(packet_buffer_size - 4);
            if let Some(mtu) = mtu.filter(|&v| v != 0) {
                let overhead = if ipv6 { 52 } else { 32 };
                value = value.min(mtu.wrapping_sub(overhead) as usize);
            }
            // A pathological configured MTU can make C divide by/use zero.
            if value == 0 {
                return Err(RequestError::InvalidBufferSize);
            }
            options.block_size = value;
            options.send_block_size = true;
        } else if name.eq_ignore_ascii_case(b"tsize") && mode == Mode::Octet {
            options.send_transfer_size = true;
        } else if name.eq_ignore_ascii_case(b"timeout") {
            options.timeout = option_number(arg).min(255);
            options.send_timeout = true;
        } else if name.eq_ignore_ascii_case(b"windowsize") && mode == Mode::Octet {
            options.window_size = option_number(arg).clamp(1, MAX_WINDOW);
            options.send_window_size = true;
        }
    }
    Ok(Some(ReadRequest {
        filename,
        mode,
        options,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetasciiBlock {
    pub len: usize,
    pub expansion: usize,
    pub carry_lf: bool,
}

/// Same bytes and continuation state as C `get_block()` lines 993–1022.
///
/// Input is at most one block of raw file bytes. `output.len()` is blocksize.
/// Each input byte is visited once, replacing C's repeated suffix memmove
/// (quadratic for newline-heavy blocks) with bounded linear output writes.
/// Like C, only LF is expanded; bare CR is not converted to CR-NUL.
pub fn encode_netascii(input: &[u8], last_carry_lf: bool, output: &mut [u8]) -> NetasciiBlock {
    let mut result = NetasciiBlock {
        len: 0,
        expansion: 0,
        carry_lf: false,
    };
    for (index, &byte) in input.iter().take(output.len()).enumerate() {
        if result.len == output.len() {
            break;
        }
        if byte == b'\n' && !(index == 0 && last_carry_lf) {
            output[result.len] = b'\r';
            result.len += 1;
            result.expansion += 1;
            if result.len == output.len() {
                result.carry_lf = true;
                break;
            }
        }
        output[result.len] = byte;
        result.len += 1;
    }
    result
}

/// Bounded linear in-place variant for the shared packet buffer. Sparse text
/// moves at most 64 suffixes. After that, the remaining dense suffix is expanded
/// backwards in two passes. Ordinary text needs no classification pass.
/// No extra block-sized buffer is needed in either path.
/// `input_len` raw bytes have already been read into `buffer` (the DATA body).
pub fn encode_netascii_in_place(
    buffer: &mut [u8],
    input_len: usize,
    last_carry_lf: bool,
) -> Result<NetasciiBlock, RequestError> {
    if input_len > buffer.len() {
        return Err(RequestError::InvalidBufferSize);
    }
    // With a constant cap this remains O(B), including the suffix moves. It
    // preserves C's efficient memmove path for ordinary short lines, avoiding
    // the first candidate's scalar reverse pass over every ordinary byte.
    let mut result = NetasciiBlock {
        len: input_len,
        expansion: 0,
        carry_lf: false,
    };
    let mut position = usize::from(last_carry_lf && input_len != 0);
    while position < result.len {
        if result.expansion == 64 {
            let suffix = encode_dense(&mut buffer[position..], result.len - position, false);
            result.len = position + suffix.len;
            result.expansion += suffix.expansion;
            result.carry_lf = suffix.carry_lf;
            return Ok(result);
        }
        let Some(skip) = buffer[position..result.len]
            .iter()
            .position(|&b| b == b'\n')
        else {
            break;
        };
        position += skip;
        result.expansion += 1;
        if result.len < buffer.len() {
            result.len += 1;
        } else if position == result.len - 1 {
            result.carry_lf = true;
        }
        buffer.copy_within(position..result.len - 1, position + 1);
        buffer[position] = b'\r';
        position += 2;
    }
    Ok(result)
}

fn encode_dense(buffer: &mut [u8], input_len: usize, last_carry_lf: bool) -> NetasciiBlock {
    let mut result = NetasciiBlock {
        len: 0,
        expansion: 0,
        carry_lf: false,
    };
    let mut consumed = 0;
    for (index, &byte) in buffer[..input_len].iter().enumerate() {
        if result.len == buffer.len() {
            break;
        }
        consumed = index + 1;
        if byte == b'\n' && !(index == 0 && last_carry_lf) {
            result.expansion += 1;
            result.len += 1;
            if result.len == buffer.len() {
                result.carry_lf = true;
                break;
            }
        }
        result.len += 1;
    }
    if result.expansion != 0 {
        let mut destination = result.len;
        for index in (0..consumed).rev() {
            let byte = buffer[index];
            if result.carry_lf && index == consumed - 1 {
                destination -= 1;
                buffer[destination] = b'\r';
            } else {
                destination -= 1;
                buffer[destination] = byte;
                if byte == b'\n' && !(index == 0 && last_carry_lf) {
                    destination -= 1;
                    buffer[destination] = b'\r';
                }
            }
        }
    }
    result
}

/// ACK/retransmit state, using caller-supplied seconds for deterministic tests.
/// A packet can affect state only after the service has checked its source TID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transfer {
    pub options: Options,
    pub mode: Mode,
    pub block: u32,
    pub next_ack: u32,
    pub offset: u64,
    pub retransmit_at: u64,
    pub active_since: u64,
    pub failed: bool,
    pub last_carry_lf: bool,
    pub expansion: usize,
    pub carry_lf: bool,
    block_high: u16,
    previous_ack: u16,
    backoff: u8,
}

impl Transfer {
    pub fn new(options: Options, mode: Mode, now: u64) -> Self {
        let block = u32::from(!options.needs_ack());
        Self {
            options,
            mode,
            block,
            next_ack: block,
            offset: 0,
            retransmit_at: now.saturating_add(u64::from(options.timeout)),
            active_since: now,
            failed: false,
            last_carry_lf: false,
            expansion: 0,
            carry_lf: false,
            block_high: 0,
            previous_ack: 0,
            backoff: 1,
        }
    }

    /// C changes wrap-tracking even for rejected ACKs. Preserve this ordering.
    pub fn receive(&mut self, packet: &[u8], now: u64) -> bool {
        if packet.len() < 4 {
            return false;
        }
        match u16::from_be_bytes([packet[0], packet[1]]) {
            4 => {
                let new = u16::from_be_bytes([packet[2], packet[3]]);
                if new <= 0x4000 && self.previous_ack >= 0xc000 {
                    self.block_high = self.block_high.wrapping_add(1);
                } else if new >= 0xc000 && self.previous_ack <= 0x4000 && self.block_high != 0 {
                    self.block_high -= 1;
                }
                self.previous_ack = new;
                let block = (u32::from(self.block_high) << 16) | u32::from(new);
                if block < self.next_ack || block > self.block {
                    return false;
                }
                self.retransmit_at = now;
                self.active_since = now;
                self.backoff = 0;
                self.next_ack = block.wrapping_add(1);
                if self.mode == Mode::Netascii && block != 0 {
                    self.offset += (self.options.block_size - self.expansion) as u64;
                    self.last_carry_lf = self.carry_lf;
                }
                true
            }
            5 => {
                self.failed = true;
                true
            }
            _ => false,
        }
    }

    pub fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.active_since) > TRANSFER_TIMEOUT
    }

    /// Returns the number of blocks to transmit, at most 32; the caller emits
    /// each block and increments `block`, stopping on EOF/error like C.
    pub fn begin_window(&mut self, now: u64) -> Option<u32> {
        if self.failed || self.expired(now) || now < self.retransmit_at {
            return None;
        }
        let delay = 1u64
            .checked_shl(u32::from(self.backoff / 2))
            .unwrap_or(u64::MAX);
        self.retransmit_at = self
            .retransmit_at
            .saturating_add(u64::from(self.options.timeout))
            .saturating_add(delay);
        self.backoff = self.backoff.saturating_add(1);
        self.block = self.next_ack;
        Some(if self.block == 0 {
            1
        } else {
            self.options.window_size
        })
    }

    /// C sends an empty DATA block when offset == file size, completing only
    /// after its ACK. That matters for exact multiples and empty files.
    pub fn file_offset(&self, size: u64) -> Option<u64> {
        if self.block == 0 {
            return None;
        }
        let offset = if self.mode == Mode::Netascii {
            self.offset
        } else {
            u64::from(self.block - 1) * self.options.block_size as u64
        };
        (offset <= size).then_some(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_options_match_image_musl_wrapping() {
        for (input, expected) in [
            (&b"2147483648"[..], 0x8000_0000),
            (&b"4294967296"[..], 0),
            (&b"4294967297"[..], 1),
            (&b"9223372036854775808"[..], 0),
            (&b"10000000000000000000000000000000000000000"[..], 0),
            (
                &b"99999999999999999999999999999999999999990"[..],
                0xffff_fff6,
            ),
            (&b"-2147483649"[..], 0x7fff_ffff),
            (&b"-4294967296"[..], 0),
            (&b"+4294967297tail"[..], 1),
            (&b" \t+4294967298x"[..], 2),
            (&b"\x0b\x0c\r\n+4294967298x"[..], 2),
            (&b"--1"[..], 0),
            (&b"abc"[..], 0),
            (&b"-1"[..], u32::MAX),
        ] {
            assert_eq!(option_number(input), expected, "input={input:?}");
        }
    }

    #[test]
    fn option_negotiation_preserves_c_bounds_and_order() {
        let r = parse_request(
            b"\0\x01file\0OCTET\0windowsize\x0099\0timeout\0-1\0blksize\x001468\0tsize\x000\0",
            4096,
            Some(1500),
            true,
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.options.block_size, 1448);
        assert_eq!(r.options.window_size, 32);
        assert_eq!(r.options.timeout, 255);
        let mut answer = Vec::new();
        r.options.write_ack(123, &mut answer);
        assert_eq!(
            answer,
            b"\0\x06blksize\x001448\0tsize\x00123\0timeout\x00255\0windowsize\x0032\0"
        );
    }

    #[test]
    fn partial_options_and_netascii_ignored_options() {
        let r = parse_request(
            b"\0\x01f\0netascii\0tsize\x000\0windowsize\x0032\0blksize\0",
            4096,
            None,
            false,
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.options, Options::default());
        assert_eq!(
            parse_request(b"\0\x02", 4096, None, false, false),
            Err(RequestError::WriteUnsupported)
        );
        assert_eq!(parse_request(b"\0\x09", 4096, None, false, false), Ok(None));
    }

    #[test]
    fn netascii_carries_newline_without_reexpanding() {
        let mut out = [0; 4];
        let first = encode_netascii(b"ab\nX", false, &mut out);
        assert_eq!(&out, b"ab\r\n");
        assert_eq!(
            first,
            NetasciiBlock {
                len: 4,
                expansion: 1,
                carry_lf: false
            }
        );
        let second = encode_netascii(b"abc\n", false, &mut out);
        assert_eq!(&out, b"abc\r");
        assert_eq!(
            second,
            NetasciiBlock {
                len: 4,
                expansion: 1,
                carry_lf: true
            }
        );
        let third = encode_netascii(b"\nX\r", true, &mut out);
        assert_eq!(&out[..third.len], b"\nX\r");
        assert_eq!(third.expansion, 0);
    }

    #[test]
    fn duplicate_ack_and_empty_final_block() {
        let mut transfer = Transfer::new(Options::default(), Mode::Octet, 10);
        assert!(!transfer.receive(&[0, 4, 0, 2], 11));
        assert!(transfer.receive(&[0, 4, 0, 1], 11));
        assert!(!transfer.receive(&[0, 4, 0, 1], 12));
        assert_eq!(transfer.begin_window(11), Some(1));
        assert_eq!(transfer.file_offset(512), Some(512));
        transfer.block += 1;
        assert!(transfer.receive(&[0, 4, 0, 2], 12));
        assert_eq!(transfer.begin_window(12), Some(1));
        assert_eq!(transfer.file_offset(512), None);
        assert!(!transfer.expired(132));
        assert!(transfer.expired(133));
    }

    #[test]
    fn block_wrap_and_delayed_old_ack() {
        let mut transfer = Transfer::new(Options::default(), Mode::Octet, 1);
        transfer.block = 65535;
        transfer.next_ack = 65535;
        transfer.previous_ack = 65534;
        assert!(transfer.receive(&[0, 4, 255, 255], 2));
        transfer.block = 65536;
        assert!(transfer.receive(&[0, 4, 0, 0], 3));
        assert!(!transfer.receive(&[0, 4, 255, 255], 4));
        transfer.block = 65537;
        assert!(transfer.receive(&[0, 4, 0, 1], 5));
    }
}

//! RR names from the matching dnsmasq 2.93 cache.c::typestr table.
//! Keep the source spelling (including NSAP_PTR); option.c uses this table
//! case-insensitively after trying a decimal integer.

use super::Error;

pub(crate) fn name(kind: u16) -> Option<&'static [u8]> {
    TYPES
        .iter()
        .find_map(|(name, value)| (*value == kind).then_some(*name))
}

pub(super) fn parse(bytes: &[u8]) -> Result<u16, Error> {
    if bytes.iter().all(u8::is_ascii_digit) {
        // numeric_check accepts empty input. The image's musl atoi wraps
        // to signed int before rrlist stores the low unsigned-short bits.
        let value = bytes.iter().fold(0u32, |value, digit| {
            value
                .wrapping_mul(10)
                .wrapping_add(u32::from(*digit - b'0'))
        });
        return Ok(value as u16);
    }
    TYPES
        .iter()
        .find_map(|(name, kind)| name.eq_ignore_ascii_case(bytes).then_some(*kind))
        .ok_or(Error("bad RR type"))
}

const TYPES: &[(&[u8], u16)] = &[
    (b"A", 1),
    (b"NS", 2),
    (b"MD", 3),
    (b"MF", 4),
    (b"CNAME", 5),
    (b"SOA", 6),
    (b"MB", 7),
    (b"MG", 8),
    (b"MR", 9),
    (b"NULL", 10),
    (b"WKS", 11),
    (b"PTR", 12),
    (b"HINFO", 13),
    (b"MINFO", 14),
    (b"MX", 15),
    (b"TXT", 16),
    (b"RP", 17),
    (b"AFSDB", 18),
    (b"X25", 19),
    (b"ISDN", 20),
    (b"RT", 21),
    (b"NSAP", 22),
    (b"NSAP_PTR", 23),
    (b"SIG", 24),
    (b"KEY", 25),
    (b"PX", 26),
    (b"GPOS", 27),
    (b"AAAA", 28),
    (b"LOC", 29),
    (b"NXT", 30),
    (b"EID", 31),
    (b"NIMLOC", 32),
    (b"SRV", 33),
    (b"ATMA", 34),
    (b"NAPTR", 35),
    (b"KX", 36),
    (b"CERT", 37),
    (b"A6", 38),
    (b"DNAME", 39),
    (b"SINK", 40),
    (b"OPT", 41),
    (b"APL", 42),
    (b"DS", 43),
    (b"SSHFP", 44),
    (b"IPSECKEY", 45),
    (b"RRSIG", 46),
    (b"NSEC", 47),
    (b"DNSKEY", 48),
    (b"DHCID", 49),
    (b"NSEC3", 50),
    (b"NSEC3PARAM", 51),
    (b"TLSA", 52),
    (b"SMIMEA", 53),
    (b"HIP", 55),
    (b"NINFO", 56),
    (b"RKEY", 57),
    (b"TALINK", 58),
    (b"CDS", 59),
    (b"CDNSKEY", 60),
    (b"OPENPGPKEY", 61),
    (b"CSYNC", 62),
    (b"ZONEMD", 63),
    (b"SVCB", 64),
    (b"HTTPS", 65),
    (b"DSYNC", 66),
    (b"HHIT", 67),
    (b"BRID", 68),
    (b"SPF", 99),
    (b"UINFO", 100),
    (b"UID", 101),
    (b"GID", 102),
    (b"UNSPEC", 103),
    (b"NID", 104),
    (b"L32", 105),
    (b"L64", 106),
    (b"LP", 107),
    (b"EUI48", 108),
    (b"EUI64", 109),
    (b"NXNAME", 128),
    (b"TKEY", 249),
    (b"TSIG", 250),
    (b"IXFR", 251),
    (b"AXFR", 252),
    (b"MAILB", 253),
    (b"MAILA", 254),
    (b"ANY", 255),
    (b"URI", 256),
    (b"CAA", 257),
    (b"AVC", 258),
    (b"DOA", 259),
    (b"AMTRELAY", 260),
    (b"RESINFO", 261),
    (b"WALLET", 262),
    (b"CLA", 263),
    (b"IPN", 264),
    (b"TA", 32768),
    (b"DLV", 32769),
];

//! MD5 (RFC 1321) for the baseline digests.  BusyBox `md5sum` produced them
//! before; computing them in-process keeps `/var/run/config.md5`
//! interchangeable byte for byte (the r1 differential compares the file) and
//! removes the one remaining child of an unchanged round.

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

fn block(state: &mut [u32; 4], chunk: &[u8]) {
    let mut m = [0u32; 16];
    for (word, bytes) in m.iter_mut().zip(chunk.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    let [mut a, mut b, mut c, mut d] = *state;
    for i in 0..64 {
        let (f, g) = match i / 16 {
            0 => ((b & c) | (!b & d), i),
            1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            2 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let rotated = a
            .wrapping_add(f)
            .wrapping_add(K[i])
            .wrapping_add(m[g])
            .rotate_left(S[i]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(rotated);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// The 16-byte digest of `data`.
pub fn digest(data: &[u8]) -> [u8; 16] {
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let (blocks, rest) = data.as_chunks::<64>();
    for chunk in blocks {
        block(&mut state, chunk);
    }
    // padding: 0x80, zeros to 56 mod 64, then the bit length little-endian
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let padded = if rest.len() < 56 { 64 } else { 128 };
    tail[padded - 8..padded].copy_from_slice(&((data.len() as u64).wrapping_mul(8)).to_le_bytes());
    for chunk in tail[..padded].as_chunks::<64>().0 {
        block(&mut state, chunk);
    }
    let mut out = [0u8; 16];
    for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *bytes = word.to_le_bytes();
    }
    out
}

/// Lower-case hex, the way `md5sum` prints it.
pub fn hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for byte in digest(data) {
        s.push(DIGITS[(byte >> 4) as usize] as char);
        s.push(DIGITS[(byte & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::hex;

    #[test]
    fn rfc_1321_vectors() {
        assert_eq!(hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hex(b"message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
        assert_eq!(
            hex(b"abcdefghijklmnopqrstuvwxyz"),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
        assert_eq!(
            hex(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    /// Lengths around the block and padding boundaries (55, 56, 63, 64, 65
    /// bytes) against digests computed by the reference implementation.
    #[test]
    fn padding_boundaries() {
        let cases: [(usize, &str); 5] = [
            (55, "0d7ae056b2f015cd7dc67494efd658f1"),
            (56, "31fcfb5165169eb55898e7e4cf34d19a"),
            (63, "1b30c0670c15e7da3c2ba7bce77ebe99"),
            (64, "a2eaf6295c32adc403865fd96a2f182b"),
            (65, "eba2cce0ca8df47e62414a736b3105a2"),
        ];
        for (len, expected) in cases {
            let data: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
            assert_eq!(hex(&data), expected, "len {len}");
        }
    }
}

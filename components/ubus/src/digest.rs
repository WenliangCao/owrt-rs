//! RFC 1321 digest used by procd change detection and rpcd file.md5.
//! This compatibility primitive is not used for authentication.
use std::io::{self, Read};

/// RFC 1321 MD5 over an in-memory slice.
pub fn md5(input: &[u8]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(input);
    digest.finish()
}

/// Hash a reader with fixed memory; interrupted reads are retried.
pub fn md5_reader(reader: &mut impl Read) -> io::Result<[u8; 16]> {
    let mut digest = Md5::new();
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(digest.finish()),
            Ok(n) => digest.update(&buffer[..n]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

struct Md5 {
    state: [u32; 4],
    block: [u8; 64],
    used: usize,
    bit_len: u64,
    k: [u32; 64],
}

impl Md5 {
    fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            block: [0; 64],
            used: 0,
            bit_len: 0,
            k: core::array::from_fn(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32),
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.bit_len = self
            .bit_len
            .wrapping_add((input.len() as u64).wrapping_mul(8));
        if self.used != 0 {
            let n = (64 - self.used).min(input.len());
            self.block[self.used..self.used + n].copy_from_slice(&input[..n]);
            self.used += n;
            input = &input[n..];
            if self.used < 64 {
                return;
            }
            let block = self.block;
            self.compress(&block);
            self.used = 0;
        }
        let (blocks, tail) = input.as_chunks::<64>();
        for block in blocks {
            self.compress(block);
        }
        self.block[..tail.len()].copy_from_slice(tail);
        self.used = tail.len();
    }

    fn finish(mut self) -> [u8; 16] {
        self.block[self.used] = 0x80;
        self.block[self.used + 1..].fill(0);
        if self.used >= 56 {
            let block = self.block;
            self.compress(&block);
            self.block = [0; 64];
        }
        self.block[56..].copy_from_slice(&self.bit_len.to_le_bytes());
        let block = self.block;
        self.compress(&block);
        let mut out = [0; 16];
        for (slot, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            slot.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn compress(&mut self, chunk: &[u8; 64]) {
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        let [mut a0, mut b0, mut c0, mut d0] = self.state;
        let m: [u32; 16] = core::array::from_fn(|i| {
            u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ])
        });
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for (i, shift) in S.into_iter().enumerate() {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(self.k[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(shift));
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
        self.state = [a0, b0, c0, d0];
    }
}
#[cfg(test)]
mod tests {
    use super::md5;

    #[test]
    fn md5_matches_the_rfc_vectors() {
        let hex = |d: [u8; 16]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex(md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            hex(md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn streaming_padding_boundaries_and_short_reads() {
        use std::io::{self, Read};
        struct ShortReads<'a>(&'a [u8], usize);
        impl Read for ShortReads<'_> {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                let n = output.len().min(self.0.len()).min(self.1);
                output[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        // Independent Python hashlib reference values, data[i] = i % 251.
        for (len, expected) in [
            (0, "d41d8cd98f00b204e9800998ecf8427e"),
            (1, "93b885adfe0da089cdf634904fd59f71"),
            (55, "6912ee65fff2d9f9ce2508cddf8bcda0"),
            (56, "51fdd1acda72405dfdfa03fcb85896d7"),
            (63, "48a6295221902e8e0938f773a7185e72"),
            (64, "b2d3f56bc197fd985d5965079b5e7148"),
            (65, "8bd7053801c768420faf816fadba971c"),
            (127, "8402b21e7bc7906493bae0dac017f1f9"),
            (128, "37eff01866ba3f538421b30b7cbefcac"),
            (129, "46f986692847558fc38b0cece591c20f"),
            (8191, "7f2ec389f48edf255a5841b7aa2506c4"),
            (8192, "5756928d3feb9c830c61f92b56416d95"),
            (8193, "d70940b0f2d0a8ac92655d222ce0ecd5"),
            (65537, "4c2641c7fe5c93d3aed7c406629ff0ab"),
        ] {
            let input: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
            let hex = |d: [u8; 16]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
            assert_eq!(hex(super::md5(&input)), expected);
            for chunk in [1, 7, 63, 64, 65, 8192] {
                assert_eq!(
                    hex(super::md5_reader(&mut ShortReads(&input, chunk)).unwrap()),
                    expected,
                    "len={len}, chunk={chunk}"
                );
            }
        }
    }

    #[test]
    fn reader_retries_interruption_and_propagates_failure() {
        use std::io::{self, Read};
        struct Reader(usize, bool);
        impl Read for Reader {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                match self.0 {
                    1 => Err(io::ErrorKind::Interrupted.into()),
                    2 => {
                        output[..3].copy_from_slice(b"abc");
                        Ok(3)
                    }
                    _ if self.1 => Err(io::ErrorKind::PermissionDenied.into()),
                    _ => Ok(0),
                }
            }
        }
        assert_eq!(
            super::md5_reader(&mut Reader(0, false)).unwrap(),
            super::md5(b"abc")
        );
        assert_eq!(
            super::md5_reader(&mut Reader(0, true)).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}

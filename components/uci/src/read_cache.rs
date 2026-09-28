//! Bounded reuse of a base file's parse, validated by rereading all its bytes.
//! Paths, access decisions, file locks and delta files are never cached.

use crate::context::{Context, FLAG_STRICT};
use crate::model::{OptionValue, Package};
use crate::{parse, Result};
use std::io::{self, BufRead, Read};

const INPUT_LIMIT: usize = 32 * 1024;
const ENTRY_LIMIT: usize = 128 * 1024;

struct Entry {
    bytes: Vec<u8>,
    flags: u32,
    name: String,
    package: Option<Package>,
    retained_bytes: usize,
}

/// One successful strict base-file parse, plus a bounded read buffer.
///
/// A parse is retained only after two consecutive reads of identical bytes,
/// avoiding model copies for cold or alternating files. A hit requires the
/// same package name, flags and complete current bytes.
/// The caller receives an independent model; current deltas are applied later.
/// The base entry and a returned working model together retain at most
/// 128 KiB of input/model capacities, and scratch
/// for at most 32 KiB. Allocator bookkeeping is additional to these bounds.
#[derive(Default)]
pub struct ReadCache {
    entry: Option<Entry>,
    scratch: Vec<u8>,
    spare: Option<Package>,
}

/// Replay prefetched bytes and any read error exactly once before continuing
/// the original buffered stream. Failed or oversized reads use the parser.
struct Replay<'a> {
    prefix: &'a [u8],
    eof: bool,
    error: Option<io::Error>,
    reader: &'a mut dyn BufRead,
}

impl Read for Replay<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() { return Ok(0); }
        let bytes = self.fill_buf()?;
        let n = output.len().min(bytes.len());
        output[..n].copy_from_slice(&bytes[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Replay<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if !self.prefix.is_empty() {
            return Ok(self.prefix);
        }
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        if self.eof { return Ok(&[]); }
        self.reader.fill_buf()
    }

    fn consume(&mut self, n: usize) {
        if self.prefix.is_empty() {
            self.reader.consume(n);
        } else {
            self.prefix = &self.prefix[n..];
        }
    }
}

fn model_bytes(p: &Package) -> usize {
    let mut bytes = std::mem::size_of::<Package>() + p.name.capacity()
        + p.sections.capacity() * std::mem::size_of::<crate::Section>();
    for s in &p.sections {
        bytes += s.name.capacity() + s.ty.capacity()
            + s.options.capacity() * std::mem::size_of::<crate::Opt>();
        for o in &s.options {
            bytes += o.name.capacity();
            match &o.value {
                OptionValue::Str(s) => bytes += if s.len() > 15 { s.len() } else { 0 },
                OptionValue::List(items) => {
                    bytes += items.capacity() * std::mem::size_of::<crate::model::Bytes>();
                    bytes += items.iter().filter(|s| s.len() > 15).map(|s| s.len()).sum::<usize>();
                }
            }
        }
    }
    bytes
}

// A recycled result may contain another session's deltas. Overwrite every
// model field from the validated base before any current delta is replayed.
fn reuse_model(target: &mut Package, source: &Package) {
    target.name.clone_from(&source.name);
    target.has_delta = source.has_delta;
    target.uses_conf2 = source.uses_conf2;
    target.path.clone_from(&source.path);
    target.n_section = source.n_section;
    target.delta.clone_from(&source.delta);
    target.saved_delta.clone_from(&source.saved_delta);
    target.sections.resize_with(source.sections.len(), || crate::Section {
        name: String::new(), ty: String::new(), anonymous: false, options: Vec::new(),
    });
    for (dst, src) in target.sections.iter_mut().zip(&source.sections) {
        dst.name.clone_from(&src.name);
        dst.ty.clone_from(&src.ty);
        dst.anonymous = src.anonymous;
        dst.options.resize_with(src.options.len(), || crate::Opt {
            name: String::new(), value: OptionValue::Str(Default::default()),
        });
        for (dst, src) in dst.options.iter_mut().zip(&src.options) {
            dst.name.clone_from(&src.name);
            match (&mut dst.value, &src.value) {
                (OptionValue::Str(dst), OptionValue::Str(src)) => dst.clone_from(src),
                (OptionValue::List(dst), OptionValue::List(src)) => dst.clone_from(src),
                _ => dst.value = src.value.clone(),
            }
        }
    }
}

impl ReadCache {
    /// Return an owned result for allocation reuse on the next identical base
    /// read. Its contents are never authoritative: every field is overwritten
    /// before the next caller's current delta chain is applied.
    pub fn recycle(&mut self, mut package: Package) {
        self.spare = None;
        let Some(entry) = &self.entry else { return };
        if entry.package.is_none() { return; }
        package.path = None;
        package.delta = Vec::new();
        package.saved_delta = Vec::new();
        if entry.retained_bytes + model_bytes(&package) <= ENTRY_LIMIT
        {
            self.spare = Some(package);
        }
    }

    pub(crate) fn import(&mut self, ctx: &mut Context, reader: &mut dyn BufRead, name: &str) -> Result<Option<usize>> {
        // Non-strict parsing may succeed after emitting errors. Preserve all
        // those side effects, and existing-package/duplicate handling too.
        if !ctx.root.is_empty() || ctx.flags & FLAG_STRICT == 0 {
            return parse::import(ctx, reader, Some(name), None, true);
        }
        let mut input = std::mem::take(&mut self.scratch);
        input.clear();
        let mut eof = false;
        let mut error = None;
        loop {
            let available = match reader.fill_buf() {
                Ok(bytes) => bytes,
                Err(e) => { error = Some(e); break; }
            };
            if available.is_empty() { eof = true; break; }
            let n = available.len().min(INPUT_LIMIT - input.len());
            if n == 0 { break; }
            let needed = input.len() + n;
            if input.capacity() < needed {
                input.reserve_exact(needed.next_power_of_two() - input.len());
            }
            input.extend_from_slice(&available[..n]);
            reader.consume(n);
        }
        let repeated = eof && self.entry.as_ref().is_some_and(|entry| {
            entry.flags == ctx.flags && entry.name == name && entry.bytes == input
        });
        if repeated {
            if let Some(entry) = &self.entry {
                if let Some(package) = &entry.package {
                    ctx.cleanup();
                    let package = match self.spare.take() {
                        Some(mut spare) => { reuse_model(&mut spare, package); spare }
                        None => package.clone(),
                    };
                    ctx.root.push(package);
                    self.scratch = input;
                    return Ok(Some(0));
                }
            }
        }
        self.spare = None;
        let mut replay = Replay { prefix: &input, eof, error, reader };
        let result = parse::import(ctx, &mut replay, Some(name), None, true);
        // Only an unambiguous successful base parse can become an entry.
        let success = eof && result == Ok(Some(0)) && ctx.err.is_none()
            && input.capacity() + name.len() <= ENTRY_LIMIT;
        let package = (success && repeated
            && model_bytes(&ctx.root[0]) + input.capacity() + name.len() <= ENTRY_LIMIT)
            .then(|| ctx.root[0].clone());
        let mut spare = self.entry.take().map(|e| e.bytes).unwrap_or_default();
        if success {
            let retained_bytes = input.capacity() + name.len() + package.as_ref().map_or(0, model_bytes);
            self.entry = Some(Entry { bytes: input, flags: ctx.flags, name: name.to_owned(), package, retained_bytes });
            spare.clear();
            self.scratch = spare;
        } else {
            input.clear();
            self.scratch = input;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{FLAG_PERROR, ParseInfo};
    use crate::Error;
    use std::io::Cursor;

    type Observation = (Result<Option<usize>>, Vec<Package>, Option<Error>, Option<ParseInfo>);

    fn observe(cache: Option<&mut ReadCache>, input: &mut dyn BufRead, name: &str, flags: u32) -> Observation {
        let mut ctx = Context::new();
        ctx.flags = flags & !FLAG_PERROR;
        let result = match cache {
            Some(cache) => cache.import(&mut ctx, input, name),
            None => parse::import(&mut ctx, input, Some(name), None, true),
        };
        (result, ctx.root, ctx.err, ctx.pctx)
    }

    #[test]
    fn cached_parse_matches_live_bytes_names_flags_and_errors() {
        let mut cache = ReadCache::default();
        let mut cases: Vec<Vec<u8>> = vec![
            b"config example 'a'\noption value 'first'\nlist x one\nlist x two\n".to_vec(),
            b"config example 'a'\noption value 'other'\nlist x one\nlist x two\n".to_vec(),
            b"config example\noption value 'raw\xff'\n".to_vec(),
            b"config example a\noption value 'unterminated".to_vec(),
            b"config example a\ninvalid command\noption value after\n".to_vec(),
            b"config example a\noption value before\0 discarded\noption next yes\n".to_vec(),
            b"config example a\noption a one\\\n two\n".to_vec(),
            Vec::new(),
        ];
        cases.push(format!("config example a\noption big '{}'\n", "v".repeat(INPUT_LIMIT + 1)).into_bytes());
        for flags in [FLAG_STRICT, 0, FLAG_STRICT] {
            for name in ["one", "two", "bad/name"] {
                for input in &cases {
                    let expected = observe(None, &mut Cursor::new(input), name, flags);
                    for _ in 0..3 {
                        let actual = observe(Some(&mut cache), &mut Cursor::new(input), name, flags);
                        assert_eq!(actual, expected, "name={name} flags={flags} len={}", input.len());
                    }
                    assert!(cache.scratch.capacity() <= INPUT_LIMIT);
                    if let Some(entry) = &cache.entry {
                        assert!(entry.bytes.capacity() + entry.name.capacity()
                            + entry.package.as_ref().map_or(0, model_bytes)
                            + cache.spare.as_ref().map_or(0, model_bytes) <= ENTRY_LIMIT);
                    }
                }
            }
        }
    }

    #[test]
    fn caller_mutation_cannot_change_cached_base() {
        let bytes = b"config example a\noption value first\n";
        let mut cache = ReadCache::default();
        let expected = observe(None, &mut Cursor::new(bytes), "one", FLAG_STRICT);
        let mut first = observe(Some(&mut cache), &mut Cursor::new(bytes), "one", FLAG_STRICT);
        first.1[0].sections.clear();
        assert_eq!(observe(Some(&mut cache), &mut Cursor::new(bytes), "one", FLAG_STRICT), expected);
        assert!(cache.entry.as_ref().unwrap().package.is_some());
        assert_eq!(observe(Some(&mut cache), &mut Cursor::new(bytes), "one", FLAG_STRICT), expected);
    }

    struct ErrorOnce<'a> {
        bytes: &'a [u8],
        split: usize,
        pos: usize,
        kind: Option<io::ErrorKind>,
    }
    impl Read for ErrorOnce<'_> {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { unreachable!() }
    }
    impl BufRead for ErrorOnce<'_> {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.pos == self.split {
                if let Some(kind) = self.kind.take() { return Err(kind.into()); }
            }
            let end = if self.kind.is_some() { self.split } else { self.bytes.len() };
            Ok(&self.bytes[self.pos..end])
        }
        fn consume(&mut self, n: usize) { self.pos += n; }
    }

    #[test]
    fn prefetch_replays_interruptions_and_io_failures_at_the_same_byte() {
        let input = b"config example a\noption value 'first'\nlist x one\n";
        for split in 0..=input.len() {
            for kind in [io::ErrorKind::Interrupted, io::ErrorKind::Other] {
                let reader = || ErrorOnce { bytes: input, split, pos: 0, kind: Some(kind) };
                let expected = observe(None, &mut reader(), "one", FLAG_STRICT);
                let mut cache = ReadCache::default();
                observe(Some(&mut cache), &mut Cursor::new(input), "one", FLAG_STRICT);
                observe(Some(&mut cache), &mut Cursor::new(input), "one", FLAG_STRICT);
                assert!(cache.entry.as_ref().unwrap().package.is_some());
                let actual = observe(Some(&mut cache), &mut reader(), "one", FLAG_STRICT);
                assert_eq!(actual, expected, "split={split} kind={kind:?}");
                assert!(cache.entry.is_none());
            }
        }
    }

    #[test]
    fn recycled_models_are_bounded_and_overwritten_after_arbitrary_mutation() {
        let bytes = b"config example a\noption value 'long base scalar value'\nlist x one\nlist x two\n";
        let mut cache = ReadCache::default();
        for _ in 0..3 { observe(Some(&mut cache), &mut Cursor::new(bytes), "one", FLAG_STRICT).0.unwrap(); }
        let expected = observe(None, &mut Cursor::new(bytes), "one", FLAG_STRICT);
        let mut working = expected.1[0].clone();
        working.name = "another".to_owned();
        working.sections[0].options[0].value = OptionValue::List(vec!["different".into()]);
        working.sections[0].options[1].value = OptionValue::Str("different".into());
        working.n_section = 100;
        working.has_delta = true;
        working.uses_conf2 = true;
        working.path = Some("other/path".to_owned());
        cache.recycle(working);
        assert!(cache.spare.is_some());
        assert_eq!(observe(Some(&mut cache), &mut Cursor::new(bytes), "one", FLAG_STRICT), expected);
        let mut oversized = expected.1[0].clone();
        oversized.sections.reserve(ENTRY_LIMIT);
        cache.recycle(oversized);
        assert!(cache.spare.is_none());
        cache.recycle(expected.1[0].clone());
        assert!(cache.spare.is_some());
        assert!(observe(Some(&mut cache), &mut Cursor::new(b"invalid command\n"), "one", FLAG_STRICT).0.is_err());
        assert!(cache.entry.is_none());
        assert!(cache.spare.is_none());
    }

    #[test]
    fn model_capacity_limit_rejects_many_small_sections() {
        let bytes = "config x\n".repeat(2500).into_bytes();
        assert!(bytes.len() < INPUT_LIMIT);
        let mut cache = ReadCache::default();
        let expected = observe(None, &mut Cursor::new(&bytes), "one", FLAG_STRICT);
        assert_eq!(observe(Some(&mut cache), &mut Cursor::new(&bytes), "one", FLAG_STRICT), expected);
        assert_eq!(observe(Some(&mut cache), &mut Cursor::new(&bytes), "one", FLAG_STRICT), expected);
        assert!(cache.entry.as_ref().unwrap().package.is_none());
    }
}

//! Ring buffer with the same retention arithmetic as ubox logd (syslog.c):
//! a byte arena of `capacity`, each record occupying a 32-byte header plus
//! its NUL-terminated text padded to 4 bytes; writes wrap to offset 0 and
//! evict whatever they overwrite.
//!
//! Records live in the arena itself, as in C: adding a record allocates
//! nothing, and the retained set costs exactly `capacity` bytes plus a
//! 4-byte offset per record. The arena header is private (native endian);
//! records are read back through the borrowed `Record` view.

use std::collections::VecDeque;

pub const HEAD: usize = 32; // sizeof(struct log_head) on 64-bit
pub const LINE_SIZE: usize = 1024;

pub const SOURCE_KLOG: u32 = 0;
pub const SOURCE_SYSLOG: u32 = 1;

/// One stored record, borrowed from the arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub id: u32,
    pub priority: u32,
    pub source: u32,
    pub time_ms: u64,
    /// Message text followed by its NUL terminator, as stored (`size` bytes).
    pub text: &'a [u8],
}

impl Record<'_> {
    /// Message bytes without the terminator.
    #[cfg(test)]
    pub fn msg(&self) -> &[u8] {
        &self.text[..self.text.len() - 1]
    }

    /// `size` in C terms: text length including the NUL.
    pub fn size(&self) -> usize {
        self.text.len()
    }
}

pub struct Ring {
    arena: Vec<u8>,
    capacity: usize,
    /// Offsets of retained records, oldest first (ids wrap at u32::MAX).
    offsets: VecDeque<u32>,
    newest: usize,
    next_id: u32,
}

pub const fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

// header layout inside the arena
const H_SIZE: usize = 0;
const H_ID: usize = 4;
const H_PRIORITY: usize = 8;
const H_SOURCE: usize = 12;
const H_TIME: usize = 16;

impl Ring {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(HEAD + 4);
        Self {
            arena: vec![0u8; capacity],
            capacity,
            offsets: VecDeque::new(),
            newest: 0,
            next_id: 0,
        }
    }

    /// Retained record count.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// Largest `size` (text with NUL) a record can have in this arena. C has
    /// no such check and writes past its buffer; we truncate instead.
    fn max_size(&self) -> usize {
        (self.capacity - HEAD) & !3
    }

    fn log_next(&self, offset: usize, size: usize) -> usize {
        let next = offset + HEAD + pad4(size);
        if next >= self.capacity {
            0
        } else {
            next
        }
    }

    fn read_u32(&self, at: usize) -> u32 {
        u32::from_ne_bytes(self.arena[at..at + 4].try_into().unwrap())
    }

    fn record_at(&self, offset: usize) -> Record<'_> {
        let size = self.read_u32(offset + H_SIZE) as usize;
        Record {
            id: self.read_u32(offset + H_ID),
            priority: self.read_u32(offset + H_PRIORITY),
            source: self.read_u32(offset + H_SOURCE),
            time_ms: u64::from_ne_bytes(self.arena[offset + H_TIME..offset + H_TIME + 8].try_into().unwrap()),
            text: &self.arena[offset + HEAD..offset + HEAD + size],
        }
    }

    /// Store `msg` (already trimmed; may still contain LF, which is stored
    /// as a space like C log_add) and return the stored record.
    pub fn add(&mut self, msg: &[u8], priority: u32, source: u32, time_ms: u64) -> Record<'_> {
        let size = (msg.len() + 1).min(self.max_size());
        let next = self.log_next(self.newest, size);
        let write_at;
        if next > self.newest {
            let newest = self.newest;
            // `front == newest` only happens after a record filled the whole
            // arena (C overruns its buffer there); it is overwritten too.
            while let Some(&front) = self.offsets.front() {
                let front = front as usize;
                if front >= newest && front <= next {
                    self.offsets.pop_front();
                } else {
                    break;
                }
            }
            write_at = newest;
            self.newest = next;
        } else {
            // C wrap branch (syslog.c:195-206): the old write position becomes
            // a `size == 0` sentinel, the eviction walk restarts at `log` and
            // runs past `next`, and `newest` goes back to `log`. So a wrap
            // drops two groups, wherever they sit in the list: the records the
            // new record overwrites (offset <= next0), and everything from the
            // sentinel to the end of the arena -- log_list jumps from the
            // sentinel straight back to `log` (`if (!h->size && (h > newest))
            // h = log`, syslog.c:304-325), so those records are unreachable.
            // Popping only from the front instead keeps overwritten records
            // listed as soon as a lap wraps earlier than the one before it.
            let next0 = self.log_next(0, size);
            let sentinel = self.newest;
            self.offsets
                .retain(|&offset| (offset as usize) > next0 && (offset as usize) < sentinel);
            write_at = 0;
            self.newest = next0;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let header = &mut self.arena[write_at..write_at + HEAD];
        header[H_SIZE..H_SIZE + 4].copy_from_slice(&(size as u32).to_ne_bytes());
        header[H_ID..H_ID + 4].copy_from_slice(&id.to_ne_bytes());
        header[H_PRIORITY..H_PRIORITY + 4].copy_from_slice(&priority.to_ne_bytes());
        header[H_SOURCE..H_SOURCE + 4].copy_from_slice(&source.to_ne_bytes());
        header[H_TIME..H_TIME + 8].copy_from_slice(&time_ms.to_ne_bytes());
        let text = &mut self.arena[write_at + HEAD..write_at + HEAD + size];
        for (dst, &src) in text[..size - 1].iter_mut().zip(msg) {
            *dst = if src == b'\n' { b' ' } else { src };
        }
        text[size - 1] = 0;
        self.offsets.push_back(write_at as u32);
        self.record_at(write_at)
    }

    /// Entries with id >= min, oldest first, where `min` follows C log_list:
    /// `min = count ? (count < current_id ? current_id - count : 0) : 0`.
    /// `count` is signed. Compare each stored id, as C does: after the id
    /// wraps, matching records can be on both sides of a nonmatching record.
    /// Deriving a suffix from current_id and the retained count loses history.
    pub fn list(&self, count: i64) -> impl Iterator<Item = Record<'_>> + '_ {
        let cur = self.next_id as i64;
        let min = if count != 0 {
            if count < cur { cur - count } else { 0 }
        } else {
            0
        };
        self.offsets
            .iter()
            .map(move |&offset| self.record_at(offset as usize))
            .filter(move |record| i64::from(record.id) >= min)
    }
}

/// Apply logd's `log_add` normalization without copying: returns the
/// priority and the message slice of `raw` to store, or None when the record
/// must not be stored (facility LOCAL7). C first turns every LF into a
/// space, so the trailing-whitespace trim and the timestamp check below treat
/// LF as a space; `Ring::add` performs the replacement while copying.
pub fn normalize(raw: &[u8], source: u32) -> Option<(u32, &[u8])> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let mut bytes = &raw[..end];
    while bytes
        .last()
        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    let mut priority = 0u32;
    if bytes.first() == Some(&b'<') {
        // Find the closing delimiter and parse its decimal interior in one
        // pass. The old path scanned the same short prefix for `>`, digits,
        // and then `str::parse`.
        let mut parsed = 0u32;
        let mut valid = true;
        let mut overflow = false;
        let mut index = 1usize;
        while index < bytes.len() {
            let digit = bytes[index];
            if digit == b'>' {
                break;
            }
            if !digit.is_ascii_digit() {
                valid = false;
            } else if !overflow {
                let value = (digit - b'0') as u32;
                if parsed > 429_496_729 || (parsed == 429_496_729 && value > 5) {
                    overflow = true;
                } else {
                    parsed = parsed * 10 + value;
                }
            }
            index += 1;
        }
        if index < bytes.len() && bytes[index] == b'>' && valid {
            // Match `str::parse::<u32>()`: an out-of-range value becomes
            // zero, but the syntactically valid `<digits>` prefix is consumed.
            priority = if overflow { 0 } else { parsed };
            bytes = &bytes[index + 1..];
        }
    }
    // strip "Mmm dd hh:mm:ss " syslog timestamp
    if source == SOURCE_SYSLOG && bytes.len() > 15 && matches!(bytes[15], b' ' | b'\n') {
        bytes = &bytes[16..];
    }
    if priority & 0x3f8 == 23 << 3 {
        return None;
    }
    Some((priority, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(r: &mut Ring, msg: &str) -> u32 {
        r.add(msg.as_bytes(), 0, 1, 0).id
    }

    fn ids(r: &Ring, count: i64) -> Vec<u32> {
        r.list(count).map(|e| e.id).collect()
    }

    fn stored(raw: &[u8], source: u32) -> Option<(u32, Vec<u8>)> {
        let (priority, msg) = normalize(raw, source)?;
        let mut r = Ring::new(4096);
        let record = r.add(msg, priority, source, 0);
        Some((priority, record.msg().to_vec()))
    }

    #[test]
    fn normalize_strips_priority_timestamp_and_trailing_space() {
        let (p, m) = stored(b"<30>Sep  2 13:16:33 reload_config[1]: hello\n", SOURCE_SYSLOG).unwrap();
        assert_eq!(p, 30);
        assert_eq!(m, b"reload_config[1]: hello");
        let (p, m) = stored(b"<6>[  123.456] kernel line", SOURCE_KLOG).unwrap();
        assert_eq!(p, 6);
        assert_eq!(m, b"[  123.456] kernel line");
        assert_eq!(stored(b"plain", SOURCE_SYSLOG), Some((0, b"plain".to_vec())));
        assert!(stored(b"<191>debug local7", SOURCE_SYSLOG).is_none());
    }

    #[test]
    fn normalize_treats_lf_as_space_everywhere_like_log_add() {
        // LF in the timestamp slot counts as the separator space; inner LFs
        // are stored as spaces; a NUL ends the input; trailing LF is trimmed.
        assert_eq!(
            stored(b"<30>123456789012345\nhello\nworld\0ignored", SOURCE_SYSLOG),
            Some((30, b"hello world".to_vec()))
        );
        assert_eq!(
            stored(b"<30>\xff\xfe\n\x80 \t", SOURCE_SYSLOG),
            Some((30, vec![0xff, 0xfe, b' ', 0x80]))
        );
        assert_eq!(stored(b"<184>discard", SOURCE_SYSLOG), None);
        // Decimal syntax is consumed even when u32 conversion overflows;
        // malformed interiors remain part of the message.
        assert_eq!(stored(b"<4294967295>max", SOURCE_SYSLOG), Some((u32::MAX, b"max".to_vec())));
        assert_eq!(stored(b"<4294967296>overflow", SOURCE_SYSLOG), Some((0, b"overflow".to_vec())));
        assert_eq!(stored(b"<12x>malformed", SOURCE_SYSLOG), Some((0, b"<12x>malformed".to_vec())));
        for raw in [b"".as_slice(), b" \t\n", b"\0ignored", b"<0>", b"<>"] {
            let (_, bytes) = stored(raw, SOURCE_SYSLOG).unwrap();
            assert!(bytes.is_empty(), "{raw:?}");
        }
        // an unparsable priority keeps the whole text (no regex match in C)
        assert_eq!(stored(b"<1a>x", SOURCE_SYSLOG), Some((0, b"<1a>x".to_vec())));
        // kernel lines never lose a timestamp-shaped prefix
        assert_eq!(
            stored(b"<4>0123456789ABCDE rest", SOURCE_KLOG),
            Some((4, b"0123456789ABCDE rest".to_vec()))
        );
    }

    #[test]
    fn ring_evicts_like_logd() {
        // three 36-byte slots; logd wraps when the next write position would
        // reach the end, and the wrap evicts every record at offset <= next.
        let mut r = Ring::new(108);
        add(&mut r, "a"); // @0
        add(&mut r, "b"); // @36
        assert_eq!(r.len(), 2);
        add(&mut r, "c"); // would start @72 -> wrap to @0, next=36
        assert_eq!(ids(&r, 0), vec![2]);
        add(&mut r, "d"); // @36, no wrap
        assert_eq!(ids(&r, 0), vec![2, 3]);
        assert_eq!(ids(&r, 1), vec![3]);
        // C log_list: count 0 or >= current_id -> all; negative -> none.
        assert_eq!(ids(&r, 100), vec![2, 3]);
        assert_eq!(ids(&r, -1), Vec::<u32>::new());
        assert_eq!(r.list(0).map(|e| e.msg().to_vec()).collect::<Vec<_>>(), [b"c", b"d"]);
    }

    /// Bytes the retained records occupy in the arena: the 32-byte header plus
    /// the padded text, as in C log_next().
    fn retained_bytes(r: &Ring) -> usize {
        r.list(0).map(|e| HEAD + pad4(e.size())).sum()
    }

    #[test]
    fn wrap_with_abandoned_tail_entry_drops_overwritten_records() {
        // Mixed lengths make a lap wrap earlier than the one before it, so the
        // previous lap's tail is still retained at high offsets when the wrap
        // happens. C restarts the eviction walk at `log`, so the records the
        // wrapping write overwrites go away even though they are not at the
        // head of the list.
        let mut r = Ring::new(256);
        for m in ["aaa", "bbb", "ccc", "ddd", "eee", "fff", "ggg"] {
            add(&mut r, m); // ids 0..=6 at offsets 0,36,..,216; newest=252
        }
        add(&mut r, "hhh"); // id 7 wraps to @0 (evicts a,b); newest=36
        add(&mut r, "iii"); // id 8 @36 (evicts c)
        add(&mut r, "jjj"); // id 9 @72 (evicts d)
        add(&mut r, "kkk"); // id 10 @108 (evicts e); f@180, g@216 remain

        // 79-byte message, slot 112: 144+112 >= 256 -> wrap to [0,112), which
        // overwrites h,i,j,k
        r.add(&[b'm'; 79], 0, 1, 0); // id 11
        let ids = ids(&r, 0);
        for overwritten in 7..=10 {
            assert!(
                !ids.contains(&overwritten),
                "id {overwritten} was overwritten by the wrap write but is still listed: {ids:?}"
            );
        }
        assert!(
            retained_bytes(&r) <= 256,
            "retained {} bytes in a 256-byte ring: {ids:?}",
            retained_bytes(&r)
        );
    }

    #[test]
    fn mixed_sizes_never_retain_more_than_capacity() {
        // 16 KiB ring, 60-byte lines with an occasional 1000-byte line: the lap
        // that wraps on the long line leaves the previous lap's tail retained.
        let mut r = Ring::new(16 * 1024);
        for lap in 0..40 {
            for i in 0..200 {
                r.add(format!("lap {lap} line {i} {}", "x".repeat(40)).as_bytes(), 0, 1, 0);
                assert!(retained_bytes(&r) <= 16 * 1024, "lap {lap} line {i}");
            }
            r.add(&[b'L'; 1000], 0, 1, 0);
            assert!(retained_bytes(&r) <= 16 * 1024, "lap {lap} long line");
        }
    }

    #[test]
    fn retention_matches_the_c_oracle_on_mixed_lengths() {
        // Golden from upstream ubox 6f78fa49 log/syslog.c (log_add + log_list
        // extracted verbatim and driven with this same sequence, R83): a
        // 2 KiB ring, 35 records, every 7th one 200 bytes instead of 60, so
        // laps wrap at different offsets. C retains ids 21..=34; the front-only
        // eviction this test was written for also kept 17..=20, whose bytes the
        // wrapping writes had already overwritten.
        let mut r = Ring::new(2048);
        for i in 0..35 {
            let len = if i % 7 == 6 { 200 } else { 60 };
            r.add(format!("l{i}_{}", "x".repeat(len)).as_bytes(), 0, 1, 0);
        }
        assert_eq!(ids(&r, 0), (21..=34).collect::<Vec<u32>>());
        assert!(retained_bytes(&r) <= 2048, "{}", retained_bytes(&r));
    }

    #[test]
    fn list_window_equals_the_id_filter_and_records_survive_eviction_intact() {
        // The suffix arithmetic must agree with C's `id >= min` filter for
        // every count, including windows larger than the retained set.
        let mut r = Ring::new(4096);
        let mut expected: Vec<(u32, Vec<u8>)> = Vec::new();
        for i in 0..300u32 {
            let msg = format!("record {i} {}", "y".repeat(i as usize % 50));
            let rec = r.add(msg.as_bytes(), i % 8, i % 2, 1_000 + i as u64);
            assert_eq!((rec.id, rec.priority, rec.source, rec.time_ms), (i, i % 8, i % 2, 1_000 + i as u64));
            assert_eq!(rec.msg(), msg.as_bytes());
            expected.push((i, msg.into_bytes()));
        }
        let cur = 300i64;
        let retained: Vec<u32> = ids(&r, 0);
        let oldest = retained[0];
        assert_eq!(retained, (oldest..300).collect::<Vec<_>>(), "ids must stay contiguous");
        for count in [-5i64, -1, 0, 1, 2, 7, 50, 100, (cur - oldest as i64) - 1, cur - oldest as i64, cur - 1, cur, cur + 1, 10_000] {
            let min = if count != 0 { if count < cur { cur - count } else { 0 } } else { 0 };
            let reference: Vec<u32> = retained.iter().copied().filter(|&id| (id as i64) >= min).collect();
            assert_eq!(ids(&r, count), reference, "count {count}");
        }
        for rec in r.list(0) {
            let (id, msg) = &expected[rec.id as usize];
            assert_eq!(rec.id, *id);
            assert_eq!(rec.msg(), msg.as_slice());
            assert_eq!(rec.text.last(), Some(&0));
            assert_eq!(rec.time_ms, 1_000 + rec.id as u64);
        }
    }

    #[test]
    fn list_keeps_history_on_both_sides_of_id_wrap() {
        let mut r = Ring::new(4096);
        r.next_id = u32::MAX - 1;
        add(&mut r, "before a");
        add(&mut r, "before b");
        for count in [-1, 0, 1, 2] {
            assert_eq!(ids(&r, count), [u32::MAX - 1, u32::MAX], "count {count}");
        }
        add(&mut r, "after a");
        add(&mut r, "after b");
        assert_eq!(ids(&r, 0), [u32::MAX - 1, u32::MAX, 0, 1]);
        assert_eq!(ids(&r, 1), [u32::MAX - 1, u32::MAX, 1]);
        assert_eq!(ids(&r, -1), [u32::MAX - 1, u32::MAX]);
        assert_eq!(r.list(0).map(|record| record.msg().to_vec()).collect::<Vec<_>>(),
                   [b"before a".as_slice(), b"before b", b"after a", b"after b"]);
    }

    #[test]
    fn evicting_wrapped_history_restores_ordinary_count_windows() {
        let mut r = Ring::new(108);
        r.next_id = u32::MAX - 1;
        for message in ["a", "b", "c", "d"] {
            add(&mut r, message);
        }
        assert_eq!(ids(&r, 0), [0, 1]);
        assert_eq!(ids(&r, 1), [1]);
        assert!(ids(&r, -1).is_empty());
    }

    #[test]
    fn oversize_record_is_truncated_to_the_arena_instead_of_overflowing() {
        // C would write past its buffer here (undefined). A -S 1 ring holds
        // at most 992 text bytes per record; the message keeps its prefix and
        // the ring keeps exactly one record.
        let mut r = Ring::new(1024);
        let rec = r.add(&[b'z'; 1023], 3, 1, 9);
        assert_eq!(rec.size(), 992);
        assert_eq!(rec.msg().len(), 991);
        assert!(rec.msg().iter().all(|&b| b == b'z'));
        add(&mut r, "next");
        assert_eq!(ids(&r, 0), vec![1]);
        assert!(retained_bytes(&r) <= 1024);
    }

    #[test]
    fn stored_text_replaces_lf_and_preserves_arbitrary_bytes() {
        let mut r = Ring::new(4096);
        let rec = r.add(b"a\nb\xff\x00c", 0, 1, 0);
        // NUL inside the slice is the caller's business (normalize cuts it);
        // the ring stores what it is given, LF as space.
        assert_eq!(rec.msg(), b"a b\xff\x00c");
        assert_eq!(rec.text, b"a b\xff\x00c\0");
    }
}

//! Ring buffer with the same retention arithmetic as ubox logd (syslog.c):
//! a byte arena of `capacity`, each record occupying a 32-byte header plus
//! its NUL-terminated text padded to 4 bytes; writes wrap to offset 0 and
//! evict whatever they overwrite.

use std::collections::VecDeque;

const HEAD: usize = 32; // sizeof(struct log_head) on 64-bit
pub const LINE_SIZE: usize = 1024;

pub const SOURCE_KLOG: u32 = 0;
pub const SOURCE_SYSLOG: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    offset: usize,
    size: usize,
    pub id: u32,
    pub priority: u32,
    pub source: u32,
    pub time_ms: u64,
    pub msg: String,
}

pub struct Ring {
    capacity: usize,
    entries: VecDeque<Entry>,
    newest: usize,
    next_id: u32,
}

fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

impl Ring {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: VecDeque::new(),
            newest: 0,
            next_id: 0,
        }
    }

    fn log_next(&self, offset: usize, size: usize) -> usize {
        let next = offset + HEAD + pad4(size);
        if next >= self.capacity {
            0
        } else {
            next
        }
    }

    /// Store `msg` (already normalized); returns the stored entry.
    pub fn add(&mut self, msg: String, priority: u32, source: u32, time_ms: u64) -> Entry {
        let size = msg.len() + 1;
        let next = self.log_next(self.newest, size);
        let write_at;
        if next > self.newest {
            let newest = self.newest;
            while let Some(front) = self.entries.front() {
                if front.offset > newest && front.offset <= next {
                    self.entries.pop_front();
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
            self.entries
                .retain(|entry| entry.offset > next0 && entry.offset < sentinel);
            write_at = 0;
            self.newest = next0;
        }
        let entry = Entry {
            offset: write_at,
            size,
            id: self.next_id,
            priority,
            source,
            time_ms,
            msg,
        };
        self.next_id = self.next_id.wrapping_add(1);
        self.entries.push_back(entry.clone());
        entry
    }

    /// Entries with id >= min, oldest first, where `min` follows C log_list:
    /// `min = count ? (count < current_id ? current_id - count : 0) : 0`.
    /// `count` is signed: 0 or a value >= current_id yields all entries; a
    /// negative count yields none (min = current_id - count > current_id).
    pub fn list(&self, count: i64) -> impl Iterator<Item = &Entry> {
        let cur = self.next_id as i64;
        let min = if count != 0 {
            if count < cur { cur - count } else { 0 }
        } else {
            0
        };
        self.entries.iter().filter(move |e| (e.id as i64) >= min)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Apply logd's `log_add` normalization. Returns None when the record must
/// not be stored (facility LOCAL7).
pub fn normalize(raw: &[u8], source: u32) -> Option<(u32, String)> {
    let mut bytes: Vec<u8> = raw
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| if b == b'\n' { b' ' } else { b })
        .collect();
    while bytes
        .last()
        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
    {
        bytes.pop();
    }
    let mut priority = 0u32;
    if bytes.first() == Some(&b'<') {
        if let Some(close) = bytes.iter().position(|&b| b == b'>') {
            if bytes[1..close].iter().all(|b| b.is_ascii_digit()) {
                priority = std::str::from_utf8(&bytes[1..close])
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                bytes.drain(..=close);
            }
        }
    }
    // strip "Mmm dd hh:mm:ss " syslog timestamp
    if source == SOURCE_SYSLOG && bytes.len() > 15 && bytes[15] == b' ' {
        bytes.drain(..16);
    }
    if priority & 0x3f8 == 23 << 3 {
        return None;
    }
    Some((priority, String::from_utf8_lossy(&bytes).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_priority_timestamp_and_trailing_space() {
        let (p, m) = normalize(
            b"<30>Sep  2 13:16:33 reload_config[1]: hello\n",
            SOURCE_SYSLOG,
        )
        .unwrap();
        assert_eq!(p, 30);
        assert_eq!(m, "reload_config[1]: hello");
        let (p, m) = normalize(b"<6>[  123.456] kernel line", SOURCE_KLOG).unwrap();
        assert_eq!(p, 6);
        assert_eq!(m, "[  123.456] kernel line");
        assert_eq!(
            normalize(b"plain", SOURCE_SYSLOG),
            Some((0, "plain".into()))
        );
        assert!(normalize(b"<191>debug local7", SOURCE_SYSLOG).is_none());
    }

    #[test]
    fn ring_evicts_like_logd() {
        // three 36-byte slots; logd wraps when the next write position would
        // reach the end, and the wrap evicts every record at offset <= next.
        let mut r = Ring::new(108);
        r.add("a".into(), 0, 1, 0); // @0
        r.add("b".into(), 0, 1, 0); // @36
        assert_eq!(r.len(), 2);
        r.add("c".into(), 0, 1, 0); // would start @72 -> wrap to @0, next=36
        assert_eq!(r.list(0).map(|e| e.id).collect::<Vec<_>>(), vec![2]);
        r.add("d".into(), 0, 1, 0); // @36, no wrap
        assert_eq!(r.list(0).map(|e| e.id).collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(r.list(1).map(|e| e.id).collect::<Vec<_>>(), vec![3]);
        // C log_list: count 0 or >= current_id -> all; negative -> none.
        assert_eq!(r.list(100).map(|e| e.id).collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(r.list(-1).count(), 0);
    }

    /// Bytes the retained records occupy in the arena: the 32-byte header plus
    /// the padded text, as in C log_next().
    fn retained_bytes(r: &Ring) -> usize {
        r.list(0).map(|e| HEAD + pad4(e.msg.len() + 1)).sum()
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
            r.add(m.into(), 0, 1, 0); // ids 0..=6 at offsets 0,36,..,216; newest=252
        }
        r.add("hhh".into(), 0, 1, 0); // id 7 wraps to @0 (evicts a,b); newest=36
        r.add("iii".into(), 0, 1, 0); // id 8 @36 (evicts c)
        r.add("jjj".into(), 0, 1, 0); // id 9 @72 (evicts d)
        r.add("kkk".into(), 0, 1, 0); // id 10 @108 (evicts e); f@180, g@216 remain

        // 79-byte message, slot 112: 144+112 >= 256 -> wrap to [0,112), which
        // overwrites h,i,j,k
        r.add("m".repeat(79), 0, 1, 0); // id 11
        let ids: Vec<u32> = r.list(0).map(|e| e.id).collect();
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
                r.add(format!("lap {lap} line {i} {}", "x".repeat(40)), 0, 1, 0);
                assert!(retained_bytes(&r) <= 16 * 1024, "lap {lap} line {i}");
            }
            r.add("L".repeat(1000), 0, 1, 0);
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
            r.add(format!("l{i}_{}", "x".repeat(len)), 0, 1, 0);
        }
        assert_eq!(
            r.list(0).map(|e| e.id).collect::<Vec<_>>(),
            (21..=34).collect::<Vec<u32>>()
        );
        assert!(retained_bytes(&r) <= 2048, "{}", retained_bytes(&r));
    }
}

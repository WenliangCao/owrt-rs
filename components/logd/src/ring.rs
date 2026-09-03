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
            let next0 = self.log_next(0, size);
            while let Some(front) = self.entries.front() {
                if front.offset <= next0 {
                    self.entries.pop_front();
                } else {
                    break;
                }
            }
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
}

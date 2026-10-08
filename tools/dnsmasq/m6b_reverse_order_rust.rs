// Only appended to an ignored cfg(test) source copy. No production fields/API.
use super::*;
use std::cell::RefCell;
use std::io::Write as IoWrite;

thread_local! {
    static CONTEXT: RefCell<(String, usize, String, bool)> = RefCell::new((String::new(), 0, String::new(), false));
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    for byte in bytes { write!(text, "{byte:02x}").unwrap(); }
    text
}
fn quote(text: &str) -> String {
    assert!(text.bytes().all(|byte| (32..=126).contains(&byte)), "fixed ASCII primitive corpus required");
    format!("{text:?}")
}
fn emit(fields: String) {
    let Some(path) = std::env::var_os("DNSMASQ_REVERSE_ORDER_SIDECAR") else { return };
    CONTEXT.with(|context| {
        let context = context.borrow();
        let line = format!("{{\"owner\":{},\"command\":{},\"op\":{},{} }}\n",
            quote(&context.0), context.1, quote(&context.2), fields);
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
        file.write_all(line.as_bytes()).unwrap();
    });
}
pub(super) fn context(owner: &str, command: usize, op: &str) {
    CONTEXT.with(|state| *state.borrow_mut() = (owner.to_owned(), command, op.to_owned(), false));
}
pub(super) fn bucket(name: &Name, value: usize, mix: &[u8;64], hash_size: usize) {
    let diagnostic = CONTEXT.with(|state| state.borrow().3);
    emit(format!("\"event\":\"bucket\",\"name_hex\":{},\"bucket\":{value},\"mix\":{},\"hash_size\":{hash_size},\"diagnostic\":{diagnostic}",
        quote(&hex(&name.dnsmasq_bytes())), quote(&hex(mix))));
}
fn token(entry: &Entry) -> String {
    let kind = match entry.record.kind {
        Kind::Ipv4 => "F4", Kind::Ipv6 => "F6", Kind::ReverseIpv4 => "R4", Kind::ReverseIpv6 => "R6", _ => panic!("fixed primitive dynamic kind"),
    };
    format!("{kind}:{}:{}:{}", String::from_utf8(entry.record.name.dnsmasq_bytes()).unwrap(), entry.expires, hex(&entry.record.data))
}
pub(super) fn snapshot(cache: &Cache, counters: &CacheCounters, when: &str) {
    CONTEXT.with(|state| state.borrow_mut().3 = true);
    let mut lru = Vec::new();
    let mut slot = cache.head;
    while let Some(index) = slot {
        let node = &cache.slots[index];
        if let Some(entry) = cache.entry(index) {
            assert!(entry.committed);
            lru.push(token(entry));
        }
        slot = slot_index(node.next);
    }
    let mut chains: Vec<(usize, Vec<String>)> = Vec::new();
    let mut names = Vec::new();
    for index in &cache.reverse_chain {
        let entry = cache.entry(*index).unwrap();
        assert!(entry.committed && entry.record.kind.is_reverse());
        let value = reverse_bucket(&entry.record.name, cache.slots.len());
        names.push(format!("[{},{}]", quote(&hex(&entry.record.name.dnsmasq_bytes())), value));
        if chains.last().is_none_or(|(bucket,_)| *bucket != value) { chains.push((value, Vec::new())); }
        chains.last_mut().unwrap().1.push(token(entry));
    }
    let lru = lru.iter().map(|item| quote(item)).collect::<Vec<_>>().join(",");
    let chains = chains.iter().map(|(bucket,items)| format!("[{bucket},[{}]]", items.iter().map(|item| quote(item)).collect::<Vec<_>>().join(","))).collect::<Vec<_>>().join(",");
    emit(format!("\"event\":\"snapshot\",\"when\":{},\"lru\":[{lru}],\"chains\":[{chains}],\"name_buckets\":[{}],\"counter\":[{},{}]", quote(when), names.join(","), counters.inserted, counters.live_freed));
    CONTEXT.with(|state| state.borrow_mut().3 = false);
}

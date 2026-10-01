// Appended only to an ignored copy of cache.rs by reverse_cache_rust_gate.py.
impl Cache {
    pub(crate) fn reverse_gate_entry_json(&self, id: EntryId) -> String {
        let entry = self.get(id).expect("observed ID must belong to this cache");
        let (kind, reverse) = match entry.record.kind {
            Kind::Ipv4 => (1u32, false),
            Kind::Ipv6 => (28, false),
            Kind::Generic(kind) => (u32::from(kind), false),
            Kind::Cname => (5, false),
            Kind::NxDomain => (65536, false),
            /* REVERSE_MATCH_ARMS */
        };
        let address = if !entry.record.negative && kind == 1 {
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(entry.record.data.as_slice()).unwrap()).to_string()
        } else if !entry.record.negative && kind == 28 {
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(entry.record.data.as_slice()).unwrap()).to_string()
        } else {
            String::new()
        };
        let name = String::from_utf8(entry.record.name.dnsmasq_bytes()).unwrap();
        format!(
            "{{\"name\":{name:?},\"forward\":{},\"reverse\":{},\"kind\":{kind},\"negative\":{},\"expires\":{},\"address\":{address:?}}}",
            u8::from(!reverse), u8::from(reverse), u8::from(entry.record.negative), entry.expires
        )
    }

    pub(crate) fn reverse_gate_lru_json(&self) -> String {
        let mut rows = Vec::new();
        let mut next = self.head;
        while let Some(slot) = next {
            if self.slots[slot].entry.is_some() {
                rows.push(self.reverse_gate_entry_json(self.id(slot)));
            }
            next = self.slots[slot].next;
        }
        format!("[{}]", rows.join(","))
    }
}

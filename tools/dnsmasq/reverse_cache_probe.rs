// Appended only to an ignored copy of daemon.rs by reverse_cache_rust_gate.py.
pub fn reverse_cache_probe_main() {
    use std::io::BufRead;
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    assert_eq!(args[1], "-C");
    let bytes = std::fs::read(&args[2]).unwrap();
    let mut config = DnsConfig::default();
    let mut scalar = crate::config::ScalarConfig::default();
    for line in bytes.split(|byte| *byte == b'\n') {
        if let Some(directive) = crate::config::lex_line(line).unwrap() {
            assert!(scalar.apply(&directive).unwrap() || config.apply(&directive).unwrap());
        }
    }
    assert_eq!(scalar.min_cache_ttl, 0);
    assert_eq!(scalar.max_cache_ttl, 0);
    assert_eq!(scalar.max_ttl, 0);
    let negative_cache = !config.no_negative_cache;
    let hosts = super::local::configured_hosts(&config, 0);
    let mut local = LocalDnsService::new_with_limits(config, hosts, 0, 65535, 1232);
    let mut cache = Cache::new(scalar.cache_size as usize, CachePolicy::default());
    let mut counters = CacheCounters::default();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let words: Vec<_> = line.split_whitespace().collect();
        match words[0] {
            "M" => println!("{{\"op\":\"M\",\"inserted\":{},\"live_freed\":{}}}", counters.inserted, counters.live_freed),
            "S" => println!("{{\"op\":\"S\",\"entries\":{}}}", cache.reverse_gate_lru_json()),
            "N" => {
                let now: i64 = words[1].parse().unwrap();
                let name = Name::from_ascii(words[2]).unwrap();
                println!("{{\"op\":\"N\",\"exists\":{}}}", u8::from(cache.contains_forward_name(&name, now)));
            }
            "A" => {
                /* REVERSE_LOOKUP */
            }
            "P" | "Q" => {
                let now: i64 = words[1].parse().unwrap();
                let packet: Vec<_> = (0..words[2].len()).step_by(2)
                    .map(|at| u8::from_str_radix(&words[2][at..at + 2], 16).unwrap()).collect();
                let header = Header::parse(&packet).unwrap();
                let mut context = CacheContext {
                    cache: &mut cache,
                    counters: &mut counters,
                    negative_cache,
                    negative_ttl: scalar.negative_ttl,
                };
                if words[0] == "P" {
                    let result = context.insert_reply_with_policy(
                        &packet, now, &local, &AddressPolicy::default(),
                        header.rcode().into(), OrdinaryCacheMode::Commit,
                    );
                    let status = if result.is_ok() { 0 } else { 2 };
                    println!("{{\"op\":\"P\",\"status\":{status},\"packet\":{}}}", reverse_gate_packet_json(Some(&packet)));
                } else {
                    let question = super::forward::Question::parse(&packet).unwrap();
                    let result = context.answer_records(&question, header, now, &mut local, 65535).unwrap();
                    println!("{{\"op\":\"Q\",\"stale\":{},\"filtered\":0,\"packet\":{}}}",
                             u8::from(result.stale), reverse_gate_packet_json(result.packet.as_deref()));
                }
            }
            other => panic!("unsupported command {other}"),
        }
    }
}

fn reverse_gate_packet_json(packet: Option<&[u8]>) -> String {
    packet.map_or_else(|| "null".to_string(), |packet| {
        let hex: String = packet.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("\"{hex}\"")
    })
}

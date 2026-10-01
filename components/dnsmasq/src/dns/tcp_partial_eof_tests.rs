//! Opt-in before-fix observation of the existing typed Receiver and importer.
//! Seeds/cut stages/lookup order are generated from the independently frozen C
//! plan. No EOF handling, cache import or production codec is substituted.

use super::*;
use crate::dns::cache::{Cache, CacheCounters, CnameTarget, EntryId, Policy};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

fn kind(text: &str) -> Kind {
    match text {
        "A" => Kind::Ipv4,
        "CNAME" => Kind::Cname,
        _ => panic!("unsupported bounded fixture type"),
    }
}

fn record(host: &str, record_kind: &str, data: &str) -> Record {
    Record {
        name: Name::from_ascii(host).unwrap(),
        kind: kind(record_kind),
        negative: false,
        data: if data == "-" {
            Vec::new()
        } else {
            data.parse::<Ipv4Addr>().unwrap().octets().to_vec()
        },
    }
}

fn observe(
    output: &mut String,
    cache: &mut Cache,
    counters: &CacheCounters,
    queries: &[(&str, Kind)],
    now: i64,
    stage: &str,
    received: i32,
) {
    let (pending, _) = cache.insertion_test_state();
    write!(output, "{{\"stage\":\"{stage}\",\"received\":{received},\"pending_before_lookup\":{pending},\"lookups\":{{").unwrap();
    for (index, (host, record_kind)) in queries.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(output, "\"{host}\":[").unwrap();
        let ids = cache.lookup(
            &Name::from_ascii(host).unwrap(),
            &[*record_kind],
            now,
            false,
        );
        for (index, id) in ids.into_iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            let entry = cache.get(id).unwrap();
            let value = if entry.record.kind == Kind::Cname {
                let CnameTarget::Dynamic(target) = entry.cname_target().unwrap() else {
                    panic!("local target outside this fixture")
                };
                String::from_utf8(cache.get(target).unwrap().record.name.dnsmasq_bytes()).unwrap()
            } else {
                Ipv4Addr::from(<[u8; 4]>::try_from(entry.record.data.as_slice()).unwrap())
                    .to_string()
            };
            write!(
                output,
                "{{\"expiry\":{},\"value\":\"{value}\"}}",
                entry.expires
            )
            .unwrap();
        }
        output.push(']');
    }
    let (pending, failed) = cache.insertion_test_state();
    writeln!(output, "}},\"pending_after_lookup\":{pending},\"insert_error\":{},\"inserted\":{},\"live_freed\":{}}}",
             u8::from(failed), counters.inserted, counters.live_freed).unwrap();
}

#[derive(Clone, Copy)]
struct Spans {
    name_length: usize,
    name: usize,
    data: usize,
    data_length: usize,
    end: usize,
}

fn spans(bytes: &[u8]) -> Vec<Spans> {
    let count = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    let mut offset = 8;
    let mut result = Vec::new();
    for _ in 0..count {
        // Inspect the output of the real encoder; never construct a second
        // encoding. This only locates boundaries of valid A records.
        assert_eq!(&bytes[offset..offset + 4], &[0, 0, 0, 0]);
        let name_length = offset + 12;
        let length =
            u16::from_be_bytes(bytes[name_length..name_length + 2].try_into().unwrap()) as usize;
        let name = name_length + 2;
        let data_length_field = name + length;
        let data_length = u32::from_be_bytes(
            bytes[data_length_field..data_length_field + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(data_length, 4);
        let data = data_length_field + 4;
        let authority_length = data + data_length;
        assert_eq!(&bytes[authority_length..authority_length + 2], &[0, 0]);
        offset = authority_length + 2;
        result.push(Spans {
            name_length,
            name,
            data,
            data_length,
            end: offset,
        });
    }
    assert_eq!(offset, bytes.len());
    result
}

#[test]
#[ignore = "explicit exact-C partial EOF differential only; isolated Linux host required"]
fn exact_c_partial_eof_probe() {
    assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").unwrap(), "1");
    let folder = std::path::PathBuf::from(std::env::var("DNSMASQ_PARTIAL_EOF_CASE").unwrap());
    let input = std::fs::read_to_string(folder.join("plan.txt")).unwrap();
    let commands: Vec<Vec<&str>> = input
        .lines()
        .map(|line| line.split_whitespace().collect())
        .collect();
    let scalar = |key| commands.iter().find(|line| line[0] == key).unwrap()[1];
    let seed_now: i64 = scalar("seed-now").parse().unwrap();
    let receive_now: i64 = scalar("receive-now").parse().unwrap();
    let label = scalar("case");
    let mut cache = Cache::new(scalar("capacity").parse().unwrap(), Policy::default());
    let mut counters = CacheCounters::default();
    let mut ids: HashMap<&str, EntryId> = HashMap::new();
    for line in commands.iter().filter(|line| line[0] == "seed") {
        match line[1] {
            "start" => cache.start_insert(),
            "commit" => assert!(cache.commit_counted(&mut counters)),
            "insert" => {
                let expiry: i64 = line[4].parse().unwrap();
                let id = cache
                    .insert_counted(
                        record(line[2], line[3], line[5]),
                        seed_now,
                        (expiry - seed_now).try_into().unwrap(),
                        &mut counters,
                    )
                    .unwrap();
                ids.insert(line[2], id);
            }
            "link" => assert!(cache.set_cname_target(ids[line[2]], ids[line[3]])),
            _ => panic!("unknown seed operation"),
        }
    }
    let records: Vec<_> = commands
        .iter()
        .filter(|line| line[0] == "record")
        .map(|line| TransferredRecord {
            record: record(line[1], line[2], line[4]),
            expires: line[3].parse().unwrap(),
            authority_name: None,
        })
        .collect();
    let bytes = encode(CacheTransaction { records }).unwrap();
    // The complete wire must be valid under the actual current decoder. A
    // shorter byte prefix never invents a wrong count or declared length.
    let complete = decode(&bytes[4..]).unwrap();
    let offsets = spans(&bytes);
    assert_eq!(complete.records.len(), offsets.len());
    let cut = match scalar("cut") {
        "before-operation" => 0,
        "after-operation-before-record-length" => 4,
        "partial-first-record-length" => offsets[0].name_length + 1,
        "partial-first-record-name" => offsets[0].name + 3,
        "partial-first-record-address" => offsets[0].data + offsets[0].data_length - 1,
        "after-first-record-before-second-record" => {
            assert_eq!(offsets.len(), 2);
            offsets[0].end
        }
        "partial-second-record-address" => offsets[1].data + offsets[1].data_length - 1,
        "complete-transaction" => bytes.len(),
        _ => panic!("no valid typed equivalent for native sentinel"),
    };
    let queries: Vec<_> = commands
        .iter()
        .filter(|line| line[0] == "lookup")
        .map(|line| (line[1], kind(line[2])))
        .collect();
    let mut output = String::new();
    observe(
        &mut output,
        &mut cache,
        &counters,
        &queries,
        receive_now,
        "before",
        -1,
    );
    let (mut receiver, mut sender) = pipe().unwrap();
    sender.0.write_all(&bytes[..cut]).unwrap();
    drop(sender);
    let (received, outcome) = match receiver.receive() {
        Ok(Received::Transaction(transaction)) => {
            assert!(cache.import_counted(transaction, receive_now, &mut counters, |_| None));
            (1, "Transaction")
        }
        Ok(Received::Eof) => (0, "Eof"),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => (0, "UnexpectedEof"),
        _ => panic!("unexpected receiver outcome"),
    };
    observe(
        &mut output,
        &mut cache,
        &counters,
        &queries,
        receive_now,
        "after-receive",
        received,
    );
    cache.start_insert();
    observe(
        &mut output,
        &mut cache,
        &counters,
        &queries,
        receive_now,
        "after-next-start",
        -1,
    );
    std::fs::write(folder.join("rust-states.jsonl"), &output).unwrap();
    std::fs::write(folder.join("typed-complete-wire.bin"), &bytes).unwrap();
    let metadata = format!("{{\"case\":\"{label}\",\"cut\":{cut},\"total\":{},\"records\":{},\"receiver_outcome\":\"{outcome}\",\"first_record_end\":{}}}",
        bytes.len(), offsets.len(), offsets[0].end);
    std::fs::write(folder.join("typed-metadata.json"), &metadata).unwrap();
    println!("\nPARTIAL_META {metadata}");
    for row in output.lines() {
        println!("PARTIAL_STATE {row}");
    }
}

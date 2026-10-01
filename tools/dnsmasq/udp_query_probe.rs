use dnsmasq_rs::dns::udp_query::{inspect, table_full, Admission};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut words = line.split_whitespace();
        let operation = words.next().unwrap();
        let encoded = words.next().unwrap_or("");
        assert!(encoded.len().is_multiple_of(2));
        let query: Vec<_> = (0..encoded.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&encoded[at..at + 2], 16).unwrap())
            .collect();
        let result = if operation == "F" {
            table_full(&query, 1232).map_or(Admission::Drop, Admission::Reply)
        } else {
            assert_eq!(operation, "I");
            inspect(&query, 1232)
        };
        match result {
            Admission::Continue => println!("CONTINUE"),
            Admission::Drop => println!("DROP"),
            Admission::Reply(packet) => println!(
                "{}",
                packet
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
        }
    }
}

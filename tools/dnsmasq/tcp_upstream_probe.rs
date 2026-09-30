use dnsmasq_rs::config::dns::DnsConfig;
use dnsmasq_rs::config::loader::{self, Action};
use dnsmasq_rs::config::{Error, ScalarConfig};
use dnsmasq_rs::dns::forward::Question;
use dnsmasq_rs::dns::routing::RoutingTable;
use dnsmasq_rs::dns::tcp_upstream::{TcpOptions, TcpUpstream};
use std::io::{self, BufRead};
use std::path::Path;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut config = DnsConfig::default();
    let mut scalar = ScalarConfig::default();
    assert_eq!(loader::load(&args, Path::new("/dev/null"), |directive, _| {
        if config.apply(directive)? || scalar.apply(directive)? { Ok(()) }
        else { Err(Error("unsupported TCP probe directive")) }
    }).unwrap(), Action::Run);
    config.finalize().unwrap();
    config.validate_ready().unwrap();
    let routing = RoutingTable::from_runtime_config(&config, &[]).unwrap();
    let mut transport = TcpUpstream::new(routing.dispatcher_groups(), TcpOptions::default()).unwrap();
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let query: Vec<u8> = (0..line.len()).step_by(2).map(|i| u8::from_str_radix(&line[i..i+2], 16).unwrap()).collect();
        let question = Question::parse(&query).unwrap();
        let reply = routing.select(&question.name, question.rrtype, question.class, false).upstream_group()
            .and_then(|group| transport.exchange(group, &query, Instant::now() + Duration::from_secs(150), &|| false).ok());
        let output = reply.map_or_else(|| "NONE".into(), |packet| packet.iter().map(|b| format!("{b:02x}")).collect::<String>());
        println!("{} {output}", transport.socket_count());
    }
    transport.clear();
    println!("CLOSED {}", transport.socket_count());
}

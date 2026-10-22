//! Diagnose client-table requested heap independently of receive buffers.
//! Real Client constructors and socket pairs, but no event loop or traffic:
//! these numbers are neither daemon RSS nor CPU performance evidence.
#![allow(dead_code)]
#[path = "../src/client.rs"]
mod client;
mod heap_support;
#[path = "../src/sys.rs"]
mod sys;

use client::Client;
use std::collections::HashMap;
use std::os::unix::net::UnixStream;

fn measure<V>(layout: &str, count: usize, store: fn(Client) -> V) {
    let mut peers: [Option<UnixStream>; 128] = std::array::from_fn(|_| None);
    let mut clients = HashMap::new();
    let baseline = heap_support::live();
    heap_support::reset_peak();
    let mut credentials = 0;
    let mut wrappers = 0;
    for (i, peer) in peers.iter_mut().enumerate().take(count) {
        let (sock, other) = UnixStream::pair().unwrap();
        *peer = Some(other);
        let before = heap_support::live();
        let client = Client::new(
            sock.into(),
            sys::Ucred {
                pid: std::process::id() as i32,
                uid: 0,
                gid: 0,
            },
            "root".into(),
            "root".into(),
        );
        credentials += heap_support::live() - before;
        let before = heap_support::live();
        let value = store(client);
        wrappers += heap_support::live() - before;
        assert!(clients.insert(i as u32 + 1, value).is_none());
    }
    let capacity = clients.capacity();
    let retained = heap_support::live() - baseline;
    let peak = heap_support::peak() - baseline;
    let table = retained - credentials - wrappers;
    clients.clear();
    let cleared = heap_support::live() - baseline;
    assert_eq!(
        cleared, table,
        "cleared map must retain only table allocation"
    );
    drop(clients);
    drop(peers);
    assert_eq!(
        heap_support::live(),
        baseline,
        "client allocations survived drop"
    );
    println!("{layout},{count},{capacity},{},{credentials},{wrappers},{table},{retained},{peak},{cleared}",
             std::mem::size_of::<(u32, V)>());
}

fn main() {
    println!("layout,clients,capacity,entry_size,credential_heap,wrapper_heap,table_heap,retained_heap,peak_heap,after_clear_heap");
    // Initialize process/allocator state before comparative accounting.
    measure("inline_warmup", 1, std::convert::identity);
    for count in [0, 1, 8, 16, 32, 64, 128] {
        measure("inline", count, std::convert::identity);
        measure("boxed", count, Box::new);
    }
}

// Minimal extraction of control.rs:107-125 queue/wake ordering.
// The rendezvous forces the permitted worker interleave, without timing guesses.
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;

fn main() {
    let (mut wake, mut worker_wake) = UnixStream::pair().unwrap();
    wake.set_nonblocking(true).unwrap();
    worker_wake.set_nonblocking(true).unwrap();
    let (event_tx, events) = mpsc::sync_channel(8);
    let (empty_tx, empty_rx) = mpsc::sync_channel(0);
    let (sent_tx, sent_rx) = mpsc::sync_channel(0);
    let worker = thread::spawn(move || {
        empty_rx.recv().unwrap();
        event_tx.try_send("Network or Request").unwrap();
        worker_wake.write_all(&[1]).unwrap();
        sent_tx.send(()).unwrap();
        // Keep the producer and wake writer alive during the poll-equivalent.
        empty_rx.recv().unwrap();
    });
    let result = match events.try_recv() {
        Ok(event) => Some(event),
        Err(mpsc::TryRecvError::Empty) => None,
        Err(mpsc::TryRecvError::Disconnected) => panic!("unexpected disconnect"),
    };
    empty_tx.send(()).unwrap();
    sent_rx.recv().unwrap();
    let mut bytes = [0u8; 64];
    let amount = if result.is_some() { 1 } else { bytes.len() };
    match wake.read(&mut bytes[..amount]) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => panic!("{error}"),
    }
    assert!(result.is_none());
    assert_eq!(wake.read(&mut bytes).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert_eq!(events.try_recv().unwrap(), "Network or Request");
    println!("returned=None wake_read=WouldBlock event_still_queued=true");
    empty_tx.send(()).unwrap();
    worker.join().unwrap();
}

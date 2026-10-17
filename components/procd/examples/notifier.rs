//! Register a ubus object and send one notification from it, then exit.
//!
//! r65 needs this because the `ubus` CLI can only invoke and listen; it
//! cannot *be* an object that notifies. procd's `watch` is a subscription to
//! another object's notifications, so testing it needs a real second object.
//!
//! Usage: notifier <path> <type> [key=value ...]
//!
//! It stays alive briefly after notifying so the subscriber has time to be
//! delivered to; nothing here is meant to model a real service.

#![forbid(unsafe_code)]
use std::io;

use owrt_ubus::blob::BlobBuf;
use owrt_ubus::conn::Connection;

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: notifier <path> <type> [key=value ...]");
        std::process::exit(2);
    }
    let (path, kind) = (&args[0], &args[1]);

    let mut conn = Connection::connect(None)?;
    let id = conn.add_object(path, &[], 1000)?;

    // Give a subscriber that is waiting on ubus.object.add a moment to
    // attach before the notification goes out; a notify with no subscribers
    // is simply dropped by ubusd.
    std::thread::sleep(std::time::Duration::from_millis(1500));

    let mut b = BlobBuf::new();
    for kv in &args[2..] {
        match kv.split_once('=') {
            Some((k, v)) => {
                b.msg_string(k, v);
            }
            None => {
                b.msg_string(kv, "");
            }
        }
    }
    conn.notify(id, kind, b.payload())?;

    std::thread::sleep(std::time::Duration::from_millis(1500));
    Ok(())
}

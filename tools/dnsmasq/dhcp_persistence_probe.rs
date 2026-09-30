//! Trace the production persistence/publication functions with bounded I/O.
use dnsmasq_rs::dhcp::lease::{ClientIdentity, LeaseStore};
use dnsmasq_rs::dhcp::persistence::{self, AlarmAction, DnsLeaseRecord, DnsPublisher, LeaseIo};
use std::io::{self, BufRead, Write};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

type Trace = Arc<Mutex<String>>;
fn event(trace: &Trace, value: &str) {
    trace.lock().unwrap().push_str(value);
}

struct Stream {
    trace: Trace,
    bytes: Vec<u8>,
    failure: i64,
    wrote: bool,
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.wrote {
            event(&self.trace, "write;");
            self.wrote = true;
        }
        let count = if self.failure & 4 != 0 {
            bytes.len().min(16usize.saturating_sub(self.bytes.len()))
        } else {
            bytes.len()
        };
        if count == 0 && !bytes.is_empty() {
            return Err(io::Error::from_raw_os_error(28));
        }
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        event(&self.trace, "flush;");
        if self.failure & 8 != 0 {
            Err(io::Error::from_raw_os_error(28))
        } else {
            Ok(())
        }
    }
}
impl LeaseIo for Stream {
    fn rewind(&mut self) -> io::Result<()> {
        event(&self.trace, "rewind;");
        if self.failure & 1 != 0 {
            Err(io::Error::from_raw_os_error(29))
        } else {
            Ok(())
        }
    }
    fn truncate(&mut self) -> io::Result<()> {
        event(&self.trace, "truncate;");
        if self.failure & 2 != 0 {
            Err(io::Error::from_raw_os_error(13))
        } else {
            self.bytes.clear();
            Ok(())
        }
    }
    fn sync(&mut self) -> io::Result<()> {
        event(&self.trace, "sync;");
        if self.failure & 16 != 0 {
            Err(io::Error::from_raw_os_error(5))
        } else {
            Ok(())
        }
    }
}
struct Publisher {
    trace: Trace,
    serial: u32,
}
impl DnsPublisher for Publisher {
    fn replace(&mut self, records: &[DnsLeaseRecord<'_>]) -> io::Result<()> {
        self.serial += 1;
        event(&self.trace, "unhash;");
        for record in records {
            event(
                &self.trace,
                &format!(
                    "dns:{}:{}:{};",
                    std::str::from_utf8(record.name).unwrap(),
                    record.address,
                    record.expires.unwrap_or(0)
                ),
            );
        }
        Ok(())
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<i64> = line
            .split_whitespace()
            .map(|word| word.parse().unwrap())
            .collect();
        assert_eq!(v.len(), 10);
        let mut store = LeaseStore::new(2);
        for (last, name, expiry, domain) in [
            (11, &b"second"[..], 0, None),
            (10, &b"first"[..], v[2], Some(&b"test"[..])),
        ] {
            let address = Ipv4Addr::new(192, 0, 2, last);
            store
                .allocate(
                    address,
                    ClientIdentity {
                        hardware_type: 1,
                        hardware_address: vec![2, 0, 0, 0, 0, last - 9],
                        client_id: (last == 10).then_some(vec![1, 2]),
                    },
                )
                .unwrap();
            store
                .set_expires(
                    address,
                    if expiry == 0 { u32::MAX } else { expiry as u32 },
                    0,
                )
                .unwrap();
            store
                .set_hostname(address, Some(name), false, domain, false)
                .unwrap();
        }
        store
            .set_agent_id(Ipv4Addr::new(192, 0, 2, 10), Some(&[3, 4]))
            .unwrap();
        store
            .set_vendor_class(Ipv4Addr::new(192, 0, 2, 11), Some(&[5]))
            .unwrap();
        if v[3] == 0 {
            store.file_written();
        }
        if v[4] == 0 {
            store.dns_updated();
        }
        let trace = Arc::new(Mutex::new(String::from("state;")));
        let mut stream = Stream {
            trace: trace.clone(),
            bytes: b"old".to_vec(),
            failure: v[1],
            wrote: false,
        };
        let mut publisher = Publisher {
            trace: trace.clone(),
            serial: 7,
        };
        let report = persistence::update_file(
            &mut store,
            if v[5] != 0 { Some(&mut stream) } else { None },
            v[0],
        );
        let logs = u8::from(report.error.is_some());
        if logs != 0 {
            event(&trace, "log;");
        }
        event(
            &trace,
            &format!("alarm:{};", report.next_event.unwrap_or(0)),
        );
        let mut current = 777;
        let mut queued = 0;
        match report.alarm {
            AlarmAction::Keep => {}
            AlarmAction::Immediate => {
                queued = 1;
                event(&trace, "immediate;");
            }
            AlarmAction::At(when) => {
                current = when;
                event(&trace, &format!("arm:{};", when - v[0]));
            }
        }
        persistence::update_dns(
            &mut store,
            v[6] != 0,
            v[8] != 0,
            v[7] != 0,
            Some(&mut publisher),
        );
        if v[9] != 0 {
            event(&trace, "send;");
        }
        print!(
            "{} {} {} {} {} {} {} {} ",
            u8::from(store.changes().file),
            u8::from(store.changes().dns),
            publisher.serial,
            report.next_event.unwrap_or(0),
            current,
            queued,
            logs,
            report
                .error
                .as_ref()
                .and_then(|error| error.raw_os_error())
                .unwrap_or(0)
        );
        for byte in stream.bytes {
            print!("{byte:02x}");
        }
        println!(" {}", trace.lock().unwrap());
    }
}

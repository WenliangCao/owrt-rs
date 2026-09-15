# R93 bounded-connect red/green evidence

Linux build host only, disposable `/tmp` sockets and probe processes; no physical router.
The red crate used the current R93 request-deadline fix with the previous unbounded constructor.
The green crate added bounded construction. The independent probe invokes public `Connection::connect`,
so all three green scenarios use its default one-second budget, not a test-only setting.

- No HELLO: red still blocked at 1.6 s; green returns timeout at 1.00026 s.
- One-byte HELLO: red still blocked at 1.6 s; green returns timeout at 1.00054 s.
- Full accept backlog: red still blocked at 1.6 s; green returns timeout at 1.00011 s.

`probe.py BINARY red|green` recreates the listeners and always kills/reaps the red process.
The probe binary is the following small program linked against the corresponding owrt-ubus crate:

```rust
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let start = std::time::Instant::now();
    match owrt_ubus::Connection::connect(Some(&path)) {
        Ok(_) => panic!("unexpected complete connection"),
        Err(e) => println!("error={e}; elapsed={:?}", start.elapsed()),
    }
}
```

Linux library suite: 44/44 passed at the bounded-connect snapshot. The added connect tests cover
absent/partial HELLO, complete fragmented HELLO, normal path errors, peer-observed EOF after failure,
backlog recovery, and admission consuming part of the same HELLO deadline. Later root-owned changes
require their own complete regression run; these files are not device acceptance results.

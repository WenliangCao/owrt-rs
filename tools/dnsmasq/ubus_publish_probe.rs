//! Private integration-test client: register one real ubus object.
use owrt_ubus::{conn::error_status, Connection};
use std::io::{self, Write};
fn main() {
    assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
    let args: Vec<_> = std::env::args().collect();
    let result = Connection::connect(None).and_then(|mut bus| {
        bus.add_object(&args[1], &[], 1000)?;
        println!("{{\"status\":0}}");
        io::stdout().flush()?;
        if args.get(2).is_some_and(|arg| arg == "--hold") {
            loop { std::thread::park(); }
        }
        Ok(())
    });
    if let Err(error) = result {
        println!("{{\"status\":{}}}", error_status(&error).unwrap_or(-1));
        std::process::exit(1);
    }
}

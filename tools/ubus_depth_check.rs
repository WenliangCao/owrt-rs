//! Compile against owrt-ubus on the Linux builder; see check_ubus_depth.py.
use owrt_ubus::{convert, BlobBuf};
use std::io::{self, Write};

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: ubus-depth-check tree|direct DEPTH".into());
    }
    let depth: usize = args[2].parse().map_err(|_| "invalid depth")?;
    let mut blob = BlobBuf::new();
    let mut cookies = Vec::new();
    for _ in 0..depth { cookies.push(blob.msg_open_table("a")); }
    blob.msg_u32("value", 7);
    for cookie in cookies.into_iter().rev() { blob.msg_close(cookie); }
    let output = match args[1].as_str() {
        "tree" => convert::fields_to_json(blob.payload())?.to_bytes(),
        "direct" => {
            let mut output = Vec::new();
            convert::append_fields_json(blob.payload(), &mut output)?;
            output
        }
        _ => return Err("invalid mode".into()),
    };
    io::stdout().write_all(&output).map_err(|e| e.to_string())?;
    println!();
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::from(2)
        }
    }
}

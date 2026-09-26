//! Bounded suffix validation for the isolated four-action netifd event lane.
use super::{integer, json, obj, require, Json, Result};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const CHANNELS: [&str; 3] = ["listen", "subscribe", "hotplug"];
const STEPS: [&str; 4] = ["lan-down", "lan-up", "wired-down", "wired-up"];
fn load(path: &Path) -> Result<Json> {
    Ok(json::parse_bytes(&fs::read(path)?)?)
}
fn offset(value: &Json, channel: &str) -> Result<u64> {
    match value.get(channel) {
        Some(Json::Int(n)) if *n >= 0 => Ok(*n as u64),
        _ => Err("invalid transcript cursor".into()),
    }
}
fn write(path: &Path, value: &Json) -> Result<()> {
    let mut bytes = value.to_bytes();
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}
fn normalize_status(value: &mut Json) -> Result<()> {
    let Json::Object(fields) = value else {
        return Err("status is not an object".into());
    };
    fields.retain(|(key, _)| key != "uptime");
    Ok(())
}
fn lines(bytes: &[u8], subscribe: bool) -> Result<Json> {
    require(
        bytes.is_empty() || bytes.ends_with(b"\n"),
        "incomplete event line",
    )?;
    let mut records = Vec::new();
    for line in bytes.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let mut value = json::parse_bytes(line)?;
        if subscribe {
            let Json::Object(ref mut fields) = value else {
                return Err("event is not an object".into());
            };
            require(fields.len() == 1, "unexpected subscription event shape")?;
            require(
                matches!(fields[0].0.as_str(), "interface.update" | "interface.down"),
                "unexpected event kind",
            )?;
            normalize_status(&mut fields[0].1)?;
        }
        records.push(value);
    }
    Ok(Json::Array(records))
}
fn suffix(path: &Path, start: u64) -> Result<(Vec<u8>, u64)> {
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    require(
        length >= start && length - start <= 1_048_576,
        "transcript truncated or suffix too large",
    )?;
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = vec![0; (length - start) as usize];
    file.read_exact(&mut bytes)?;
    Ok((bytes, length))
}

pub fn run(args: &[String]) -> Result<()> {
    require(!args.is_empty(), "event-evidence mark|capture|check ...")?;
    if args[0] == "mark" {
        require(args.len() == 3, "event-evidence mark LOGDIR CURSOR")?;
        let root = Path::new(&args[1]);
        let mut fields = Vec::new();
        for channel in CHANNELS {
            fields.push((
                channel,
                integer(fs::metadata(root.join(format!("{channel}.txt")))?.len()),
            ));
        }
        return write(Path::new(&args[2]), &obj(fields));
    }
    require(
        args.len() == 7 && matches!(args[0].as_str(), "capture" | "check"),
        "event-evidence capture|check CONTRACT STEP LOGDIR CURSOR ACTIONDIR RECORDS_JSONL",
    )?;
    let step = &args[2];
    require(STEPS.contains(&step.as_str()), "unknown event action")?;
    let logs = Path::new(&args[3]);
    let cursor_path = Path::new(&args[4]);
    let output = Path::new(&args[5]);
    let before = load(cursor_path)?;
    let mut after = Vec::new();
    let mut fields = Vec::new();
    for channel in CHANNELS {
        let (bytes, end) = suffix(
            &logs.join(format!("{channel}.txt")),
            offset(&before, channel)?,
        )?;
        fs::write(output.join(format!("{channel}.raw")), &bytes)?;
        after.push((channel, integer(end)));
        let value = if channel == "hotplug" {
            require(
                bytes.ends_with(b"\n"),
                "missing or incomplete hotplug completion",
            )?;
            Json::Str(String::from_utf8(bytes)?)
        } else {
            let records = lines(&bytes, channel == "subscribe")?;
            require(
                records.as_array().is_some_and(|a| !a.is_empty()),
                "observer did not receive action",
            )?;
            records
        };
        fields.push((channel, value));
    }
    let mut status = load(&output.join("status.json"))?;
    normalize_status(&mut status)?;
    let up = step.ends_with("-up");
    require(
        status.get("up") == Some(&Json::Bool(up)),
        "action state not reached",
    )?;
    require(
        status.get("pending") == Some(&Json::Bool(false)),
        "action still pending",
    )?;
    fields.push(("status", status));
    fields.push((
        "command_stdout",
        Json::from_string_bytes(fs::read(output.join("command.stdout"))?),
    ));
    for kernel in ["kernel-addresses.txt", "routes.txt", "routes6.txt"] {
        fields.push((
            kernel,
            Json::from_string_bytes(fs::read(output.join(kernel))?),
        ));
    }
    let evidence = obj(fields);
    write(&output.join("evidence.json"), &evidence)?;
    write(&output.join("offsets-before.json"), &before)?;
    let after = obj(after);
    write(&output.join("offsets-after.json"), &after)?;
    if args[0] == "check" {
        let contract = load(Path::new(&args[1]))?;
        let expected = contract
            .get("steps")
            .and_then(|v| v.get(step))
            .ok_or("missing action contract")?;
        require(
            expected == &evidence,
            "complete action output/event contract mismatch",
        )?;
    } else {
        require(args[1] == "-", "capture cannot accept a contract")?;
    }
    let mut raw = Vec::new();
    for name in [
        "listen.raw",
        "subscribe.raw",
        "hotplug.raw",
        "command.stdout",
        "command.stderr",
        "command.rc",
        "status.json",
        "status-polls.jsonl",
        "status.stderr",
        "polls.txt",
        "addresses.txt",
        "kernel-addresses.txt",
        "routes.txt",
        "routes6.txt",
        "routes-unsorted.txt",
        "routes6-unsorted.txt",
        "evidence-errors.txt",
    ] {
        raw.push((name, Json::from_string_bytes(fs::read(output.join(name))?)));
    }
    let record = obj([
        ("step", Json::Str(step.clone())),
        ("evidence", evidence),
        ("offsets_before", before),
        ("offsets_after", after.clone()),
        ("raw", obj(raw)),
    ]);
    let mut records = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args[6])?;
    records.write_all(&record.to_bytes())?;
    records.write_all(b"\n")?;
    records.flush()?;
    // Only an accepted, complete action advances any transcript cursor.
    write(cursor_path, &after)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_status_uptime_is_normalized_and_order_duplicates_survive() {
        let input = br#"{"interface.update":{"uptime":7,"data":{"uptime":9}}}
{"interface.update":{"uptime":8,"data":{"uptime":9}}}
"#;
        let result = lines(input, true).unwrap();
        let list = result.as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], list[1]);
        assert_eq!(
            list[0]
                .get("interface.update")
                .unwrap()
                .get("data")
                .unwrap()
                .get("uptime"),
            Some(&Json::Int(9))
        );
        assert!(lines(&input[..input.len() - 1], true).is_err());
        assert!(lines(b"not JSON\n", true).is_err());
        assert!(lines(b"{\"unknown\":{}}\n", true).is_err());
    }
}

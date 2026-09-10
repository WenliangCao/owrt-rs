//! Common client for original OpenWrt and Rust servers. No payloads or
//! configuration values are emitted. A failed operation invalidates a run.
use owrt_ubus::convert::{fields_to_json, object_to_payload};
use owrt_ubus::json::{self, Json};
use owrt_ubus::{BlobBuf, Connection, Incoming, MsgType};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::process::Command;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn obj(fields: impl IntoIterator<Item = (impl Into<String>, Json)>) -> Json {
    Json::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn num(value: impl Into<f64>) -> Json {
    Json::Float(value.into())
}
fn integer(value: u64) -> Json {
    Json::Int(value as i64)
}
fn emit(value: Json) {
    println!("{}", value.to_compact());
}
fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}

// An object is a recursive subset; an empty array still requires an array.
// This permits dynamic timestamps and counters without accepting error bodies.
fn contains(actual: &Json, expected: &Json) -> bool {
    match (actual, expected) {
        (Json::Object(a), Json::Object(e)) => e
            .iter()
            .all(|(key, value)| a.iter().any(|(k, v)| k == key && contains(v, value))),
        (Json::Array(a), Json::Array(e)) => {
            a.len() >= e.len() && a.iter().zip(e).all(|(a, e)| contains(a, e))
        }
        _ => actual == expected,
    }
}

fn read_json(path: &str) -> Result<Json> {
    Ok(json::parse(&fs::read_to_string(path)?)?)
}

#[derive(Clone)]
struct ProcSample {
    start_ticks: u64,
    cpu_ticks: u64,
    child_ticks: u64,
    values: BTreeMap<String, u64>,
}

fn proc_sample(pid: u32) -> Result<ProcSample> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let tail = stat.rsplit_once(") ").ok_or("invalid proc stat")?.1;
    let fields: Vec<_> = tail.split_whitespace().collect();
    require(fields.len() >= 20, "short proc stat")?;
    let n = |index: usize| -> Result<u64> { Ok(fields[index].parse()?) };
    let mut values = BTreeMap::new();
    for line in fs::read_to_string(format!("/proc/{pid}/status"))?.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if matches!(
                key,
                "VmRSS"
                    | "RssAnon"
                    | "RssFile"
                    | "RssShmem"
                    | "VmHWM"
                    | "VmPTE"
                    | "Threads"
                    | "voluntary_ctxt_switches"
                    | "nonvoluntary_ctxt_switches"
            ) {
                values.insert(
                    key.into(),
                    value
                        .split_whitespace()
                        .next()
                        .ok_or("missing proc value")?
                        .parse()?,
                );
            }
        }
    }
    values.insert(
        "fds".into(),
        fs::read_dir(format!("/proc/{pid}/fd"))?.count() as u64,
    );
    Ok(ProcSample {
        start_ticks: n(19)?,
        cpu_ticks: n(11)? + n(12)?,
        child_ticks: n(13)? + n(14)?,
        values,
    })
}

fn proc_json(pid: u32, sample: &ProcSample) -> Json {
    let mut fields: Vec<_> = sample
        .values
        .iter()
        .map(|(k, v)| (k.clone(), integer(*v)))
        .collect();
    fields.extend([
        ("pid".into(), integer(pid as u64)),
        ("start_ticks".into(), integer(sample.start_ticks)),
        ("cpu_ticks".into(), integer(sample.cpu_ticks)),
        ("child_cpu_ticks".into(), integer(sample.child_ticks)),
    ]);
    Json::Object(fields)
}

fn ticks_per_second() -> Result<u64> {
    // Linux exports AT_CLKTCK in native-word auxv; no architecture-specific
    // sysconf enum or FFI layout is needed.
    let bytes = fs::read("/proc/self/auxv")?;
    let word = std::mem::size_of::<usize>();
    for entry in bytes.chunks_exact(2 * word) {
        let kind = usize::from_ne_bytes(entry[..word].try_into()?);
        if kind == 17 {
            return Ok(usize::from_ne_bytes(entry[word..].try_into()?) as u64);
        }
    }
    Err("AT_CLKTCK missing".into())
}

fn pid_list(text: &str) -> Result<Vec<u32>> {
    if text == "-" {
        return Ok(Vec::new());
    }
    let pids: Vec<u32> = text
        .split(',')
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    require(!pids.contains(&0), "PID 0 is not a process")?;
    Ok(pids)
}

fn snapshot(pids: &[u32]) -> Result<Json> {
    let processes = pids
        .iter()
        .map(|&pid| Ok(proc_json(pid, &proc_sample(pid)?)))
        .collect::<Result<Vec<_>>>()?;
    let memory = fs::read_to_string("/proc/meminfo")?
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            let n = value.split_whitespace().next()?.parse::<u64>().ok()?;
            Some((key.to_string(), integer(n)))
        })
        .collect::<Vec<_>>();
    let cpu: Vec<_> = fs::read_to_string("/proc/stat")?
        .lines()
        .next()
        .ok_or("no CPU stats")?
        .split_whitespace()
        .skip(1)
        .map(|v| v.parse().map(integer))
        .collect::<std::result::Result<_, _>>()?;
    let temperature = fs::read_to_string("/sys/class/thermal/thermal_zone0/temp")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .map(Json::Int)
        .unwrap_or(Json::Null);
    Ok(obj([
        (
            "uptime_s",
            num(fs::read_to_string("/proc/uptime")?
                .split_whitespace()
                .next()
                .ok_or("no uptime")?
                .parse::<f64>()?),
        ),
        ("processes", Json::Array(processes)),
        ("memory_kib", Json::Object(memory)),
        ("system_cpu_ticks", Json::Array(cpu)),
        ("temperature_millic", temperature),
        ("clock_ticks_per_second", integer(ticks_per_second()?)),
    ]))
}

fn measure<F, G>(
    n: usize,
    warmup: usize,
    pids: &[u32],
    mut operation: F,
    mut finish: G,
) -> Result<()>
where
    F: FnMut(usize) -> Result<u64>,
    G: FnMut() -> Result<()>,
{
    require(n > 0, "iterations must be positive")?;
    for i in 0..warmup {
        operation(i)?;
    }
    finish()?;
    let before: Vec<_> = pids
        .iter()
        .map(|&pid| proc_sample(pid))
        .collect::<Result<_>>()?;
    let own_before = proc_sample(std::process::id())?;
    let begin = Instant::now();
    let mut latencies = Vec::with_capacity(n);
    for i in 0..n {
        latencies.push(operation(warmup + i)?);
    }
    finish()?;
    let elapsed = begin.elapsed().as_secs_f64();
    let own_after = proc_sample(std::process::id())?;
    let after: Vec<_> = pids
        .iter()
        .map(|&pid| proc_sample(pid))
        .collect::<Result<_>>()?;
    let hz = ticks_per_second()? as f64;
    let mut daemons = Vec::new();
    for ((&pid, b), a) in pids.iter().zip(&before).zip(&after) {
        require(
            b.start_ticks == a.start_ticks,
            "monitored process was replaced",
        )?;
        daemons.push(obj([
            ("pid", integer(pid as u64)),
            (
                "cpu_s",
                num((a
                    .cpu_ticks
                    .checked_sub(b.cpu_ticks)
                    .ok_or("CPU counter regressed")?) as f64
                    / hz),
            ),
            (
                "child_cpu_s",
                num((a
                    .child_ticks
                    .checked_sub(b.child_ticks)
                    .ok_or("child CPU counter regressed")?) as f64
                    / hz),
            ),
            ("before", proc_json(pid, b)),
            ("after", proc_json(pid, a)),
        ]));
    }
    let raw = Json::Array(latencies.iter().copied().map(integer).collect());
    latencies.sort_unstable();
    let percentile =
        |p: f64| -> Json { num(latencies[((n - 1) as f64 * p).round() as usize] as f64 / 1000.0) };
    emit(obj([
        ("schema", Json::Int(1)),
        ("successful", integer(n as u64)),
        ("errors", Json::Int(0)),
        ("warmup", integer(warmup as u64)),
        ("wall_s", num(elapsed)),
        ("ops_per_s", num(n as f64 / elapsed)),
        (
            "mean_us",
            num(latencies.iter().map(|&v| v as f64).sum::<f64>() / n as f64 / 1000.0),
        ),
        ("p50_us", percentile(0.50)),
        ("p95_us", percentile(0.95)),
        ("p99_us", percentile(0.99)),
        ("latency_ns", raw),
        ("daemon_cpu", Json::Array(daemons)),
        (
            "client_cpu_s",
            num((own_after.cpu_ticks - own_before.cpu_ticks) as f64 / hz),
        ),
        (
            "child_cpu_s",
            num((own_after.child_ticks - own_before.child_ticks) as f64 / hz),
        ),
        ("clock_ticks_per_second", num(hz)),
    ]));
    Ok(())
}

fn serve(socket: &str, count: usize) -> Result<()> {
    require(count > 0, "object count must be positive")?;
    let mut c = Connection::connect(Some(socket))?;
    for i in 0..count {
        let name = if i == 0 {
            "bench.target".into()
        } else {
            format!("bench.filler{i:04}")
        };
        c.add_object(&name, &[("ping", &[("n", MsgType::Int32)])], 3000)?;
    }
    loop {
        match c.read_incoming()? {
            Incoming::Invoke(req) => {
                let mut b = BlobBuf::new();
                b.msg_u32("ok", 1);
                c.reply_data(&req, b.payload())?;
                c.reply_status(&req, 0, None)?;
            }
            _ => continue,
        }
    }
}

struct HttpClient {
    address: String,
    stream: Option<BufReader<HttpStream>>,
}

struct HttpStream(TcpStream);

impl Read for HttpStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.0.read(buffer)?;
        if count > 0 {
            // QUICKACK is not persistent: refresh it after received data,
            // including a header packet that precedes a Nagle-held body.
            quick_ack(&self.0)?;
        }
        Ok(count)
    }
}

impl Write for HttpStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn quick_ack(stream: &TcpStream) -> std::io::Result<()> {
    // Linux constants and socklen_t are checked against the SDK by
    // socket_constants.c. The option is per client socket, not host state.
    unsafe extern "C" {
        fn setsockopt(
            fd: i32,
            level: i32,
            name: i32,
            value: *const std::ffi::c_void,
            len: u32,
        ) -> i32;
    }
    let enabled: i32 = 1;
    // SAFETY: the live socket and correctly sized integer remain valid for
    // the call; setsockopt copies the value before returning.
    let result = unsafe {
        setsockopt(
            stream.as_raw_fd(),
            6,
            12,
            (&enabled as *const i32).cast(),
            4,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

impl HttpClient {
    fn request(&mut self, method: &str, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        if self.stream.is_none() {
            let stream = TcpStream::connect(&self.address)?;
            stream.set_nodelay(true)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            self.stream = Some(BufReader::new(HttpStream(stream)));
        }
        let reader = self.stream.as_mut().ok_or("missing HTTP stream")?;
        // Send a complete request together. Formatting directly into a
        // TCP_NODELAY socket emits many tiny writes and can trigger delayed
        // ACK/Nagle interactions in the peer rather than measure its work.
        let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", self.address, body.len()).into_bytes();
        request.extend_from_slice(body);
        reader.get_mut().write_all(&request)?;
        // Loopback's large MSS can leave a C uhttpd response waiting for a
        // delayed ACK for ~50 ms, unlike the real LAN path. Keep ACK policy
        // identical and responsive for both subjects on this client socket.
        quick_ack(&reader.get_ref().0)?;
        let mut line = String::new();
        reader.read_line(&mut line)?;
        require(
            line.split_whitespace().nth(1) == Some("200"),
            "HTTP status is not 200",
        )?;
        let mut close = line.starts_with("HTTP/1.0");
        let mut length = None;
        let mut chunked = false;
        let mut total = line.len();
        loop {
            line.clear();
            require(reader.read_line(&mut line)? > 0, "EOF in HTTP headers")?;
            total += line.len();
            require(total < 65536, "oversized HTTP headers")?;
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.split_once(':').ok_or("invalid HTTP header")?;
            match name.to_ascii_lowercase().as_str() {
                "content-length" => length = Some(value.trim().parse::<usize>()?),
                "transfer-encoding" => {
                    require(
                        value.trim().eq_ignore_ascii_case("chunked"),
                        "unsupported transfer encoding",
                    )?;
                    chunked = true;
                }
                "connection" if value.trim().eq_ignore_ascii_case("close") => close = true,
                _ => (),
            }
        }
        let mut out = Vec::new();
        if chunked {
            loop {
                line.clear();
                require(reader.read_line(&mut line)? > 0, "EOF in chunk header")?;
                let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)?;
                require(out.len() + size < 4 * 1024 * 1024, "oversized HTTP body")?;
                if size == 0 {
                    loop {
                        line.clear();
                        require(reader.read_line(&mut line)? > 0, "EOF in trailers")?;
                        if line == "\r\n" {
                            break;
                        }
                    }
                    break;
                }
                let start = out.len();
                out.resize(start + size, 0);
                reader.read_exact(&mut out[start..])?;
                let mut end = [0; 2];
                reader.read_exact(&mut end)?;
                require(&end == b"\r\n", "invalid chunk ending")?;
            }
        } else if let Some(size) = length {
            require(size < 4 * 1024 * 1024, "oversized HTTP body")?;
            out.resize(size, 0);
            reader.read_exact(&mut out)?;
        } else {
            require(close, "HTTP response has no framing")?;
            reader.take(4 * 1024 * 1024).read_to_end(&mut out)?;
        }
        if close {
            self.stream = None;
        }
        Ok(out)
    }
}

fn main_inner(a: &[String]) -> Result<()> {
    let mode = a
        .get(1)
        .ok_or("missing mode: rpc/lookup/exec/http/syslog/serve/snapshot/idle")?;
    match mode.as_str() {
        "rpc" => {
            require(
                a.len() == 10,
                "rpc SOCKET OBJECT METHOD INPUT_JSON EXPECT_JSON N WARMUP PIDS",
            )?;
            let payload = object_to_payload(&read_json(&a[5])?);
            let expected = read_json(&a[6])?;
            let mut c = Connection::connect(Some(&a[2]))?;
            let target = c.lookup_id(&a[3], 3000)?;
            measure(
                a[7].parse()?,
                a[8].parse()?,
                &pid_list(&a[9])?,
                |_| {
                    let t = Instant::now();
                    let reply = c.invoke(target, &a[4], &payload, 5000)?;
                    let elapsed = t.elapsed().as_nanos() as u64;
                    require(
                        contains(&fields_to_json(&reply.fields()), &expected),
                        "RPC reply failed validation",
                    )?;
                    Ok(elapsed)
                },
                || Ok(()),
            )
        }
        "lookup" => {
            require(a.len() == 7, "lookup SOCKET PATH_OR_* N WARMUP PIDS")?;
            let mut c = Connection::connect(Some(&a[2]))?;
            let path = if a[3] == "*" {
                None
            } else {
                Some(a[3].as_str())
            };
            measure(
                a[4].parse()?,
                a[5].parse()?,
                &pid_list(&a[6])?,
                |_| {
                    let t = Instant::now();
                    let objects = c.lookup(path, 5000)?;
                    let elapsed = t.elapsed().as_nanos() as u64;
                    require(
                        objects.iter().any(|o| o.path == "bench.target"),
                        "lookup lost benchmark object",
                    )?;
                    Ok(elapsed)
                },
                || Ok(()),
            )
        }
        "exec" => {
            require(
                a.len() >= 8 && a[6] == "--",
                "exec N WARMUP EXPECT_BYTES PIDS -- PROGRAM ARGS...",
            )?;
            let expected = fs::read(&a[4])?;
            measure(
                a[2].parse()?,
                a[3].parse()?,
                &pid_list(&a[5])?,
                |i| {
                    let t = Instant::now();
                    let output = Command::new(&a[7])
                        .args(&a[8..])
                        .env("R84_ITERATION", i.to_string())
                        .output()?;
                    let elapsed = t.elapsed().as_nanos() as u64;
                    require(output.status.success(), "child command failed")?;
                    require(
                        output.stdout == expected,
                        "child stdout failed byte validation",
                    )?;
                    Ok(elapsed)
                },
                || Ok(()),
            )
        }
        "http" => {
            require(
                a.len() == 11,
                "http ADDRESS METHOD PATH BODY_OR_- EXPECT_BYTES_OR_JSON N WARMUP PIDS json|bytes",
            )?;
            let body = if a[5] == "-" {
                Vec::new()
            } else {
                fs::read(&a[5])?
            };
            let expected = fs::read(&a[6])?;
            let mut client = HttpClient {
                address: a[2].clone(),
                stream: None,
            };
            let json_expected = if a[10] == "json" {
                Some(json::parse_bytes(&expected)?)
            } else {
                None
            };
            require(
                matches!(a[10].as_str(), "json" | "bytes"),
                "invalid HTTP validation mode",
            )?;
            measure(
                a[7].parse()?,
                a[8].parse()?,
                &pid_list(&a[9])?,
                |_| {
                    let t = Instant::now();
                    let response = client.request(&a[3], &a[4], &body)?;
                    let elapsed = t.elapsed().as_nanos() as u64;
                    let valid = if let Some(expected) = &json_expected {
                        contains(&json::parse_bytes(&response)?, expected)
                    } else {
                        response == expected
                    };
                    require(valid, "HTTP body failed validation")?;
                    Ok(elapsed)
                },
                || Ok(()),
            )
        }
        "syslog" => {
            require(a.len() == 7, "syslog LOG_SOCKET UBUS_SOCKET N WARMUP PIDS")?;
            let socket = UnixDatagram::unbound()?;
            socket.connect(&a[2])?;
            socket.set_write_timeout(Some(Duration::from_secs(5)))?;
            let prefix = format!("r84-bench-{}", std::process::id());
            let mut c = Connection::connect(Some(&a[3]))?;
            let log = c.lookup_id("log", 3000)?;
            let mut args = BlobBuf::new();
            args.msg_u32("lines", 1);
            args.msg_bool("stream", false);
            // Shared Cell lets the drain check know the final sequence of each phase.
            let last = std::cell::Cell::new(0);
            measure(
                a[4].parse()?,
                a[5].parse()?,
                &pid_list(&a[6])?,
                |i| {
                    let payload = format!("<30>{prefix}-{i:08}: {}", "x".repeat(96));
                    let t = Instant::now();
                    let sent = socket.send(payload.as_bytes())?;
                    let elapsed = t.elapsed().as_nanos() as u64;
                    require(sent == payload.len(), "short syslog datagram")?;
                    last.set(i);
                    Ok(elapsed)
                },
                || {
                    let marker = format!("{prefix}-{:08}:", last.get());
                    for _ in 0..100 {
                        let reply = c.invoke(log, "read", args.payload(), 3000)?;
                        if fields_to_json(&reply.fields())
                            .to_compact()
                            .contains(&marker)
                        {
                            return Ok(());
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err("log daemon did not consume the final datagram".into())
                },
            )
        }
        "serve" => {
            require(a.len() == 4, "serve SOCKET OBJECT_COUNT")?;
            serve(&a[2], a[3].parse()?)
        }
        "snapshot" => {
            require(a.len() == 3, "snapshot PIDS")?;
            emit(snapshot(&pid_list(&a[2])?)?);
            Ok(())
        }
        "idle" => {
            require(a.len() == 4, "idle SECONDS PIDS")?;
            let seconds: u64 = a[2].parse()?;
            let pids = pid_list(&a[3])?;
            let start = Instant::now();
            for i in 0..=seconds {
                std::thread::sleep(Duration::from_secs(i).saturating_sub(start.elapsed()));
                emit(snapshot(&pids)?);
            }
            Ok(())
        }
        _ => Err("unknown benchmark mode".into()),
    }
}

fn main() {
    if let Err(error) = main_inner(&std::env::args().collect::<Vec<_>>()) {
        eprintln!("benchmark INVALID: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn response_gate_rejects_http_200_rpc_errors_and_missing_data() {
        let expected = json::parse(r#"{"result":[0,{"values":{}}]}"#).unwrap();
        for body in [
            r#"{"error":{"code":-32002}}"#,
            r#"{"result":[6]}"#,
            r#"{"result":[0,{}]}"#,
            r#"{}"#,
        ] {
            assert!(!contains(&json::parse(body).unwrap(), &expected));
        }
        assert!(contains(
            &json::parse(r#"{"id":1,"result":[0,{"values":{"a":1}}]}"#).unwrap(),
            &expected
        ));
    }
}

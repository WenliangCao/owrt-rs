//! Common client for original OpenWrt and Rust servers. No payloads or
//! configuration values are emitted. A failed operation invalidates a run.
use owrt_ubus::convert::{fields_to_json, object_to_payload};
use owrt_ubus::json::{self, Json};
use owrt_ubus::{BlobBuf, Connection, Incoming, MsgType};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(test)]
use owrt_ubus::LookupEntry;

mod affinity;
mod child_cpu;
mod cpu_clock;
mod event_evidence;
mod exec_journal;
mod fw4_output;
#[cfg(feature = "registration-perf")]
mod registration_perf;
#[cfg(feature = "registration-phase")]
mod registration_phase;
mod reload_exec;
mod reload_fault;

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
    // Only the caller can read RUSAGE_CHILDREN; external PIDs retain ticks.
    children_rusage: Option<child_cpu::Sample>,
    // /proc/<pid>/stat field 39: only the last CPU observed, not a
    // migration count or proof that the task stayed there between samples.
    last_processor: u64,
    cpus_allowed: String,
    cpus_allowed_list: String,
    cpu_clock: cpu_clock::Sample,
    values: BTreeMap<String, u64>,
}

fn proc_sample(pid: u32) -> Result<ProcSample> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let tail = stat.rsplit_once(") ").ok_or("invalid proc stat")?.1;
    let fields: Vec<_> = tail.split_whitespace().collect();
    require(fields.len() >= 37, "short proc stat")?;
    let n = |index: usize| -> Result<u64> { Ok(fields[index].parse()?) };
    let mut values = BTreeMap::new();
    let mut cpus_allowed = None;
    let mut cpus_allowed_list = None;
    for line in fs::read_to_string(format!("/proc/{pid}/status"))?.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key == "Cpus_allowed" {
                cpus_allowed = Some(value.trim().to_owned());
            } else if key == "Cpus_allowed_list" {
                cpus_allowed_list = Some(value.trim().to_owned());
            } else if matches!(
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
        children_rusage: if pid == std::process::id() {
            Some(child_cpu::sample()?)
        } else {
            None
        },
        // The parsed tail starts at stat field 3 (state).
        last_processor: n(36)?,
        cpus_allowed: cpus_allowed.ok_or("missing Cpus_allowed")?,
        cpus_allowed_list: cpus_allowed_list.ok_or("missing Cpus_allowed_list")?,
        cpu_clock: cpu_clock::sample(pid)?,
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
        ("last_processor".into(), integer(sample.last_processor)),
        (
            "Cpus_allowed".into(),
            Json::Str(sample.cpus_allowed.clone()),
        ),
        (
            "Cpus_allowed_list".into(),
            Json::Str(sample.cpus_allowed_list.clone()),
        ),
        ("process_cpu_ns".into(), integer(sample.cpu_clock.ns)),
        (
            "process_cpu_resolution_ns".into(),
            integer(sample.cpu_clock.resolution_ns),
        ),
    ]);
    if let Some(children) = sample.children_rusage {
        fields.extend([
            ("rusage_children_user_us".into(), integer(children.user_us)),
            (
                "rusage_children_system_us".into(),
                integer(children.system_us),
            ),
            (
                "rusage_children_counter_source".into(),
                Json::Str("getrusage(RUSAGE_CHILDREN)".into()),
            ),
        ]);
    }
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
                "cpu_clock_ns",
                integer(
                    a.cpu_clock
                        .ns
                        .checked_sub(b.cpu_clock.ns)
                        .ok_or("CPU clock regressed")?,
                ),
            ),
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
        // Reuse the snapshots already taken outside the timed interval.
        // Context switches and CPU placement are boundary observations only.
        ("client_before", proc_json(std::process::id(), &own_before)),
        ("client_after", proc_json(std::process::id(), &own_after)),
        (
            "client_cpu_s",
            num((own_after.cpu_ticks - own_before.cpu_ticks) as f64 / hz),
        ),
        (
            "child_cpu_s",
            num((own_after.child_ticks - own_before.child_ticks) as f64 / hz),
        ),
        (
            "client_cpu_clock_ns",
            integer(
                own_after
                    .cpu_clock
                    .ns
                    .checked_sub(own_before.cpu_clock.ns)
                    .ok_or("client CPU clock regressed")?,
            ),
        ),
        ("clock_ticks_per_second", num(hz)),
    ]));
    Ok(())
}

/// Serial CPU diagnostic: no per-operation timing reads or latency vector.
/// The service still uses its real socket protocol and production handler.
fn measure_cpu_loop(
    n: usize,
    warmup: usize,
    pids: &[u32],
    mut operation: impl FnMut() -> Result<()>,
) -> Result<()> {
    require(
        n > 0 && pids.len() == 1,
        "CPU loop requires iterations and one daemon PID",
    )?;
    for _ in 0..warmup {
        operation()?;
    }
    let pid = pids[0];
    let before = proc_sample(pid)?;
    let own_before = proc_sample(std::process::id())?;
    let subject_start = cpu_clock::sample(pid)?;
    let client_start = cpu_clock::sample(std::process::id())?;
    let start = Instant::now();
    for _ in 0..n {
        operation()?;
    }
    let wall = start.elapsed().as_secs_f64();
    let client_end = cpu_clock::sample(std::process::id())?;
    let subject_end = cpu_clock::sample(pid)?;
    let own_after = proc_sample(std::process::id())?;
    let after = proc_sample(pid)?;
    require(
        before.start_ticks == after.start_ticks,
        "daemon PID was reused",
    )?;
    require(
        subject_start.resolution_ns == subject_end.resolution_ns
            && client_start.resolution_ns == client_end.resolution_ns,
        "CPU clock resolution changed",
    )?;
    let daemon_ns = subject_end
        .ns
        .checked_sub(subject_start.ns)
        .ok_or("daemon CPU clock regressed")?;
    let client_ns = client_end
        .ns
        .checked_sub(client_start.ns)
        .ok_or("client CPU clock regressed")?;
    emit(obj([
        ("schema", Json::Int(1)),
        ("mode", Json::Str("serial_cpu_loop".into())),
        ("successful", integer(n as u64)),
        ("errors", Json::Int(0)),
        ("warmup", integer(warmup as u64)),
        ("subject_pid", integer(pid as u64)),
        ("wall_s", num(wall)),
        ("ops_per_s", num(n as f64 / wall)),
        ("subject_cpu_clock_ns", integer(daemon_ns)),
        ("client_cpu_clock_ns", integer(client_ns)),
        ("subject_cpu_start_ns", integer(subject_start.ns)),
        ("subject_cpu_end_ns", integer(subject_end.ns)),
        ("client_cpu_start_ns", integer(client_start.ns)),
        ("client_cpu_end_ns", integer(client_end.ns)),
        ("subject_before", proc_json(pid, &before)),
        ("subject_after", proc_json(pid, &after)),
        ("client_before", proc_json(std::process::id(), &own_before)),
        ("client_after", proc_json(std::process::id(), &own_after)),
        (
            "subject_status",
            Json::Str(fs::read_to_string(format!("/proc/{pid}/status"))?),
        ),
        (
            "client_status",
            Json::Str(fs::read_to_string("/proc/self/status")?),
        ),
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

fn serve_signature() -> Vec<u8> {
    let mut b = BlobBuf::new();
    let method = b.msg_open_table("ping");
    b.msg_u32("n", MsgType::Int32 as u32);
    b.msg_close(method);
    b.payload().to_vec()
}

fn fixture_paths(count: usize) -> Vec<String> {
    let mut paths: Vec<_> = (1..count).map(|i| format!("bench.filler{i:04}")).collect();
    // The registry's path order is lexical: all fillers precede bench.target.
    paths.push("bench.target".into());
    paths
}

fn fixture_selector(selector: &str, count: usize) -> Result<(Option<&str>, Vec<String>)> {
    require(
        matches!(count, 64 | 128),
        "fixture object count must be 64 or 128",
    )?;
    let paths = match selector {
        "bench.target" => vec!["bench.target".into()],
        "bench.*" | "*" => fixture_paths(count),
        _ => return Err("fixture path must be bench.target, bench.*, or *".into()),
    };
    // A bare '*' deliberately omits OBJPATH and exercises pathless LOOKUP.
    Ok((
        if selector == "*" {
            None
        } else {
            Some(selector)
        },
        paths,
    ))
}

fn validate_fixture_lookup(
    entries: &[owrt_ubus::LookupEntry],
    expected_paths: &[String],
    expected_ids: Option<&[u32]>,
) -> Result<Vec<u32>> {
    require(
        entries.len() == expected_paths.len(),
        "lookup fixture returned wrong object count",
    )?;
    let signature = serve_signature();
    let mut ids = Vec::with_capacity(entries.len());
    let mut seen = HashSet::with_capacity(entries.len());
    for (index, (entry, expected_path)) in entries.iter().zip(expected_paths).enumerate() {
        require(
            entry.path == *expected_path,
            "lookup fixture path/order changed",
        )?;
        require(
            entry.id != 0 && seen.insert(entry.id),
            "lookup fixture id is zero or duplicated",
        )?;
        require(
            entry.signature == signature,
            "lookup fixture signature changed",
        )?;
        if let Some(expected_ids) = expected_ids {
            require(
                expected_ids.get(index) == Some(&entry.id),
                "lookup fixture id changed",
            )?;
        }
        ids.push(entry.id);
    }
    Ok(ids)
}

fn lookup_fixture(
    socket: &str,
    selector: &str,
    count: usize,
    n: usize,
    warmup: usize,
    pids: &[u32],
) -> Result<()> {
    let (path, expected_paths) = fixture_selector(selector, count)?;
    let mut c = Connection::connect(Some(socket))?;
    // Object ids are allocated by the daemon, so establish only this identity
    // oracle before timing; every warmup and measured reply must repeat it.
    let ids = validate_fixture_lookup(&c.lookup(path, 5000)?, &expected_paths, None)?;
    measure(
        n,
        warmup,
        pids,
        |_| {
            let start = Instant::now();
            let entries = c.lookup(path, 5000)?;
            let elapsed = start.elapsed().as_nanos() as u64;
            validate_fixture_lookup(&entries, &expected_paths, Some(&ids))?;
            Ok(elapsed)
        },
        || Ok(()),
    )
}

fn rpc_fixture(socket: &str, n: usize, warmup: usize, pids: &[u32]) -> Result<()> {
    let mut c = Connection::connect(Some(socket))?;
    let expected_paths = vec!["bench.target".into()];
    let entries = c.lookup(Some("bench.target"), 5000)?;
    let ids = validate_fixture_lookup(&entries, &expected_paths, None)?;
    let target = ids[0];
    let mut args = BlobBuf::new();
    args.msg_u32("n", 1);
    let args = args.into_payload();
    let mut fields = BlobBuf::new();
    fields.msg_u32("ok", 1);
    let fields = fields.into_payload();
    let mut expected = BlobBuf::new();
    expected
        .put_u32(owrt_ubus::attr::OBJID, target)
        .put(owrt_ubus::attr::DATA, &fields);
    let expected_data = expected.payload().to_vec();
    measure(
        n,
        warmup,
        pids,
        |_| {
            let start = Instant::now();
            let reply = c.invoke(target, "ping", &args, 5000)?;
            let elapsed = start.elapsed().as_nanos() as u64;
            require(
                reply.fd.is_none(),
                "rpc fixture unexpectedly returned an FD",
            )?;
            require(
                reply.data.len() == 1 && reply.data[0] == expected_data,
                "rpc fixture reply bytes changed",
            )?;
            Ok(elapsed)
        },
        || Ok(()),
    )
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
        require(reader.read_line(&mut line)? > 0, "EOF before HTTP status")?;
        if line.split_whitespace().nth(1) != Some("200") {
            return Err(format!("HTTP status is not 200: {line:?}").into());
        }
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
                require(
                    out.len().saturating_add(size) < 4 * 1024 * 1024,
                    "oversized HTTP body",
                )?;
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
            reader.take(4 * 1024 * 1024 + 1).read_to_end(&mut out)?;
            require(out.len() <= 4 * 1024 * 1024, "oversized HTTP body")?;
        }
        if close {
            self.stream = None;
        }
        Ok(out)
    }
}

fn drain_object_events(
    listener: &mut Connection,
    recipients: &[u32],
    method: &str,
    object: u32,
    path: &str,
    sequence: &mut Option<u16>,
) -> Result<()> {
    if recipients.is_empty() {
        return Ok(());
    }
    let mut expected = BlobBuf::new();
    expected.msg_u32("id", object);
    expected.msg_string("path", path);
    for &recipient in recipients {
        let Some(Incoming::Invoke(event)) = listener.next_incoming(5000)? else {
            return Err("expected object event INVOKE".into());
        };
        require(
            event.objid == recipient
                && event.peer == 0
                && event.method == method
                && event.data == expected.payload()
                && event.fd.is_none(),
            "object event failed full payload validation",
        )?;
        if let Some(previous) = *sequence {
            require(
                event.seq == previous.wrapping_add(1),
                "object event sequence gap",
            )?;
        }
        *sequence = Some(event.seq);
    }
    Ok(())
}

fn main_inner(a: &[String]) -> Result<()> {
    let mode = a.get(1).ok_or(
        "missing mode: rpc/lookup/lookup-fixture/rpc-fixture/exec/http/syslog/serve/snapshot/idle",
    )?;
    match mode.as_str() {
        #[cfg(feature = "registration-phase")]
        "register-phase" => registration_phase::run(a),
        "rpc" | "rpc-wire" => {
            require(
                a.len() == 10,
                "rpc SOCKET OBJECT METHOD INPUT_JSON EXPECT_JSON N WARMUP PIDS",
            )?;
            let payload = object_to_payload(&read_json(&a[5])?);
            let expected = read_json(&a[6])?;
            let mut c = Connection::connect(Some(&a[2]))?;
            let target = c.lookup_id(&a[3], 3000)?;
            // Diagnostic for repeated immutable replies: establish a fully
            // validated reference, then compare every reply's complete DATA
            // bytes. This separates client JSON work from server/IPC costs.
            // The frozen R84 client and ordinary rpc mode remain the timing
            // reference; rpc-wire is never a replacement for that workload.
            let wire_validation = mode == "rpc-wire";
            let mut reference = None;
            measure(
                a[7].parse()?,
                a[8].parse()?,
                &pid_list(&a[9])?,
                |_| {
                    let t = Instant::now();
                    let reply = c.invoke(target, &a[4], &payload, 5000)?;
                    let elapsed = t.elapsed().as_nanos() as u64;
                    if wire_validation {
                        if let Some(reference) = &reference {
                            require(
                                reply.fd.is_none() && reply.data == *reference,
                                "RPC reply changed from reference",
                            )?;
                        } else {
                            // The first warm-up call is the reference: no
                            // uncounted extra request in the outer CPU interval.
                            require(
                                reply.fd.is_none()
                                    && contains(&fields_to_json(&reply.fields())?, &expected),
                                "RPC reference failed validation",
                            )?;
                            reference = Some(reply.data);
                        }
                    } else {
                        require(
                            contains(&fields_to_json(&reply.fields())?, &expected),
                            "RPC reply failed validation",
                        )?;
                    }
                    Ok(elapsed)
                },
                || Ok(()),
            )
        }
        "exec-cpu" => {
            require(a.len() >= 4, "exec-cpu CPU PROGRAM [ARGS...]")?;
            affinity::pin(a[2].parse()?)?;
            use std::os::unix::process::CommandExt;
            Err(Command::new(&a[3]).args(&a[4..]).exec().into())
        }
        "exec-cpu-as" => {
            require(a.len() >= 5, "exec-cpu-as CPU PROGRAM ARGV0 [ARGS...]")?;
            require(
                !a[3].is_empty() && !a[4].is_empty(),
                "PROGRAM and ARGV0 must not be empty",
            )?;
            affinity::pin(a[2].parse()?)?;
            use std::os::unix::process::CommandExt;
            Err(Command::new(&a[3]).arg0(&a[4]).args(&a[5..]).exec().into())
        }
        "register-cycle" | "register-cpu" => {
            require(
                a.len() == 8,
                "register-cycle SOCKET METHODS NAME_BYTES N WARMUP PIDS",
            )?;
            #[cfg(feature = "registration-perf")]
            let profiler = if a[1] == "register-cycle" {
                let pids = pid_list(&a[7])?;
                require(
                    pids.len() == 1,
                    "registration profile requires one daemon PID",
                )?;
                Some(registration_perf::Session::new(pids[0])?)
            } else {
                None
            };
            let count: usize = a[3].parse()?;
            let name_bytes: usize = a[4].parse()?;
            require(
                (1..=64).contains(&count) && (8..=128).contains(&name_bytes),
                "registration fixture outside supported bounds",
            )?;
            let names: Vec<String> = (0..count)
                .map(|i| format!("{i:08}{}", "x".repeat(name_bytes - 8)))
                .collect();
            let policy = [("policy", MsgType::Int32)];
            let methods: Vec<_> = names
                .iter()
                .map(|name| (name.as_str(), &policy[..]))
                .collect();
            let mut expected = BlobBuf::new();
            for name in &names {
                let table = expected.msg_open_table(name);
                expected.msg_u32("policy", MsgType::Int32 as u32);
                expected.msg_close(table);
            }
            let mut c = Connection::connect(Some(&a[2]))?;
            let path = "bench.cycle";
            let id = c.add_object(path, &methods, 5000)?;
            let found = c.lookup(Some(path), 5000)?;
            require(
                found.len() == 1
                    && found[0].id == id
                    && found[0].path == path
                    && found[0].signature == expected.payload(),
                "registration signature failed full byte validation",
            )?;
            c.remove_object(id, 5000)?;
            require(
                c.lookup(None, 5000)?.is_empty(),
                "registration preflight left an object",
            )?;
            #[cfg(feature = "registration-perf")]
            if let Some(mut profiler) = profiler {
                let n = a[5].parse()?;
                let warmup = a[6].parse()?;
                require(
                    n > 0 && n <= 1_000_000 && warmup <= 100_000,
                    "profile loop count out of bounds",
                )?;
                for _ in 0..warmup {
                    let id = c.add_object(path, &methods, 5000)?;
                    c.remove_object(id, 5000)?;
                }
                require(
                    c.lookup(None, 5000)?.is_empty(),
                    "registration warmup left an object",
                )?;
                let measured = profiler.measure(n, || {
                    let start = Instant::now();
                    let id = c.add_object(path, &methods, 5000)?;
                    c.remove_object(id, 5000)?;
                    Ok(start.elapsed().as_nanos() as u64)
                })?;
                require(
                    c.lookup(None, 5000)?.is_empty(),
                    "registration cycle left an object",
                )?;
                profiler.emit(measured, warmup, count, name_bytes);
                return Ok(());
            }
            // Each operation includes encoding, ADD_OBJECT and REMOVE_OBJECT.
            // Preflight signature validation and the final empty check are
            // outside both latency and measured CPU intervals.
            if a[1] == "register-cpu" {
                measure_cpu_loop(a[5].parse()?, a[6].parse()?, &pid_list(&a[7])?, || {
                    let id = c.add_object(path, &methods, 5000)?;
                    c.remove_object(id, 5000)?;
                    Ok(())
                })?;
            } else {
                measure(
                    a[5].parse()?,
                    a[6].parse()?,
                    &pid_list(&a[7])?,
                    |_| {
                        let start = Instant::now();
                        let id = c.add_object(path, &methods, 5000)?;
                        c.remove_object(id, 5000)?;
                        Ok(start.elapsed().as_nanos() as u64)
                    },
                    || Ok(()),
                )?;
            }
            require(
                c.lookup(None, 5000)?.is_empty(),
                "registration cycle left an object",
            )
        }
        "register-watch" => {
            require(
                a.len() == 8,
                "register-watch SOCKET LISTENERS MATCHED_0_OR_1 N WARMUP PIDS",
            )?;
            let count: usize = a[3].parse()?;
            require(
                (1..=8).contains(&count),
                "listener count outside fixture bounds",
            )?;
            require(a[4] == "0" || a[4] == "1", "invalid event matching flag")?;
            let matched = a[4] == "1";
            let mut c = Connection::connect(Some(&a[2]))?;
            let mut listener = Connection::connect(Some(&a[2]))?;
            let mut recipients = Vec::new();
            for _ in 0..count {
                let id = listener.add_anonymous_object(5000)?;
                listener.register_event_handler(
                    id,
                    Some(if matched {
                        "ubus.object.*"
                    } else {
                        "unrelated.*"
                    }),
                    5000,
                )?;
                recipients.push(id);
            }
            let receiving = if matched { &recipients[..] } else { &[] };
            let mut sequence = None;
            let path = "bench.cycle";
            let policy = [("policy", MsgType::Int32)];
            let methods = [("00000000", &policy[..])];
            let id = c.add_object(path, &methods, 5000)?;
            drain_object_events(
                &mut listener,
                receiving,
                "ubus.object.add",
                id,
                path,
                &mut sequence,
            )?;
            let found = c.lookup(Some(path), 5000)?;
            require(
                found.len() == 1 && found[0].id == id && found[0].path == path,
                "watched registration preflight failed",
            )?;
            c.remove_object(id, 5000)?;
            drain_object_events(
                &mut listener,
                receiving,
                "ubus.object.remove",
                id,
                path,
                &mut sequence,
            )?;
            require(
                c.lookup(None, 5000)?.is_empty(),
                "watched registration left an object",
            )?;
            // Timed cycles include full event draining and byte validation;
            // caller and listener CPU share this one benchmark process.
            measure(
                a[5].parse()?,
                a[6].parse()?,
                &pid_list(&a[7])?,
                |_| {
                    let start = Instant::now();
                    let id = c.add_object(path, &methods, 5000)?;
                    drain_object_events(
                        &mut listener,
                        receiving,
                        "ubus.object.add",
                        id,
                        path,
                        &mut sequence,
                    )?;
                    c.remove_object(id, 5000)?;
                    drain_object_events(
                        &mut listener,
                        receiving,
                        "ubus.object.remove",
                        id,
                        path,
                        &mut sequence,
                    )?;
                    Ok(start.elapsed().as_nanos() as u64)
                },
                || Ok(()),
            )?;
            require(
                c.lookup(None, 5000)?.is_empty(),
                "watched registration cycle left an object",
            )?;
            // These reply barriers also park any unexpected asynchronous
            // copies in the connection's pending queue. Check it and the
            // socket after removal, including the nonmatching scenario.
            for id in recipients {
                listener.remove_object(id, 5000)?;
            }
            require(
                listener.next_incoming(0)?.is_none(),
                "unexpected extra object event",
            )?;
            Ok(())
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
        "lookup-fixture" => {
            require(
                a.len() == 8,
                "lookup-fixture SOCKET PATH_OR_* OBJECT_COUNT N WARMUP PIDS",
            )?;
            lookup_fixture(
                &a[2],
                &a[3],
                a[4].parse()?,
                a[5].parse()?,
                a[6].parse()?,
                &pid_list(&a[7])?,
            )
        }
        "rpc-fixture" => {
            require(a.len() == 6, "rpc-fixture SOCKET N WARMUP PIDS")?;
            rpc_fixture(&a[2], a[3].parse()?, a[4].parse()?, &pid_list(&a[5])?)
        }
        "reload-fault-service" => {
            require(a.len() == 4, "reload-fault-service SOCKET PREFIX")?;
            reload_fault::serve(&a[2], &a[3])
        }
        "reload-service" => {
            require(a.len() == 4, "reload-service SOCKET TRANSCRIPT")?;
            reload_exec::serve(&a[2], &a[3])
        }
        "reload-exec" => reload_exec::measure(&a[2..]),
        "fw4-compare" => {
            require(a.len() == 4, "fw4-compare EXPECTED_FILE ACTUAL_FILE")?;
            require(
                fw4_output::normalize(&fs::read(&a[2])?)
                    == fw4_output::normalize(&fs::read(&a[3])?),
                "fw4 output differs after subnet-member ordering normalization",
            )
        }
        "exec" | "exec-strict" | "exec-fw4" => {
            require(
                a.len() >= 8 && a[6] == "--",
                "exec[-strict|-fw4] N WARMUP EXPECT_BYTES PIDS -- PROGRAM ARGS...",
            )?;
            let expected = fs::read(&a[4])?;
            let warmup = a[3].parse()?;
            let mut journal = exec_journal::Journal::from_env(warmup)?;
            let validation = match mode.as_str() {
                "exec-strict" => exec_journal::Validation::Strict,
                "exec-fw4" => {
                    require(
                        journal.is_some(),
                        "exec-fw4 requires a journal and output artifacts",
                    )?;
                    exec_journal::Validation::Fw4
                }
                _ => exec_journal::Validation::Bytes,
            };
            measure(
                a[2].parse()?,
                warmup,
                &pid_list(&a[5])?,
                |i| exec_journal::operation(&mut journal, i, &a[7], &a[8..], &expected, validation),
                || Ok(()),
            )
        }
        "sleep-ms" => {
            require(a.len() == 3, "sleep-ms MILLISECONDS")?;
            let ms = a[2].parse::<u64>()?;
            require(ms <= 60_000, "sleep exceeds 60 seconds")?;
            std::thread::sleep(Duration::from_millis(ms));
            Ok(())
        }
        "event-evidence" => event_evidence::run(&a[2..]),

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
        "http-paced" => {
            // Diagnostic-only build: the release comparison keeps its frozen
            // client. Controlled gaps exercise HTTPD's 50 ms parking boundary.
            require(
                a.len() == 9,
                "http-paced ADDRESS PATH EXPECT_BYTES N CLIENTS GAP_MS PID",
            )?;
            let count: usize = a[5].parse()?;
            let concurrency: usize = a[6].parse()?;
            let gap = Duration::from_millis(a[7].parse()?);
            let pid: u32 = a[8].parse()?;
            require(
                (1..=64).contains(&concurrency)
                    && count >= concurrency
                    && count.is_multiple_of(concurrency)
                    && pid != 0,
                "invalid paced workload",
            )?;
            let expected = fs::read(&a[4])?;
            let mut clients = Vec::new();
            for _ in 0..concurrency {
                let mut client = HttpClient {
                    address: a[2].clone(),
                    stream: None,
                };
                require(
                    client.request("GET", &a[3], &[])? == expected,
                    "warm-up response mismatch",
                )?;
                require(
                    client.stream.is_some(),
                    "server closed a diagnostic connection",
                )?;
                clients.push(client);
            }
            let before = proc_sample(pid)?;
            let stop = std::sync::atomic::AtomicBool::new(false);
            let barrier = std::sync::Barrier::new(concurrency + 1);
            let baseline_tasks: std::collections::BTreeSet<_> =
                fs::read_dir(format!("/proc/{pid}/task"))?
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name())
                    .collect();
            let started = Instant::now();
            let (samples, tasks) = std::thread::scope(|scope| -> Result<_> {
                let observer = scope.spawn(|| {
                    let mut seen = baseline_tasks.clone();
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        if let Ok(entries) = fs::read_dir(format!("/proc/{pid}/task")) {
                            seen.extend(entries.filter_map(|e| e.ok()).map(|e| e.file_name()));
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    seen.len().saturating_sub(baseline_tasks.len())
                });
                let mut workers = Vec::new();
                for mut client in clients {
                    let expected = &expected;
                    let path = &a[3];
                    let barrier = &barrier;
                    workers.push(
                        scope.spawn(move || -> std::result::Result<Vec<u64>, String> {
                            barrier.wait();
                            let mut samples = Vec::new();
                            for _ in 0..count / concurrency {
                                if !gap.is_zero() {
                                    std::thread::sleep(gap);
                                }
                                let t = Instant::now();
                                let body = client
                                    .request("GET", path, &[])
                                    .map_err(|e| e.to_string())?;
                                samples.push(t.elapsed().as_nanos() as u64);
                                if body != *expected || client.stream.is_none() {
                                    return Err(
                                        "paced response mismatch or connection closed".into()
                                    );
                                }
                            }
                            Ok(samples)
                        }),
                    );
                }
                barrier.wait();
                let results: Vec<_> = workers.into_iter().map(|w| w.join()).collect();
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                let tasks = observer.join().map_err(|_| "observer panicked")?;
                let mut samples = Vec::new();
                for result in results {
                    samples.extend(result.map_err(|_| "client panicked")??);
                }
                Ok((samples, tasks))
            })?;
            let wall = started.elapsed();
            let after = proc_sample(pid)?;
            require(
                before.start_ticks == after.start_ticks && samples.len() == count,
                "server replaced or requests missing",
            )?;
            emit(obj([
                ("diagnostic_only", Json::Bool(true)),
                ("successful", integer(count as u64)),
                ("errors", integer(0)),
                ("clients", integer(concurrency as u64)),
                ("gap_ms", integer(gap.as_millis() as u64)),
                ("wall_ns", integer(wall.as_nanos() as u64)),
                ("thread_births_observed_lower_bound", integer(tasks as u64)),
                ("observer_interval_ms", integer(2)),
                ("ticks_per_second", integer(ticks_per_second()?)),
                ("before", proc_json(pid, &before)),
                ("after", proc_json(pid, &after)),
                (
                    "latency_ns",
                    Json::Array(samples.into_iter().map(integer).collect()),
                ),
            ]));
            Ok(())
        }
        "http-resident" => {
            require(
                a.len() == 7,
                "http-resident ADDRESS PATH EXPECT_BYTES CONNECTIONS PID",
            )?;
            let count: usize = a[5].parse()?;
            let pid: u32 = a[6].parse()?;
            require(
                (1..=64).contains(&count) && pid != 0,
                "invalid resident sample size or PID",
            )?;
            let expected = fs::read(&a[4])?;
            let before = proc_sample(pid)?;
            let mut clients = Vec::with_capacity(count);
            for _ in 0..count {
                let mut client = HttpClient {
                    address: a[2].clone(),
                    stream: None,
                };
                for _ in 0..2 {
                    require(
                        client.request("GET", &a[3], &[])? == expected,
                        "resident HTTP body failed byte validation",
                    )?;
                    require(
                        client.stream.is_some(),
                        "resident connection did not stay open",
                    )?;
                }
                clients.push(client);
            }
            std::thread::sleep(Duration::from_millis(200));
            let held = proc_sample(pid)?;
            require(
                held.start_ticks == before.start_ticks,
                "resident server was replaced",
            )?;
            require(
                held.values["fds"] == before.values["fds"] + count as u64,
                "not all resident connections were held",
            )?;
            drop(clients);
            let deadline = Instant::now() + Duration::from_secs(3);
            let after = loop {
                let after = proc_sample(pid)?;
                require(
                    after.start_ticks == before.start_ticks,
                    "resident server was replaced",
                )?;
                if after.values["fds"] == before.values["fds"]
                    && after.values["Threads"] == before.values["Threads"]
                {
                    break after;
                }
                require(
                    Instant::now() < deadline,
                    "resident resources were not released",
                )?;
                std::thread::sleep(Duration::from_millis(20));
            };
            emit(obj([
                ("connections", integer(count as u64)),
                ("requests_per_connection", integer(2)),
                ("response_bytes", integer(expected.len() as u64)),
                ("before", proc_json(pid, &before)),
                ("held", proc_json(pid, &held)),
                ("after_close", proc_json(pid, &after)),
            ]));
            Ok(())
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
                        if fields_to_json(&reply.fields())?
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
    fn http_body_limits_reject_truncated_close_bodies_and_chunk_overflow() {
        fn response(wire: Vec<u8>) -> Result<Vec<u8>> {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let worker = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(&mut socket);
                let mut line = String::new();
                loop {
                    line.clear();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                drop(reader);
                // A rejected response is permitted to close before its tail.
                let _ = socket.write_all(&wire);
            });
            let result = HttpClient {
                address,
                stream: None,
            }
            .request("GET", "/", &[]);
            worker.join().unwrap();
            result
        }
        assert_eq!(
            response(b"HTTP/1.0 200 OK\r\n\r\ncomplete".to_vec()).unwrap(),
            b"complete"
        );
        let mut oversized = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        oversized.extend(std::iter::repeat_n(b'x', 4 * 1024 * 1024 + 1));
        assert_eq!(
            response(oversized).unwrap_err().to_string(),
            "oversized HTTP body"
        );
        let overflow = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n{:x}\r\n",
            usize::MAX
        );
        assert_eq!(
            response(overflow.into_bytes()).unwrap_err().to_string(),
            "oversized HTTP body"
        );
    }

    #[test]
    fn fixture_specs_are_bounded_and_pathless_is_explicit() {
        assert_eq!(fixture_paths(64).len(), 64);
        assert_eq!(fixture_paths(128).first().unwrap(), "bench.filler0001");
        assert_eq!(fixture_paths(128).last().unwrap(), "bench.target");
        assert_eq!(fixture_selector("*", 64).unwrap().0, None);
        assert_eq!(fixture_selector("bench.*", 64).unwrap().0, Some("bench.*"));
        assert!(fixture_selector("*", 63).is_err());
        assert!(fixture_selector("bench.other", 64).is_err());
    }

    #[test]
    fn fixture_lookup_rejects_missing_duplicate_or_changed_bytes() {
        let paths: Vec<String> = vec!["bench.filler0001".into(), "bench.target".into()];
        let signature = serve_signature();
        let entries = paths
            .iter()
            .enumerate()
            .map(|(i, path)| LookupEntry {
                path: path.clone(),
                id: (i + 100) as u32,
                signature: signature.clone(),
            })
            .collect::<Vec<_>>();
        let ids = validate_fixture_lookup(&entries, &paths, None).unwrap();
        assert_eq!(ids, [100, 101]);
        assert!(validate_fixture_lookup(&entries[..1], &paths, None).is_err());
        let mut duplicate = entries.clone();
        duplicate[1].id = duplicate[0].id;
        assert!(validate_fixture_lookup(&duplicate, &paths, None).is_err());
        let mut changed = entries;
        changed[1].signature.push(0);
        assert!(validate_fixture_lookup(&changed, &paths, None).is_err());
    }

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

//! Opt-in durable-through-process-exit evidence. No fsync/power-loss claim.
use super::{integer, obj, Json, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Instant;

pub struct Journal {
    file: File,
    artifacts: PathBuf,
    epoch: Instant,
    warmup: usize,
}
impl Journal {
    pub fn from_env(warmup: usize) -> Result<Option<Self>> {
        let path = std::env::var_os("OWRT_BENCH_EXEC_JOURNAL");
        let artifacts = std::env::var_os("OWRT_BENCH_EXEC_ARTIFACTS");
        match (path, artifacts) {
            (None, None) => Ok(None),
            (Some(path), Some(artifacts)) => Ok(Some(Self {
                file: OpenOptions::new().write(true).create_new(true).open(path)?,
                artifacts: PathBuf::from(artifacts),
                epoch: Instant::now(),
                warmup,
            })),
            _ => Err("exec journal and artifact directory must both be supplied".into()),
        }
    }
    fn record(&mut self, value: Json) -> Result<()> {
        self.file.write_all(&value.to_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        Ok(())
    }
    fn entry(&self, iteration: usize, event: &str, path: &std::path::Path) -> Vec<(String, Json)> {
        vec![
            ("schema".into(), integer(1)),
            ("iteration".into(), integer(iteration as u64)),
            (
                "phase".into(),
                Json::Str(
                    if iteration < self.warmup {
                        "warmup"
                    } else {
                        "measured"
                    }
                    .into(),
                ),
            ),
            ("event".into(), Json::Str(event.into())),
            (
                "monotonic_since_journal_ns".into(),
                integer(self.epoch.elapsed().as_nanos() as u64),
            ),
            (
                "artifact_path".into(),
                Json::Str(path.to_string_lossy().into_owned()),
            ),
        ]
    }
}

pub fn operation(
    journal: &mut Option<Journal>,
    iteration: usize,
    program: &str,
    args: &[String],
    expected: &[u8],
    strict_stderr: bool,
) -> Result<u64> {
    let path = journal
        .as_ref()
        .map(|j| j.artifacts.join(format!("iteration-{iteration:06}")));
    if let (Some(j), Some(path)) = (journal.as_mut(), path.as_ref()) {
        fs::create_dir(path)?;
        j.record(obj(j.entry(iteration, "started", path)))?;
    }
    let start = Instant::now();
    let output = Command::new(program)
        .args(args)
        .env("R84_ITERATION", iteration.to_string())
        .output();
    let elapsed = start.elapsed().as_nanos() as u64;
    let error = match &output {
        Err(e) => Some(format!("spawn: {e}")),
        Ok(o) if !o.status.success() => Some(format!("child exit: {}", o.status)),
        Ok(o) if o.stdout != expected => Some("child stdout failed byte validation".into()),
        Ok(o) if strict_stderr && !o.stderr.is_empty() => Some("child stderr was not empty".into()),
        Ok(_) => None,
    };
    if let (Some(j), Some(path)) = (journal.as_mut(), path.as_ref()) {
        let mut entry = j.entry(
            iteration,
            if error.is_none() {
                "completed"
            } else {
                "failed"
            },
            path,
        );
        entry.push(("latency_ns".into(), integer(elapsed)));
        entry.push((
            "error".into(),
            error.clone().map(Json::Str).unwrap_or(Json::Null),
        ));
        if let Ok(Output {
            status,
            stdout,
            stderr,
        }) = &output
        {
            fs::write(path.join("exec.stdout"), stdout)?;
            fs::write(path.join("exec.stderr"), stderr)?;
            entry.push((
                "exit_code".into(),
                status
                    .code()
                    .map(|n| Json::Int(n as i64))
                    .unwrap_or(Json::Null),
            ));
            entry.push((
                "signal".into(),
                status
                    .signal()
                    .map(|n| Json::Int(n as i64))
                    .unwrap_or(Json::Null),
            ));
        }
        j.record(obj(entry))?;
    }
    if let Some(error) = error {
        return Err(error.into());
    }
    Ok(elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_prefix_failure_bytes_and_no_overwrite() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("exec-journal-{}-{unique}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let artifacts = root.join("artifacts");
        fs::create_dir(&artifacts).unwrap();
        let path = root.join("journal.jsonl");
        let mut journal = Some(Journal {
            file: File::create(&path).unwrap(),
            artifacts: artifacts.clone(),
            epoch: Instant::now(),
            warmup: 1,
        });
        let args = [
            "-c".into(),
            "test \"$R84_ITERATION\" -lt 3 || { echo bad >&2; exit 9; }; echo ok".into(),
        ];
        for i in 0..3 {
            operation(&mut journal, i, "/bin/sh", &args, b"ok\n", false).unwrap();
        }
        assert!(operation(&mut journal, 3, "/bin/sh", &args, b"ok\n", false).is_err());
        let entries: Vec<_> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|s| super::super::json::parse(s).unwrap())
            .collect();
        assert_eq!(entries.len(), 8);
        assert_eq!(entries[1].get("phase"), Some(&Json::Str("warmup".into())));
        assert_eq!(entries[7].get("event"), Some(&Json::Str("failed".into())));
        assert_eq!(entries[7].get("exit_code"), Some(&Json::Int(9)));
        assert_eq!(
            fs::read(artifacts.join("iteration-000003/exec.stderr")).unwrap(),
            b"bad\n"
        );
        assert!(operation(&mut journal, 4, "/bin/echo", &["wrong".into()], b"ok\n", false).is_err());
        assert!(operation(&mut journal, 4, "/bin/echo", &["ok".into()], b"ok\n", false).is_err());
        assert_eq!(
            fs::read(artifacts.join("iteration-000004/exec.stdout")).unwrap(),
            b"wrong\n"
        );
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn strict_exec_rejects_stderr_without_changing_ordinary_exec() {
        let noisy = ["-c".into(), "printf ok; printf warning >&2".into()];
        let quiet = ["-c".into(), "printf ok".into()];
        assert!(operation(&mut None, 0, "/bin/sh", &noisy, b"ok", false).is_ok());
        let error = operation(&mut None, 0, "/bin/sh", &noisy, b"ok", true).unwrap_err();
        assert_eq!(error.to_string(), "child stderr was not empty");
        assert!(operation(&mut None, 0, "/bin/sh", &quiet, b"ok", true).is_ok());
    }

}

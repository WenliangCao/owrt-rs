use std::io;
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum WaitResult {
    Exited(ExitStatus),
    TimedOut,
    Cancelled,
}

pub fn wait(
    child: &mut Child,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> io::Result<WaitResult> {
    let started = Instant::now();
    loop {
        if cancelled.load(Ordering::Relaxed) {
            terminate(child)?;
            return Ok(WaitResult::Cancelled);
        }
        if let Some(status) = child.try_wait()? {
            return Ok(WaitResult::Exited(status));
        }
        if started.elapsed() >= timeout {
            terminate(child)?;
            return Ok(WaitResult::TimedOut);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn terminate(child: &mut Child) -> io::Result<()> {
    match child.kill() {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
        Err(error) => return Err(error),
    }
    let _ = child.wait()?;
    Ok(())
}

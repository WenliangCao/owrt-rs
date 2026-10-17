//! The read-only lease producer runs before PID creation and daemonisation.
//! Its temporary helper only parses bounded records; the runtime script helper
//! is created later with the service's final process identity.
use crate::config::dhcp::DhcpConfig;
use crate::dhcp::lease_file::LeaseFile;
use crate::helper::{Config, Helper, Notice, StartError};
use crate::logging::{emit_early, Logger, Priority};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

pub fn initialize(
    config: &DhcpConfig,
    debug: bool,
    early: &mut Option<Logger>,
) -> Result<Option<LeaseFile>, StartError> {
    if !config.lease_read_only || config.ranges.is_empty() {
        return Ok(None);
    }
    let Some(script) = &config.script else {
        return Ok(None);
    };
    let mut helper = Helper::start_initializer(
        Config {
            script: PathBuf::from(OsString::from_vec(script.clone())),
            script_user: config.script_user.clone(),
            debug,
        },
        config.lease_max,
    )?;
    let mut restored = LeaseFile::default();
    let mut ended = false;
    let mut exited = false;
    loop {
        let notices = helper.step().map_err(|error| StartError {
            code: 3,
            message: format!(
                "lease-init helper failed: {}",
                crate::logging::error_text(&error)
            ),
        })?;
        let mut failure = None;
        for notice in notices {
            match notice {
                Notice::InitRecord(record) => {
                    if restored.records.len() == config.lease_max {
                        failure = Some(StartError {
                            code: 5,
                            message: "too many stored leases".into(),
                        });
                    } else {
                        restored.records.push(record);
                    }
                }
                Notice::InitWarning(warning) => {
                    let priority = if warning == b"failed to parse lease database cleanly" {
                        Priority::Error
                    } else {
                        Priority::Warning
                    };
                    emit_early(early, priority, &warning);
                }
                Notice::InitEnd {
                    invalid_records,
                    clean_end,
                } => {
                    restored.invalid_records = invalid_records;
                    restored.clean_end = clean_end;
                    ended = true;
                }
                Notice::InitExit(status) => {
                    exited = status == 0;
                    if status != 0 {
                        let (code, message) = if status == 126 || status == 127 {
                            (
                                3,
                                format!(
                                    "cannot run lease-init script {}: {}",
                                    String::from_utf8_lossy(script),
                                    crate::logging::error_text(&std::io::Error::from_raw_os_error(
                                        if status == 127 { 2 } else { 13 }
                                    ))
                                ),
                            )
                        } else {
                            (
                                status + 10,
                                format!("lease-init script returned exit code {status}"),
                            )
                        };
                        failure = Some(StartError { code, message });
                    }
                }
                Notice::InitError(code) => {
                    failure = Some(StartError {
                        code,
                        message: if code == 5 {
                            "too many stored leases".into()
                        } else {
                            "cannot parse lease-init database".into()
                        },
                    });
                }
                Notice::Error(_) => {
                    failure = Some(StartError {
                        code: 3,
                        message: "lease-init helper failed".into(),
                    });
                }
                _ => {}
            }
        }
        if helper.is_finished() && !(ended && exited) && failure.is_none() {
            failure = Some(StartError {
                code: 3,
                message: "incomplete lease-init database".into(),
            });
        }
        if let Some(error) = failure {
            emit_early(early, Priority::Critical, error.message.as_bytes());
            emit_early(early, Priority::Critical, b"FAILED to start up");
            return Err(error);
        }
        if helper.is_finished() {
            return Ok(Some(restored));
        }
        let mut fds: Vec<_> = helper
            .poll_fds()
            .into_iter()
            .map(|(fd, events)| dnsmasq_platform::poll::PollFd {
                fd,
                events,
                revents: 0,
            })
            .collect();
        if let Some(logger) = early {
            logger.flush_ready();
            fds.extend(logger.poll_fds().map(|fd| dnsmasq_platform::poll::PollFd {
                fd,
                events: dnsmasq_platform::poll::POLLOUT,
                revents: 0,
            }));
        }
        // Services have not started: this one poll owner waits only on the
        // producer and logging descriptors, including nonblocking child reap.
        dnsmasq_platform::poll::poll_fds(&mut fds, 20).map_err(|error| StartError {
            code: 3,
            message: error.to_string(),
        })?;
    }
}

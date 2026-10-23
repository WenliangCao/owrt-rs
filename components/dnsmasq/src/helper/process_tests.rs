//! Fork tests run only from the dedicated single-threaded process runner.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn script(text: &str) -> (std::path::PathBuf, Config) {
    let folder = std::env::temp_dir().join(format!(
        "dnsmasq-helper-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&folder).unwrap();
    let path = folder.join("script");
    std::fs::write(&path, format!("#!/bin/sh\n{text}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    (
        folder,
        Config {
            script: path,
            script_user: None,
            debug: false,
        },
    )
}
fn until(helper: &mut Helper, predicate: impl Fn(&Helper, &[Notice]) -> bool) -> Vec<Notice> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut notices = Vec::new();
    while !predicate(helper, &notices) {
        assert!(Instant::now() < deadline, "helper timeout: {notices:?}");
        notices.extend(helper.step().unwrap());
        let mut fds: Vec<_> = helper
            .poll_fds()
            .into_iter()
            .map(|(fd, events)| dnsmasq_platform::poll::PollFd {
                fd,
                events,
                revents: 0,
            })
            .collect();
        dnsmasq_platform::poll::poll_fds(&mut fds, 10).unwrap();
    }
    notices
}

fn gated_script(tail: &str) -> (std::path::PathBuf, Config) {
    script(
        &[
            r#"dir=${0%/*}
: > "$dir/started"
n=0
while [ ! -f "$dir/release" ]; do
  n=$((n + 1))
  [ "$n" -lt 500 ] || exit 99
  sleep 0.01
done
"#,
            tail,
        ]
        .concat(),
    )
}

pub(super) fn run() {
    eprintln!("process test: helper::only_unreaped_eof_needs_an_owner_recheck");
    only_unreaped_eof_needs_an_owner_recheck();
    eprintln!(
        "process test: helper::initialization_is_streamed_before_ready_without_waiting_in_owner"
    );
    initialization_is_streamed_before_ready_without_waiting_in_owner();
    eprintln!("process test: helper::initialization_rejects_excess_leases_before_ready");
    initialization_rejects_excess_leases_before_ready();
    eprintln!("process test: helper::initialization_preserves_ignored_sigpipe");
    initialization_preserves_ignored_sigpipe();
    eprintln!("process test: helper::serial_scripts_progress_without_blocking_owner_and_eof_reaps");
    serial_scripts_progress_without_blocking_owner_and_eof_reaps();
    eprintln!("process test: helper::script_output_preserves_empty_lines_and_eof_tail_with_a_bounded_prefix");
    script_output_preserves_empty_lines_and_eof_tail_with_a_bounded_prefix();
    eprintln!("process test: helper::helper_closes_inherited_service_fds_before_script");
    helper_closes_inherited_service_fds_before_script();
    eprintln!("process test: helper::command_handoff_does_not_wait_and_closed_parent_keeps_queued_scripts");
    command_handoff_does_not_wait_and_closed_parent_keeps_queued_scripts();
    eprintln!(
        "process test: helper::unknown_user_is_configuration_failure_and_missing_script_is_event"
    );
    unknown_user_is_configuration_failure_and_missing_script_is_event();
    eprintln!("process test: helper::malformed_ipc_is_rejected_without_executing_fixed_script");
    malformed_ipc_is_rejected_without_executing_fixed_script();
    eprintln!(
        "process test: helper::killed_helper_drops_pipe_frame_without_poisoning_owner_or_reap"
    );
    killed_helper_drops_pipe_frame_without_poisoning_owner_or_reap();
    eprintln!("process test: helper::partial_and_invalid_notice_frames_close_ipc_then_reap");
    partial_and_invalid_notice_frames_close_ipc_then_reap();
}

fn only_unreaped_eof_needs_an_owner_recheck() {
    let (folder, config) = script("exit 0");

    let mut helper = Helper::start(config).unwrap();
    until(&mut helper, |helper, _| helper.ready());
    assert!(!helper.needs_reap(), "live idle helper has no timer");
    // Model EOF observed just before the child's exit becomes waitable.
    // step closes both pipes and remains nonblocking until waitpid catches up.
    helper.eof = true;
    assert!(helper.needs_reap());
    until(&mut helper, |helper, _| helper.is_finished());
    assert!(
        !helper.needs_reap(),
        "reaped helper must not keep an idle timer"
    );
    drop(helper);
    std::fs::remove_dir_all(folder).unwrap();
}
fn initialization_is_streamed_before_ready_without_waiting_in_owner() {
    let (folder, config) = gated_script(r#"[ "$1" = init ] || exit 8; printf lease-data; exit 7"#);

    let mut helper = Helper::start_with_init(config, Some(1)).unwrap();
    until(&mut helper, |_, _| folder.join("started").exists());
    assert!(!helper.ready() && !helper.is_finished());
    std::fs::write(folder.join("release"), b"").unwrap();
    let notices = until(&mut helper, |helper, _| helper.is_finished());
    assert!(!notices
        .iter()
        .any(|notice| matches!(notice, Notice::InitRecord(_))));
    assert!(notices.contains(&Notice::InitExit(7)));
    assert!(!notices.contains(&Notice::Ready));
    std::fs::remove_dir_all(folder).unwrap();
}

fn initialization_rejects_excess_leases_before_ready() {
    let (folder, config) = script(
        r#"printf '%s\n' '0 02:00:00:00:00:01 127.0.0.11 one *' '0 02:00:00:00:00:02 127.0.0.12 two *'"#,
    );

    let mut helper = Helper::start_with_init(config, Some(1)).unwrap();
    let notices = until(&mut helper, |helper, _| helper.is_finished());
    assert!(notices.contains(&Notice::InitError(5)));
    assert!(!notices.contains(&Notice::Ready));
    assert!(!notices
        .iter()
        .any(|notice| matches!(notice, Notice::InitRecord(_))));
    std::fs::remove_dir_all(folder).unwrap();
}

fn initialization_preserves_ignored_sigpipe() {
    let (folder, config) =
        script(r#"kill -PIPE "$$"; printf '%s\n' '0 02:00:00:00:00:01 127.0.0.11 one *'"#);

    let mut helper = Helper::start_initializer(config, 1).unwrap();
    let notices = until(&mut helper, |helper, _| helper.is_finished());
    assert!(notices.iter().any(|notice| matches!(
        notice,
        Notice::InitRecord(record)
            if record.address == Ipv4Addr::new(127, 0, 0, 11)
                && record.hostname.as_deref() == Some(b"one".as_slice())
    )));
    assert!(notices.contains(&Notice::InitExit(0)));
    assert!(!notices.contains(&Notice::Ready));
    std::fs::remove_dir_all(folder).unwrap();
}

fn serial_scripts_progress_without_blocking_owner_and_eof_reaps() {
    let (folder, config) = gated_script("printf '%s\\n' \"$*\"; exit 7");

    let mut helper = Helper::start(config).unwrap();
    until(&mut helper, |h, _| h.ready());
    let event = Event::Lease(super::super::tests::lease());
    assert!(helper.enqueue(&event).unwrap());
    assert!(!helper.enqueue(&event).unwrap());
    helper.step().unwrap();
    until(&mut helper, |_, _| folder.join("started").exists());
    assert!(!helper.is_finished());
    helper.begin_shutdown();
    std::fs::write(folder.join("release"), b"").unwrap();
    let notices = until(&mut helper, |h, _| h.is_finished());
    assert!(notices.contains(&Notice::ScriptExit(7)));
    assert!(notices.contains(&Notice::Reaped(0)));
    let output = notices
        .iter()
        .filter_map(|n| match n {
            Notice::Output(value) => Some(value.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert!(String::from_utf8_lossy(&output).contains("add 02:00:00:00:00:01 192.0.2.10 client"));
    assert!(!std::path::Path::new(&format!("/proc/{}", helper.pid())).exists());
    drop(helper);
    std::fs::remove_dir_all(folder).unwrap();
}

fn script_output_preserves_empty_lines_and_eof_tail_with_a_bounded_prefix() {
    let (folder, config) =
        script("printf 'one\\n\\n'; head -c 4096 /dev/zero | tr '\\000' x; printf '\\ntail'");

    let mut helper = Helper::start(config).unwrap();
    until(&mut helper, |helper, _| helper.ready());
    assert!(helper
        .enqueue(&Event::Lease(super::super::tests::lease()))
        .unwrap());
    helper.begin_shutdown();
    let notices = until(&mut helper, |helper, _| helper.is_finished());
    let lines = notices
        .into_iter()
        .filter_map(|notice| {
            if let Notice::Output(bytes) = notice {
                Some(bytes)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        lines,
        vec![b"one".to_vec(), vec![], vec![b'x'; 1024], b"tail".to_vec()]
    );
    std::fs::remove_dir_all(folder).unwrap();
}
fn helper_closes_inherited_service_fds_before_script() {
    let (folder, mut config) = script("for f in /proc/self/fd/*; do readlink \"$f\"; done");
    let marker = folder.join("must-not-inherit");
    let file = File::create(&marker).unwrap();
    // Clear CLOEXEC to verify helper isolation, not Command's exec closure.
    rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty()).unwrap();
    config.debug = false;

    let mut helper = Helper::start(config).unwrap();
    until(&mut helper, |h, _| h.ready());
    assert!(helper
        .enqueue(&Event::Lease(super::super::tests::lease()))
        .unwrap());
    helper.begin_shutdown();
    let notices = until(&mut helper, |h, _| h.is_finished());
    let output = notices
        .iter()
        .filter_map(|n| match n {
            Notice::Output(value) => Some(value.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert!(!String::from_utf8_lossy(&output).contains("must-not-inherit"));
    assert!(String::from_utf8_lossy(&output).contains("/dev/null"));
    drop(helper);
    drop(file);
    std::fs::remove_dir_all(folder).unwrap();
}

fn command_handoff_does_not_wait_and_closed_parent_keeps_queued_scripts() {
    let (folder, config) = script(
        r#"
dir=${0%/*}
n=0
[ ! -f "$dir/count" ] || read -r n < "$dir/count"
n=$((n + 1))
printf '%s\n' "$n" > "$dir/count"
: > "$dir/started-$n"
if [ "$n" = 1 ]; then
  while [ ! -f "$dir/release" ]; do sleep 0.01; done
fi
echo "output after parent closed: $n"
: > "$dir/done-$n"
case "$n" in 1) exit 7;; 2) kill -USR1 "$$";; esac
"#,
    );

    let mut helper = Helper::start(config).unwrap();
    until(&mut helper, |h, _| h.ready());
    let event = Event::Lease(super::super::tests::lease());
    assert!(helper.enqueue(&event).unwrap());
    until(&mut helper, |_, _| folder.join("started-1").exists());
    assert!(helper.enqueue(&event).unwrap());
    until(&mut helper, |h, _| h.can_enqueue());
    assert!(helper.enqueue(&event).unwrap());
    helper.begin_shutdown();
    assert!(!helper.commands_drained());
    until(&mut helper, |h, _| h.commands_drained());
    assert!(!helper.is_finished());
    assert!(!folder.join("done-1").exists());
    // This is the parent's exit boundary: no event reader survives.
    helper.reader.take();
    std::fs::write(folder.join("release"), b"").unwrap();
    until(&mut helper, |h, _| h.reaped.is_some());
    assert_eq!(helper.reaped, Some(0));
    for number in 1..=3 {
        assert!(folder.join(format!("done-{number}")).exists());
    }
    drop(helper);
    std::fs::remove_dir_all(folder).unwrap();
}

fn unknown_user_is_configuration_failure_and_missing_script_is_event() {
    let (folder, mut config) = script("exit 0");
    config.script_user = Some(b"dnsmasq-m5-nonexistent-user-87943".to_vec());
    assert_eq!(Helper::start(config.clone()).err().unwrap().code, 1);
    config.script_user = None;
    config.script = folder.join("missing");

    let mut helper = Helper::start(config).unwrap();
    until(&mut helper, |h, _| h.ready());
    helper
        .enqueue(&Event::Lease(super::super::tests::lease()))
        .unwrap();
    helper.begin_shutdown();
    let notices = until(&mut helper, |h, _| h.is_finished());
    assert!(notices.contains(&Notice::ExecError(2)));
    assert!(notices.contains(&Notice::Reaped(0)));
    drop(helper);
    std::fs::remove_dir_all(folder).unwrap();
}
fn malformed_ipc_is_rejected_without_executing_fixed_script() {
    let (folder, config) = script("echo unexpected");

    let mut helper = Helper::start(config).unwrap();
    until(&mut helper, |h, _| h.ready());
    helper.pending = wire::frame(&[1, 255]);
    helper.begin_shutdown();
    let notices = until(&mut helper, |h, _| h.is_finished());
    assert!(notices.contains(&Notice::Error(22)));
    assert!(!notices.iter().any(|n| matches!(n, Notice::Output(_))));
    drop(helper);
    std::fs::remove_dir_all(folder).unwrap();
}
fn killed_helper_drops_pipe_frame_without_poisoning_owner_or_reap() {
    let (folder, config) = script("exit 0");

    let mut helper = Helper::start(config).unwrap();
    until(&mut helper, |h, _| h.ready());
    rustix::process::kill_process(
        Pid::from_raw(helper.pid()).unwrap(),
        rustix::process::Signal::KILL,
    )
    .unwrap();
    // A command raced with the helper death; parent write sees EPIPE.
    helper
        .enqueue(&Event::Lease(super::super::tests::lease()))
        .unwrap();
    let notices = until(&mut helper, |h, _| h.is_finished());
    assert!(notices.iter().any(|n| matches!(n, Notice::Reaped(9))));
    assert!(!helper.can_enqueue());
    assert!(helper.pending.is_empty());
    assert!(!std::path::Path::new(&format!("/proc/{}", helper.pid())).exists());
    drop(helper);
    std::fs::remove_dir_all(folder).unwrap();
}
fn partial_and_invalid_notice_frames_close_ipc_then_reap() {
    for partial in [
        vec![8, 0, 0, 0, 1, b'x'],
        vec![0xff, 0xff, 0xff, 0x7f],
        vec![1, 0, 0, 0, 255],
    ] {
        let (folder, config) = script("echo must-not-run");

        let mut helper = Helper::start(config).unwrap();
        until(&mut helper, |h, _| h.ready());
        // Substitute the notice transport only, leaving the real helper
        // idle on its command pipe. EOF/error must close that command pipe,
        // allow normal child exit and still execute the parent's waitpid.
        let (input, output) = pipe().unwrap();
        let mut output = File::from(output);
        output.write_all(&partial).unwrap();
        drop(output);
        nonblocking(&input).unwrap();
        helper.reader = Some(File::from(input));
        let notices = until(&mut helper, |h, _| h.is_finished());
        assert!(notices.contains(&Notice::Error(22)));
        assert!(notices.contains(&Notice::Reaped(0)));
        assert_eq!(helper.poll_fds(), [(-1, POLLIN), (-1, POLLOUT)]);
        assert!(helper.step().unwrap().is_empty());
        assert!(!std::path::Path::new(&format!("/proc/{}", helper.pid())).exists());
        drop(helper);
        std::fs::remove_dir_all(folder).unwrap();
    }
}

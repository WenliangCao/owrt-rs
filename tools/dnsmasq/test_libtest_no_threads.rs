//! Standalone test-launcher diagnostic, never a product path or blanket suite launcher.
use std::ffi::{c_char, c_int, c_long, c_void, CString};
use std::ptr;

unsafe extern "C" {
    fn unshare(flags: c_int) -> c_int;
    fn gettid() -> c_int;
    fn fork() -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn _exit(status: c_int) -> !;
    fn syscall(number: c_long, ...) -> c_long;
    fn posix_spawn(pid: *mut c_int, path: *const c_char, actions: *const c_void,
                   attrs: *const c_void, argv: *const *mut c_char,
                   envp: *const *mut c_char) -> c_int;
    static mut environ: *mut *mut c_char;
}

fn single_main_thread() {
    let count = std::fs::read_dir("/proc/self/task").unwrap().count();
    let pid = std::process::id();
    let tid = unsafe { gettid() };
    let result = unsafe { unshare(0x100) };
    let error = if result == 0 { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap() };
    println!("gate pid={pid} tid={tid} tasks={count} unshare={result} errno={error}");
    assert_eq!(count, 1, "ordinary threaded libtest must fail this control");
    assert_eq!(tid as u32, pid, "test must execute synchronously in the main thread");
    assert_eq!(result, 0);
}

#[test]
fn ordinary_fork_is_allowed() {
    single_main_thread();
    let child = unsafe { fork() };
    if child == 0 { unsafe { _exit(0) } }
    assert!(child > 0);
    let mut status = -1;
    assert_eq!(unsafe { waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);
    println!("ordinary fork and waitpid succeeded");
}

#[test]
fn posix_spawn_is_allowed() {
    single_main_thread();
    let path = CString::new("/bin/true").unwrap();
    let argv = [path.as_ptr().cast_mut(), ptr::null_mut()];
    let mut child = 0;
    assert_eq!(unsafe { posix_spawn(&mut child, path.as_ptr(), ptr::null(),
                                  ptr::null(), argv.as_ptr(), environ) }, 0);
    let mut status = -1;
    assert_eq!(unsafe { waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);
    println!("explicit libc posix_spawn and waitpid succeeded");
}

#[test]
fn command_spawn_is_allowed() {
    single_main_thread();
    assert!(std::process::Command::new("/bin/true").status().unwrap().success());
    println!("Rust Command spawn succeeded");
}

#[test]
fn threads_fail_with_would_block_and_clone3_is_enosys() {
    single_main_thread();
    match std::thread::Builder::new().spawn(|| ()) {
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
        Ok(thread) => { thread.join().unwrap(); panic!("thread unexpectedly created"); }
    }
    // clone3 is syscall 435 on the launcher's two supported Linux architectures.
    assert_eq!(unsafe { syscall(435, ptr::null::<c_void>(), 0usize) }, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(38));
    single_main_thread();
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    assert!(status.lines().any(|line| line == "Seccomp:\t2"));
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    println!("thread WouldBlock, clone3 ENOSYS, Seccomp2/Nnp1 witnessed");
}

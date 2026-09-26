//! Pin only the calling test thread; exec preserves this mask. Production
//! processes, IRQ affinity and CPU governors are never changed here.
use std::io;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod linux {
    use super::io;
    type Mask = [u64; 16];
    unsafe extern "C" {
        fn sched_setaffinity(pid: i32, size: usize, mask: *const Mask) -> i32;
        fn sched_getaffinity(pid: i32, size: usize, mask: *mut Mask) -> i32;
    }

    pub fn current() -> io::Result<Mask> {
        let mut mask = [0; 16];
        // SAFETY: on 64-bit Linux the mask is a 128-byte array of CPU bits.
        // pid 0 selects this thread; output is aligned, writable and sized.
        if unsafe { sched_getaffinity(0, std::mem::size_of::<Mask>(), &mut mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(mask)
    }

    pub fn pin(cpu: usize) -> io::Result<()> {
        if cpu >= 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CPU outside mask",
            ));
        }
        let mut mask = [0; 16];
        mask[cpu / 64] = 1 << (cpu % 64);
        // SAFETY: same Linux CPU-mask ABI as above; only this test thread's
        // scheduling eligibility changes. The mask stays live during the call.
        if unsafe { sched_setaffinity(0, std::mem::size_of::<Mask>(), &mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if current()? != mask {
            return Err(io::Error::other("kernel did not retain requested affinity"));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn pin_available_cpu_in_disposable_thread() {
            std::thread::spawn(|| {
                let mask = current().unwrap();
                let cpu = (0..1024)
                    .find(|&i| mask[i / 64] & (1 << (i % 64)) != 0)
                    .unwrap();
                assert!(pin(1024).is_err());
                pin(cpu).unwrap();
                assert_eq!(
                    current()
                        .unwrap()
                        .iter()
                        .map(|x| x.count_ones())
                        .sum::<u32>(),
                    1
                );
            })
            .join()
            .unwrap();
        }
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use linux::pin;

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
pub fn pin(_: usize) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "affinity ABI requires 64-bit Linux",
    ))
}

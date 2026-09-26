//! Current-process reaped-child counters. Units are us, not an accuracy claim.
//! Linux 6.12.94 exports signal->cutime/cstime separately through timeval;
//! /proc's USER_HZ conversion is avoided, not the underlying CPU accounting.
use std::io;

#[derive(Clone, Copy)]
pub struct Sample {
    pub user_us: u64,
    pub system_us: u64,
}

#[cfg(any(all(target_os = "linux", target_pointer_width = "64"), test))]
mod abi {
    use std::ffi::c_long;
    use std::io;

    #[repr(C)]
    #[derive(Default)]
    pub struct Timeval {
        pub seconds: c_long,
        pub microseconds: c_long,
    }

    // musl 1.2.5 LP64 resource.h includes sixteen reserved longs after the
    // Linux 144-byte prefix. Allocate its complete 272-byte public struct.
    // glibc LP64 uses that same prefix; its shorter write also fits here.
    #[repr(C)]
    #[derive(Default)]
    pub struct Rusage {
        pub user: Timeval,
        pub system: Timeval,
        pub counters: [c_long; 14],
        pub reserved: [c_long; 16],
    }

    pub fn microseconds(value: &Timeval) -> io::Result<u64> {
        if value.seconds < 0 || !(0..1_000_000).contains(&value.microseconds) {
            return Err(io::Error::other("invalid getrusage timeval"));
        }
        (value.seconds as u64)
            .checked_mul(1_000_000)
            .and_then(|v| v.checked_add(value.microseconds as u64))
            .filter(|&v| v <= i64::MAX as u64)
            .ok_or_else(|| io::Error::other("getrusage microseconds overflow"))
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub fn sample() -> io::Result<Sample> {
    use std::ffi::c_int;
    unsafe extern "C" {
        fn getrusage(who: c_int, value: *mut abi::Rusage) -> c_int;
    }
    const RUSAGE_CHILDREN: c_int = -1;
    let mut value = abi::Rusage::default();
    // SAFETY: a full, aligned musl LP64 rusage buffer; the verified Linux/glibc
    // LP64 prefix has identical timeval/long offsets. No PID is accepted:
    // this counter only describes the current process's waited-for children.
    if unsafe { getrusage(RUSAGE_CHILDREN, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Sample {
        user_us: abi::microseconds(&value.user)?,
        system_us: abi::microseconds(&value.system)?,
    })
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
pub fn sample() -> io::Result<Sample> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "getrusage child CPU ABI requires 64-bit Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::abi::{microseconds, Rusage, Timeval};

    #[test]
    fn lp64_layout_and_checked_timeval_conversion() {
        assert_eq!(std::mem::size_of::<Timeval>(), 16);
        assert_eq!(std::mem::align_of::<Rusage>(), 8);
        assert_eq!(std::mem::size_of::<Rusage>(), 272);
        assert_eq!(std::mem::offset_of!(Rusage, system), 16);
        assert_eq!(std::mem::offset_of!(Rusage, counters), 32);
        assert_eq!(std::mem::offset_of!(Rusage, reserved), 144);
        assert_eq!(microseconds(&Timeval::default()).unwrap(), 0);
        assert_eq!(
            microseconds(&Timeval {
                seconds: 3,
                microseconds: 17
            })
            .unwrap(),
            3_000_017
        );
        for value in [
            Timeval {
                seconds: -1,
                microseconds: 0,
            },
            Timeval {
                seconds: 0,
                microseconds: -1,
            },
            Timeval {
                seconds: 0,
                microseconds: 1_000_000,
            },
            Timeval {
                seconds: i64::MAX,
                microseconds: 0,
            },
        ] {
            assert!(microseconds(&value).is_err());
        }
    }
}

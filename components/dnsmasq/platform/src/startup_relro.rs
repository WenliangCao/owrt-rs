//! Finish static musl's self-relocation by protecting the main image's RELRO.
//!
//! Called once, at the start of main: rcrt1 and libc have already applied all
//! relocations and run constructors. Static linkage has no later lazy binding.

use std::ffi::{c_char, c_int, c_void};
use std::io;

#[repr(C)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    offset: u64,
    virtual_address: u64,
    physical_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

// The stable prefix of Linux's dl_phdr_info; later fields are not needed.
#[repr(C)]
struct ImageInfo {
    base: usize,
    name: *const c_char,
    headers: *const ProgramHeader,
    header_count: u16,
}

unsafe extern "C" {
    fn dl_iterate_phdr(
        callback: unsafe extern "C" fn(*mut ImageInfo, usize, *mut c_void) -> c_int,
        data: *mut c_void,
    ) -> c_int;
}

pub fn protect() -> io::Result<()> {
    let mut result = Err(io::Error::other("missing main image program headers"));
    // SAFETY: libc calls the callback synchronously with live program headers;
    // result remains on this stack until enumeration returns.
    unsafe {
        dl_iterate_phdr(
            protect_main_image,
            (&mut result as *mut io::Result<()>).cast(),
        );
    }
    result
}

unsafe extern "C" fn protect_main_image(
    info: *mut ImageInfo,
    size: usize,
    data: *mut c_void,
) -> c_int {
    let protect = || {
        if info.is_null() || size < std::mem::size_of::<ImageInfo>() {
            return Err(io::Error::other("invalid main image program headers"));
        }
        // SAFETY: dl_iterate_phdr supplies this prefix and its readable header
        // array for the duration of the callback. The size was checked above.
        let info = unsafe { &*info };
        if info.headers.is_null() {
            return Err(io::Error::other("missing main image program headers"));
        }
        let headers = unsafe { std::slice::from_raw_parts(info.headers, info.header_count.into()) };
        const PT_GNU_RELRO: u32 = 0x6474_e552;
        let mut ranges = headers.iter().filter(|header| header.kind == PT_GNU_RELRO);
        let range = ranges
            .next()
            .ok_or_else(|| io::Error::other("missing GNU_RELRO"))?;
        if ranges.next().is_some() || range.memory_size == 0 {
            return Err(io::Error::other("invalid GNU_RELRO"));
        }
        let page_size = rustix::param::page_size();
        if !page_size.is_power_of_two() {
            return Err(io::Error::other("invalid page size"));
        }
        let start = info.base.checked_add(range.virtual_address as usize);
        let end = start.and_then(|start| start.checked_add(range.memory_size as usize));
        let (Some(start), Some(end)) = (start, end) else {
            return Err(io::Error::other("GNU_RELRO address overflow"));
        };
        // The pinned linker ends RELRO on a page boundary. Do not round up an
        // unexpected partial last page: it could contain writable .data too.
        if end & (page_size - 1) != 0 {
            return Err(io::Error::other("GNU_RELRO end is not page aligned"));
        }
        let start = start & !(page_size - 1);
        // SAFETY: this range is the main executable's relocated GNU_RELRO
        // segment. Its complete pages are mapped, and require no later writes.
        unsafe {
            rustix::mm::mprotect(
                start as *mut c_void,
                end - start,
                rustix::mm::MprotectFlags::READ,
            )
        }?;
        Ok(())
    };
    // SAFETY: protect passed a live, uniquely borrowed Result as callback data.
    unsafe { *data.cast::<io::Result<()>>() = protect() };
    // The first image is the executable. Never change other images' mappings.
    1
}

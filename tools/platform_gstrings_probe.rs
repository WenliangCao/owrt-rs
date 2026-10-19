// Linux-only regression: the allocation deliberately extends beyond the
// borrowed slice, so the old unsafe ioctl can be observed without a heap OOB.
fn main() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut info = [0u8; 20];
    info[..4].copy_from_slice(&0x37u32.to_ne_bytes());
    info[8..16].copy_from_slice(&(1u64 << 4).to_ne_bytes());
    owrt_platform::netifd::ethtool_query(&socket, "lo", &mut info).unwrap();
    let count = u32::from_ne_bytes(info[16..20].try_into().unwrap()) as usize;
    assert!(count > 0 && count < 1024);
    let mut passed = true;
    for short in [false, true] {
        let mut storage = vec![0xa5; 12 + count * 32];
        storage[..4].copy_from_slice(&0x1bu32.to_ne_bytes());
        storage[4..8].copy_from_slice(&4u32.to_ne_bytes());
        storage[8..12].copy_from_slice(&(if short { 0 } else { count as u32 }).to_ne_bytes());
        let len = if short { 12 } else { storage.len() };
        let result = owrt_platform::netifd::ethtool_query(&socket, "lo", &mut storage[..len]);
        let changed = storage[12..].iter().filter(|v| **v != 0xa5).count();
        let good = if short { result.is_err() && changed == 0 } else { result.is_ok() && changed > 0 };
        println!("{{\"short\":{short},\"slice_bytes\":{len},\"kernel_count\":{count},\"ioctl_ok\":{},\"changed_after_header\":{changed},\"passed\":{good}}}", result.is_ok());
        passed &= good;
    }
    assert!(passed, "kernel wrote beyond the borrowed GSTRINGS slice");
}

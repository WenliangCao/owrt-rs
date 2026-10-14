// Appended to the exact FrameError/encode/framer source by the Python builder.
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

static ALLOC: AtomicU64 = AtomicU64::new(0);
static REALLOC: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

#[cfg(allocation_tracking)]
mod allocation {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    struct Meter;
    unsafe impl GlobalAlloc for Meter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOC.fetch_add(1, Relaxed);
            BYTES.fetch_add(layout.size() as u64, Relaxed);
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) };
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            REALLOC.fetch_add(1, Relaxed);
            BYTES.fetch_add(size as u64, Relaxed);
            unsafe { System.realloc(pointer, layout, size) }
        }
    }
    #[global_allocator]
    static METER: Meter = Meter;
}

struct Sink(usize);
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += black_box(bytes).len();
        Ok(bytes.len())
    }
    fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let count = black_box(buffers).iter().map(|bytes| bytes.len()).sum();
        self.0 += count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn snapshot() -> [u64; 3] {
    [ALLOC.load(Relaxed), REALLOC.load(Relaxed), BYTES.load(Relaxed)]
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mode = &args[1];
    let length: usize = args[2].parse().unwrap();
    let split: usize = args[3].parse().unwrap();
    let iterations: usize = args[4].parse().unwrap();
    let payload = vec![0xa5; length];
    let input = encode_tcp_frame(&payload).unwrap();
    let mut framer = TcpFramer::new();
    // Retain the baseline's steady-state input capacity before counting.
    assert_eq!(framer.push_frame(&input).unwrap().1.unwrap(), payload);
    let mut sink = Sink(0);
    let before = snapshot();
    for _ in 0..iterations {
        if mode == "receive" {
            let (used, output) = if split == 0 {
                framer.push_frame(black_box(&input)).unwrap()
            } else {
                let (used, output) = framer.push_frame(black_box(&input[..split])).unwrap();
                assert_eq!(used, split);
                assert!(output.is_none());
                let (used, output) = framer.push_frame(black_box(&input[split..])).unwrap();
                (used + split, output)
            };
            assert_eq!(used, input.len());
            let output = output.unwrap();
            assert_eq!(black_box(&output).len(), payload.len());
        } else {
            let packet = black_box(&payload).clone();
            #[cfg(vectored_frame)]
            {
                let frame = TcpWriteFrame::new(packet).unwrap();
                assert_eq!(frame.write_from(&mut sink, 0).unwrap(), length + 2);
                black_box(frame);
            }
            #[cfg(not(vectored_frame))]
            {
                let frame = encode_tcp_frame(&packet).unwrap();
                sink.write_all(black_box(&frame)).unwrap();
            }
        }
    }
    let after = snapshot();
    let delta: Vec<_> = before.iter().zip(after).map(|(a, b)| b - a).collect();
    println!("{{\"mode\":\"{mode}\",\"length\":{length},\"split\":{split},\"iterations\":{iterations},\"alloc_realloc_bytes\":{delta:?},\"sent_bytes\":{}}}", sink.0);
}

//! Standalone meter-control fixture; explicit requests distinguish whole-turn
//! accounting from the narrower cached-query step without test-harness threads.
#[path = "../../components/dnsmasq/src/udp_allocation_diagnostic.rs"]
mod meter;
#[global_allocator]
static ALLOCATOR: meter::Meter = meter::Meter;
fn main() {
    use std::alloc::{alloc, alloc_zeroed, dealloc, realloc, Layout};
    use std::hint::black_box;
    {
        let _turn = meter::Turn::new();
        {
            let _step = meter::Step::new();
            meter::classify(meter::Kind::Cached);
            unsafe {
                let initial = Layout::from_size_align(16, 8).unwrap();
                let pointer = black_box(alloc(initial));
                assert!(!pointer.is_null());
                let grown = black_box(realloc(pointer, initial, 32));
                assert!(!grown.is_null());
                dealloc(grown, Layout::from_size_align(32, 8).unwrap());
                let zero_layout = Layout::from_size_align(24, 8).unwrap();
                let zero = black_box(alloc_zeroed(zero_layout));
                assert!(!zero.is_null());
                assert!((0..24).all(|i| *zero.add(i) == 0));
                dealloc(zero, zero_layout);
            }
        }
        // The complete owner-turn total must include this request, while
        // the already completed cache-hit step must not.
        unsafe {
            let layout = Layout::from_size_align(8, 8).unwrap();
            let pointer = black_box(alloc(layout));
            assert!(!pointer.is_null());
            dealloc(pointer, layout);
        }
    }
    {
        let _turn = meter::Turn::new();
        let _step = meter::Step::new();
        meter::classify(meter::Kind::Local);
        unsafe {
            let layout = Layout::from_size_align(8, 8).unwrap();
            let pointer = black_box(alloc(layout));
            assert!(!pointer.is_null());
            dealloc(pointer, layout);
        }
    }
    meter::write_report().unwrap();
}

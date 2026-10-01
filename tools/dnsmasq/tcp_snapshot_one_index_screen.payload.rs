// Generated private index storage and retained-clone/drop gate.
/* CACHE_MODULES */
/* ALLOCATION_AND_CLOCK */
/* IMAGE_API */

use cache::{Cache, Policy};

fn main() {
    drop(Cache::new(0, Policy::default()));
    for retained_first in [false, true] {
        let before = allocation::snapshot()[3];
        cache::screen_index_checks(retained_first);
        assert_eq!(allocation::snapshot()[3], before, "index clones leaked");
    }
    println!("{{\"drop_orders\":2,\"adapter_checks\":true,\"retained_independence\":true,\"balanced\":true}}");
}

//! Excluded cardinality screen for a proposed inline socket-owner set.
//! No product implementation is changed; complete set semantics are checked.
use std::collections::HashSet;
use std::hint::black_box;

trait Owners: Default {
    fn insert(&mut self, id: u64) -> bool;
    fn contains(&self, id: u64) -> bool;
    fn remove(&mut self, id: u64) -> bool;
    fn count(&self) -> usize;
    fn sum(&self) -> u64;
}
impl Owners for HashSet<u64> {
    fn insert(&mut self, id: u64) -> bool { self.insert(id) }
    fn contains(&self, id: u64) -> bool { self.contains(&id) }
    fn remove(&mut self, id: u64) -> bool { self.remove(&id) }
    fn count(&self) -> usize { self.len() }
    fn sum(&self) -> u64 { self.iter().sum() }
}
#[derive(Default)]
struct InlineOwner {
    first: Option<u64>,
    remaining: HashSet<u64>,
}
impl Owners for InlineOwner {
    fn insert(&mut self, id: u64) -> bool {
        match self.first {
            None => {
                if self.remaining.contains(&id) { return false; }
                self.first = Some(id);
                true
            }
            Some(first) if first == id => false,
            Some(_) => self.remaining.insert(id),
        }
    }
    fn contains(&self, id: u64) -> bool {
        self.first == Some(id) || self.remaining.contains(&id)
    }
    fn remove(&mut self, id: u64) -> bool {
        if self.first == Some(id) {
            self.first = None;
            true
        } else {
            self.remaining.remove(&id)
        }
    }
    fn count(&self) -> usize { usize::from(self.first.is_some()) + self.remaining.len() }
    fn sum(&self) -> u64 { self.first.unwrap_or(0) + self.remaining.iter().sum::<u64>() }
}

fn run<T: Owners>(count: u64, iterations: u64) {
    for _ in 0..iterations {
        let mut owners = T::default();
        for id in 0..count { assert!(owners.insert(black_box(id))); }
        assert_eq!(owners.count(), count as usize);
        assert_eq!(owners.sum(), count * (count - 1) / 2);
        for id in 0..count { assert!(owners.contains(black_box(id))); }
        for id in 0..count { assert!(owners.remove(black_box(id))); }
        assert_eq!(owners.count(), 0);
        // Removing the inline entry while others remain must not allow a
        // duplicate remaining ID to occupy that slot.
        if count > 1 {
            assert!(owners.insert(0));
            assert!(owners.insert(1));
            assert!(owners.remove(0));
            assert!(!owners.insert(1));
            assert!(owners.remove(1));
        }
        black_box(owners);
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let count: u64 = args[2].parse().unwrap();
    let iterations: u64 = args[3].parse().unwrap();
    assert!(count > 0 && count <= 150 && iterations > 0);
    if args[1] == "baseline" { run::<HashSet<u64>>(count, iterations); }
    else { assert_eq!(args[1], "inline"); run::<InlineOwner>(count, iterations); }
    println!("{{\"method\":\"{}\",\"owners\":{count},\"iterations\":{iterations},\"baseline_inline_bytes\":{},\"candidate_inline_bytes\":{}}}", args[1], std::mem::size_of::<HashSet<u64>>(), std::mem::size_of::<InlineOwner>());
}

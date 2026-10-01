//! Private representation screen; generated paths select frozen cache sources.
/* CACHE_MODULES */
/* ALLOCATION_AND_CLOCK */

use cache::{Cache, Kind, Policy, Record};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

type Image = Cache;
fn image(cache: Cache) -> Image { cache }
fn mutable(cache: &mut Image) -> &mut Cache { cache }

#[cfg(inline_rdata)]
fn screen_data(bytes: &[u8]) -> cache::RecordData { cache::RecordData::from_slice(bytes) }
#[cfg(not(inline_rdata))]
fn screen_data(bytes: &[u8]) -> Vec<u8> { bytes.to_vec() }

fn stats() -> [i64; 5] {
    #[cfg(allocation_tracking)] { allocation::snapshot() }
    #[cfg(not(allocation_tracking))] { [0; 5] }
}

fn reset_peak() {
    #[cfg(allocation_tracking)] allocation::reset_peak();
}

fn delta(after: [i64; 5], before: [i64; 5]) -> [i64; 5] {
    std::array::from_fn(|i| after[i] - before[i])
}

fn percentile(samples: &[u128], percent: usize) -> u128 {
    let mut samples = samples.to_vec(); samples.sort_unstable();
    samples[(samples.len() * percent).div_ceil(100).saturating_sub(1)]
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let capacity: usize = args[0].parse().unwrap();
    let filled: usize = args[1].parse().unwrap();
    let allocation_mode = args[2] == "allocation";
    let mut records = Vec::with_capacity(filled);
    for index in 0..filled {
        let owner = if index % 10 == 0 {
            format!("record{index:05}.{}.cache.test", "x".repeat(56))
        } else { format!("record{index:05}.cache.test") };
        let (kind, data) = if index % 4 == 3 {
            let mut data = [0; 16];data[..4].copy_from_slice(&[0x20, 1, 0xd, 0xb8]);
            data[12..].copy_from_slice(&(index as u32).to_be_bytes());
            (Kind::Ipv6, screen_data(&data))
        } else { (Kind::Ipv4, screen_data(&[192, 0, 2, (index % 250 + 1) as u8])) };
        records.push(Record { name: wire::Name::from_ascii(&owner).unwrap(), kind, negative: false, data });
    }
    let fallback = wire::Name::from_ascii("missing.cache.test").unwrap();
    // Initialize RandomState outside the cache-population measurement.
    drop(Cache::new(0, Policy::default()));
    let before = stats();let started = cpu_ns();
    let mut cache = Cache::new(capacity, Policy::default());
    for record in &records {
        cache.start_insert();assert!(cache.insert(record.clone(), 100, 3600).is_ok());assert!(cache.commit());
    }
    let cache = image(cache);
    let population_cpu_ns = cpu_ns() - started;
    let population = delta(stats(), before);
    let groups = if allocation_mode { 1 } else { 25 };
    let warm = if allocation_mode { 0 } else { 5 };
    let mut snapshots = Vec::with_capacity(20);
    let mut clone_samples = Vec::with_capacity(groups * 20);
    let mut lookup_samples = Vec::with_capacity(groups * 20);
    let (mut clone_cpu, mut lookup_cpu, mut drop_cpu) = (0u64, 0u64, 0u64);
    let (mut completed, mut hits, mut errors) = (0usize, 0usize, 0usize);
    let (mut clone_allocation, mut lookup_allocation, mut final_allocation) = ([0; 5], [0; 5], [0; 5]);
    let mut peak_extra = 0;
    for group in 0..warm + groups {
        let measured = group >= warm;
        reset_peak();let before_group = stats();
        let started = cpu_ns();
        for _ in 0..20 {
            let started = Instant::now();snapshots.push(black_box(cache.clone()));
            if measured { clone_samples.push(started.elapsed().as_nanos()); }
        }
        let elapsed = cpu_ns() - started;
        if measured { clone_cpu += elapsed;clone_allocation = delta(stats(), before_group); }
        let before_lookup = stats();let started = cpu_ns();
        for (slot, snapshot) in snapshots.iter_mut().enumerate() {
            let selected = if filled == 0 { None } else {
                Some(&records[(slot * (filled / 20).max(1) + group) % filled])
            };
            let owner = selected.map_or(&fallback, |record| &record.name);
            let kind = selected.map_or(Kind::Ipv4, |record| record.kind);
            let started = Instant::now();
            let cache = mutable(snapshot);let found = cache.lookup(owner, &[kind], 100, false);
            let elapsed = started.elapsed().as_nanos();
            let correct = if let Some(record) = selected {
                found.len() == 1 && cache.get(found[0]).is_some_and(|entry| {
                    entry.record.name == record.name && entry.record.data.as_slice() == record.data.as_slice()
                        && entry.expires == 3700 && !entry.record.negative
                })
            } else { found.is_empty() };
            if measured {
                lookup_samples.push(elapsed);completed += 1;hits += found.len();errors += usize::from(!correct);
            }
            black_box(found);
        }
        let elapsed = cpu_ns() - started;
        if measured {
            lookup_cpu += elapsed;lookup_allocation = delta(stats(), before_lookup);
            peak_extra = peak_extra.max(stats()[4] - before_group[3]);
        }
        let started = cpu_ns();snapshots.clear();let elapsed = cpu_ns() - started;
        if measured {
            drop_cpu += elapsed;final_allocation = delta(stats(), before_group);
            errors += usize::from(final_allocation[3] != 0);
        }
    }
    assert_eq!(completed, groups * 20);assert_eq!(hits, if filled == 0 { 0 } else { completed });
    let combined_samples: Vec<_> = clone_samples.iter().zip(&lookup_samples).map(|(a,b)| a+b).collect();
    let combined_wall_ns: u128 = combined_samples.iter().sum();
    let before_drop = stats();drop(cache);let population_drop = stats()[3] - before_drop[3];
    errors += usize::from(allocation_mode && population_drop != -population[3]);
    let layout = cache::screen_layout();
    println!("{{\"capacity\":{capacity},\"filled\":{filled},\"completed\":{completed},\"hits\":{hits},\"errors\":{errors},\"population_cpu_ns\":{population_cpu_ns},\"clone_cpu_ns\":{clone_cpu},\"lookup_cpu_ns\":{lookup_cpu},\"drop_cpu_ns\":{drop_cpu},\"population_allocation\":{population:?},\"clone_allocation\":{clone_allocation:?},\"lookup_allocation\":{lookup_allocation:?},\"final_allocation\":{final_allocation:?},\"peak_extra_requested\":{peak_extra},\"population_drop\":{population_drop},\"layout\":{layout:?},\"image_layout\":{},\"clone_p50_ns\":{},\"clone_p95_ns\":{},\"lookup_p50_ns\":{},\"lookup_p95_ns\":{},\"combined_p50_ns\":{},\"combined_p95_ns\":{},\"combined_wall_ns\":{combined_wall_ns},\"clone_samples_ns\":{clone_samples:?},\"lookup_samples_ns\":{lookup_samples:?}}}",
        std::mem::size_of::<Image>(),percentile(&clone_samples,50),percentile(&clone_samples,95),percentile(&lookup_samples,50),percentile(&lookup_samples,95),percentile(&combined_samples,50),percentile(&combined_samples,95));
    assert_eq!(errors, 0);
}

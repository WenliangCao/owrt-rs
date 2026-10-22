//! Measure the actual UCI library stages used by rpcd. Times exclude ubus,
//! ACLs and reply construction; use the daemon benchmark for end-to-end gains.
//! Usage: uci_profile <config-directory> [iterations] [stage-filter]

use owrt_uci::{file, parse, Context, ReadCache};
use std::hint::black_box;
use std::io::Cursor;

mod profile_support;
use profile_support::measure;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let dir = args.get(1).expect("config directory");
    let n: u64 = args
        .get(2)
        .map(|s| s.parse().expect("iterations"))
        .unwrap_or(20000);
    let filter = args.get(3).map(String::as_str).unwrap_or("");
    assert!(n > 0);
    println!("stage,iterations,ns_per_op,allocs,reallocs,requested_bytes");
    measure("context_new", n, filter, || {
        black_box(Context::new());
    });
    let mut listing = Context::new();
    listing.set_confdir(dir);
    measure("list_config_files", n, filter, || {
        black_box(file::list_config_files(&listing).expect("list fixture configs"));
    });
    for name in ["network", "r84fixture"] {
        let bytes = std::fs::read(format!("{dir}/{name}"))?;
        let stage = format!("parse_{name}");
        measure(&stage, n, filter, || {
            let mut ctx = Context::new();
            let mut input = Cursor::new(black_box(bytes.as_slice()));
            parse::import(&mut ctx, &mut input, Some(name), None, true).unwrap();
            black_box(ctx);
        });
        let stage = format!("load_{name}");
        measure(&stage, n, filter, || {
            let mut ctx = Context::new();
            ctx.set_confdir(dir);
            file::load(&mut ctx, name).unwrap();
            black_box(ctx);
        });
        let mut cache = ReadCache::default();
        let stage = format!("cached_warm_{name}");
        measure(&stage, n, filter, || {
            let mut ctx = Context::new();
            ctx.set_confdir(dir);
            let pidx = file::load_cached(&mut ctx, name, &mut cache).unwrap();
            cache.recycle(black_box(ctx.root.remove(pidx)));
            black_box(ctx);
        });
        let stage = format!("cached_cold_{name}");
        measure(&stage, n, filter, || {
            let mut ctx = Context::new();
            ctx.set_confdir(dir);
            file::load_cached(&mut ctx, name, &mut ReadCache::default()).unwrap();
            black_box(ctx);
        });
    }
    for cached in [false, true] {
        // One measured operation is a two-file pair, so both the timing and
        // allocation probe cover the same mix (measure counts one probe call).
        let stage = if cached {
            "cached_alternating_pair"
        } else {
            "load_alternating_pair"
        };
        let mut cache = ReadCache::default();
        measure(stage, n, filter, || {
            for name in ["network", "r84fixture"] {
                let mut ctx = Context::new();
                ctx.set_confdir(dir);
                if cached {
                    let pidx = file::load_cached(&mut ctx, name, &mut cache).unwrap();
                    cache.recycle(black_box(ctx.root.remove(pidx)));
                } else {
                    file::load(&mut ctx, name).unwrap();
                }
                black_box(ctx);
            }
        });
    }
    Ok(())
}

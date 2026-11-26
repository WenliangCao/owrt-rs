//! `owrt-tools`: host-only build, release, device-window and benchmark
//! tooling. Never shipped to a router.
//!
//! The binary dispatches on its subcommand, or on its own file name when the
//! SDK recipe invokes a copy installed as `pgo-cargo` or `map-cc`.

mod bench;
mod device;
mod dnsmasq_ci;
mod dnsmasq_package;
mod history;
mod native_check;
mod native_image;
mod native_release;
mod pgo_wrappers;
mod rust_check;
mod util;
mod warnings;

use std::path::Path;

const USAGE: &str = "usage: owrt-tools <command> [args]

commands:
  rust-check                       workspace fmt/clippy/test gates
  warnings OUTPUT LOG...           strict compiler-warning scan
  dnsmasq-build-package            SDK package build and audit
  ci-build-dnsmasq WORK            release dnsmasq build (frozen PGO)
  ci-check-dnsmasq-target WORK     diagnostic dnsmasq target build
  ci-check-dnsmasq-pgo-pipeline    canonical PGO stage build
  native-image ACTION WORK SPEC APK fetch|prepare|verify the native image
  native-image-check ROOTFS OUT    offline migration/recovery/reinstall checks
  native-package-reinstall-selftest ROOTFS APKS OUT
  native-apk-fixtures ROOTFS NATIVE_APK APK OUT
  native-release-prepare CANONICAL VALIDATION TAG EVIDENCE OUT
  native-trial-prepare CONFIG MANIFEST BOUNDED OUT --rootfs R ...
  native-deploy-window stage|activate|observe DIR  (Mac-side; authorized windows only)
  device-probe [--mode M] [--native-manifest F]    (Mac-side, read-only)
  run-candidate CANDIDATE OUTPUT --interface IF [options]  (Mac-side; authorized windows only)
  analyze PRIVATE --manifest M --output OUT [--partial]
  analyze-candidate PRIVATE --output DIR --label LABEL
  json-field FILE KEY...           print one string field of a JSON file";

fn json_field(raw: &[String]) -> util::Result<i32> {
    let (file, keys) = raw
        .split_first()
        .ok_or_else(|| util::Error::new("usage: json-field FILE KEY..."))?;
    let mut value = &util::read_json(Path::new(file))?;
    for key in keys {
        value = value
            .get(key)
            .ok_or_else(|| util::Error::new(format!("{file}: missing {key}")))?;
    }
    match value.as_str() {
        Some(text) => println!("{text}"),
        None => println!("{value}"),
    }
    Ok(0)
}

fn dispatch(program: &str, args: &[String]) -> util::Result<i32> {
    match program {
        pgo_wrappers::PGO_CARGO => return pgo_wrappers::pgo_cargo(args),
        pgo_wrappers::MAP_CC => return pgo_wrappers::map_cc(args),
        _ => {}
    }
    let Some((command, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return Ok(2);
    };
    match command.as_str() {
        "rust-check" => rust_check::main(rest),
        "warnings" => warnings::main(rest),
        "dnsmasq-build-package" => dnsmasq_package::main(rest),
        "ci-build-dnsmasq" => dnsmasq_ci::build_main(rest),
        "ci-check-dnsmasq-target" => dnsmasq_ci::target_main(rest),
        "ci-check-dnsmasq-pgo-pipeline" => dnsmasq_ci::pgo_pipeline_main(rest),
        "native-image" => native_image::main(rest),
        "native-image-check" => native_check::check_main(rest),
        "native-package-reinstall-selftest" => native_check::reinstall_selftest_main(rest),
        "native-apk-fixtures" => native_check::apk_fixtures_main(rest),
        "native-release-prepare" => native_release::main(rest),
        "native-trial-prepare" => device::trial_main(rest),
        "native-deploy-window" => device::deploy_main(rest),
        "device-probe" => device::probe_main(rest),
        "run-candidate" => bench::run_candidate::main(rest),
        "analyze" => bench::analyze::main(rest),
        "analyze-candidate" => bench::candidate::main(rest),
        "json-field" => json_field(rest),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(0)
        }
        other => {
            eprintln!("owrt-tools: unknown command {other:?}\n{USAGE}");
            Ok(2)
        }
    }
}

fn main() {
    let argv = util::os_args();
    let program = argv
        .first()
        .and_then(|arg| Path::new(arg).file_name())
        .map(|name| name.to_string_lossy().into_owned());
    let code = dispatch(
        program.as_deref().unwrap_or_default(),
        argv.get(1..).unwrap_or_default(),
    )
    .unwrap_or_else(|error| {
        eprintln!("owrt-tools: {error}");
        1
    });
    std::process::exit(code);
}

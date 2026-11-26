//! Strict compiler-warning gate shared by the core, image and dnsmasq builds.
//!
//! Every `warning:` line fails the build unless it is one of the few SDK
//! metadata diagnostics the unmodified OpenWrt SDK always prints.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use crate::util::{self, Args, Result};

static ANSI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]").unwrap());
static WARNING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bwarning(?:\[[^\]]+\])?:").unwrap());
static SDK_WARNING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:WARNING: Makefile '.+' has a dependency on '.+', which does not exist$|",
        r"(?:[^\s:]+/)?(?:\.config(?:-[^\s:]+)?(?:\.in)?|Config(?:-[^\s:]+)?\.in):\d+:warning:|",
        r"Makefile:\d+: WARNING: skipping [A-Za-z0-9_+.-]+ -- package has no install section$|",
        r"WARNING: can't open config file: /builder/shared-workdir/build/staging_dir/host/etc/ssl/openssl\.cnf$)"
    ))
    .unwrap()
});
/// ImageBuilder checks its empty local repository before creating the index.
static INITIAL_INDEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^WARNING: opening /[^\s]+/openwrt-imagebuilder-[0-9]+\.[0-9]+\.[0-9]+-",
        r"[^/\s]+/packages/packages\.adb: No such file or directory$"
    ))
    .unwrap()
});

/// Classifies every warning line in `logs` (missing files are skipped by
/// callers). Only known SDK metadata warnings are exempt.
pub fn scan(logs: &[PathBuf]) -> Result<Value> {
    let mut compiler = Vec::new();
    let mut sdk = Vec::new();
    for path in logs {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        for (index, raw) in util::splitlines(&util::read_lossy(path)?)
            .into_iter()
            .enumerate()
        {
            let line = ANSI.replace_all(raw, "");
            let line = line.trim();
            if WARNING.is_match(line) {
                let entry = json!({"log": name, "line": index + 1, "text": line});
                if SDK_WARNING.is_match(line) {
                    sdk.push(entry)
                } else {
                    compiler.push(entry)
                }
            }
        }
    }
    let zero = compiler.is_empty();
    Ok(
        json!({"compiler_or_unclassified": compiler, "sdk_metadata": sdk, "strict_compiler_warnings_zero": zero}),
    )
}

/// `*.log` files directly inside `directory`, sorted.
pub fn logs_in(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut logs: Vec<PathBuf> = match std::fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "log") && path.is_file())
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    logs.sort();
    Ok(logs)
}

/// The image/core gate: [`scan`] plus the ImageBuilder initial-index notice,
/// accepted only in `image.log`. Writes the report to `output`.
pub fn gate(output: &Path, logs: &[PathBuf]) -> Result<Value> {
    let files: Vec<PathBuf> = logs.iter().filter(|path| path.is_file()).cloned().collect();
    let mut result = scan(&files)?;
    let entries = result["compiler_or_unclassified"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let (metadata, compiler): (Vec<Value>, Vec<Value>) = entries.into_iter().partition(|entry| {
        entry["log"] == "image.log" && INITIAL_INDEX.is_match(entry["text"].as_str().unwrap_or(""))
    });
    result["sdk_metadata"]
        .as_array_mut()
        .expect("scan returns an array")
        .extend(metadata);
    let zero = compiler.is_empty();
    result["compiler_or_unclassified"] = Value::Array(compiler);
    result["strict_compiler_warnings_zero"] = Value::Bool(zero);
    util::write_json(output, &result)?;
    println!(
        "compiler/unclassified warnings: {}; SDK metadata warnings: {}",
        result["compiler_or_unclassified"]
            .as_array()
            .map_or(0, Vec::len),
        result["sdk_metadata"].as_array().map_or(0, Vec::len)
    );
    Ok(result)
}

/// `owrt-tools warnings OUTPUT LOG...`: exit 1 on any compiler warning.
pub fn main(raw: &[String]) -> Result<i32> {
    let args = Args::parse(raw, &[], &[])?;
    let (output, logs) = args
        .positional()
        .split_first()
        .ok_or_else(|| util::Error::new("usage: warnings OUTPUT LOG..."))?;
    util::ensure!(!logs.is_empty(), "usage: warnings OUTPUT LOG...");
    let logs: Vec<PathBuf> = logs.iter().map(PathBuf::from).collect();
    let result = gate(Path::new(output), &logs)?;
    Ok(if result["strict_compiler_warnings_zero"] == true {
        0
    } else {
        1
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    const INDEX: &str =
        "WARNING: opening /work/openwrt-imagebuilder-25.12.5-mediatek-filogic.Linux-x86_64/\
                         packages/packages.adb: No such file or directory";

    fn classify(name: &str, text: &str) -> Value {
        let directory = TempDir::new("warnings");
        let log = directory.path().join(name);
        std::fs::write(&log, format!("{text}\n")).unwrap();
        gate(&directory.path().join("warnings.json"), &[log]).unwrap()
    }

    #[test]
    fn initial_local_index_is_metadata_only_in_the_image_log() {
        let accepted = classify("image.log", INDEX);
        assert_eq!(accepted["strict_compiler_warnings_zero"], true);
        assert_eq!(accepted["sdk_metadata"].as_array().unwrap().len(), 1);
        let rejected = classify("compile.log", INDEX);
        assert_eq!(rejected["strict_compiler_warnings_zero"], false);
        assert_eq!(
            rejected["compiler_or_unclassified"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn other_missing_paths_and_compiler_warnings_still_fail() {
        for text in [
            INDEX.replace("packages.adb", "other.adb"),
            INDEX.replace("openwrt-imagebuilder-", "openwrt-sdk-"),
            format!("warning: linker stderr: {INDEX}"),
            format!("{INDEX}\nwarning: an actual compiler diagnostic"),
        ] {
            assert_eq!(
                classify("image.log", &text)["strict_compiler_warnings_zero"],
                false,
                "{text}"
            );
        }
    }

    #[test]
    fn sdk_metadata_forms_are_exempt_and_rust_forms_fail() {
        let directory = TempDir::new("scan");
        let log = directory.path().join("compile.log");
        std::fs::write(
            &log,
            "\x1b[33mwarning\x1b[0m: unused variable\n\
             warning[E0599]: x\n\
             Config.in:12:warning: ignoring\n\
             WARNING: Makefile 'package/a/Makefile' has a dependency on 'b', which does not exist\n\
             Makefile:9: WARNING: skipping foo -- package has no install section\n\
             WARNING: can't open config file: /builder/shared-workdir/build/staging_dir/host/etc/ssl/openssl.cnf\n\
             WARNING: can't open config file: /usr/lib/ssl/openssl.cnf\n",
        )
        .unwrap();
        let result = scan(&[log]).unwrap();
        let lines = |key: &str| -> Vec<u64> {
            result[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["line"].as_u64().unwrap())
                .collect()
        };
        assert_eq!(lines("compiler_or_unclassified"), [1, 2, 7]);
        assert_eq!(lines("sdk_metadata"), [3, 4, 5, 6]);
        assert_eq!(
            result["compiler_or_unclassified"][0]["text"],
            "warning: unused variable"
        );
    }
}

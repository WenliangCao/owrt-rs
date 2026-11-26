//! `core-manifest OUT COMMIT VERSION STAGING BINARY...`: the identity record
//! `ci_build_core.sh` writes after packing the standalone core binaries.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use serde_json::{json, Value};

use crate::util::{self, bail, ensure, Result};

pub fn manifest(
    out: &Path,
    commit: &str,
    version: &str,
    staging: &Path,
    binaries: &[String],
) -> Result<Value> {
    let image = util::read_json(&out.join("manifest.json"))?;
    ensure!(
        image["source_commit"] == commit && image["openwrt"] == version,
        "image manifest is for another source or release"
    );
    let expected: BTreeSet<&str> = binaries.iter().map(String::as_str).collect();
    // Python dict order: the checksum file's order.
    let mut hashes = serde_json::Map::new();
    for line in util::splitlines(&util::read_text(&out.join("core-binary-sha256.txt"))?) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [digest, name] = fields[..] else {
            bail!("invalid core checksum row: {line}")
        };
        hashes.insert(name.to_owned(), json!(digest));
    }
    ensure!(
        hashes.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected,
        "core checksums differ from the built binaries"
    );
    let archive = out.join("core-binaries.tar.gz");
    let mut members = BTreeSet::new();
    let mut count = 0;
    for entry in tar::Archive::new(flate2::read::GzDecoder::new(File::open(&archive)?)).entries()? {
        let mut entry = entry?;
        let name = util::display(&entry.path()?);
        ensure!(
            entry.header().entry_type().is_file() && entry.header().mode()? & 0o111 != 0,
            "{name} is not an executable file"
        );
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        ensure!(
            hashes.get(&name).and_then(Value::as_str) == Some(util::sha256_bytes(&data).as_str()),
            "{name} differs from its checksum"
        );
        members.insert(name);
        count += 1;
    }
    ensure!(
        count == expected.len()
            && members.iter().map(String::as_str).collect::<BTreeSet<_>>() == expected,
        "core archive members differ from the built binaries"
    );
    let sdk = staging
        .parent()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(json!({
        "source_commit": commit,
        "openwrt": version,
        "target": "aarch64-unknown-linux-musl",
        "sdk": sdk,
        "binary_sha256": hashes,
        "archive": {"file": "core-binaries.tar.gz", "sha256": util::sha256_file(&archive)?},
        "image_manifest_sha256": util::sha256_file(&out.join("manifest.json"))?,
        "toolchain_identity_sha256": util::sha256_file(&out.join("core-toolchain.log"))?,
        "deployment": "Standalone binaries; not activated by the generated image or by artifact creation.",
        "flashed": false,
    }))
}

pub fn main(raw: &[String]) -> Result<i32> {
    let [out, commit, version, staging, binaries @ ..] = raw else {
        bail!("usage: core-manifest OUT COMMIT VERSION STAGING BINARY...")
    };
    let out = Path::new(out);
    let value = manifest(out, commit, version, Path::new(staging), binaries)?;
    fs::write(
        out.join("core-manifest.json"),
        util::pretty_json(&value) + "\n",
    )?;
    println!("{}", util::pretty_json(&value));
    Ok(0)
}

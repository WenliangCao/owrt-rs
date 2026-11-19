#!/bin/sh
# Install the checksum-pinned Cargo fork after rustup installs the compiler.
set -eu
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || {
    echo 'canonical Cargo installer requires x86_64 Linux' >&2
    exit 1
}
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
curl --fail --silent --show-error --location \
    https://github.com/huacnlee/cargo/releases/download/v0.103.0-1/cargo-0.103.0-1-x86_64-unknown-linux-gnu.tar.gz \
    --output "$temporary/cargo.tar.gz"
echo "681505dec73335d593da1ae4e0492423344799757ef505193233f68b3bc6e103  $temporary/cargo.tar.gz" | sha256sum --check --strict
tar -xzf "$temporary/cargo.tar.gz" -C "$temporary"
mkdir -p "$HOME/.local/bin"
install -m 755 "$temporary/cargo" "$HOME/.local/bin/cargo"
if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$HOME/.local/bin" >> "$GITHUB_PATH"
fi
"$HOME/.local/bin/cargo" -V | grep -F 'huacnlee/cargo 0.103.0-1'

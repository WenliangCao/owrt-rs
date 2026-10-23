#!/bin/sh
# Install the checksum-pinned x86_64 Linux cache used by canonical CI builds.
set -eu
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || {
    echo 'canonical mbx installer requires x86_64 Linux' >&2
    exit 1
}
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
curl --fail --silent --show-error --location \
    https://github.com/jdx/mr-boxington/releases/download/v1.26.0/mbx-x86_64-unknown-linux-gnu.tar.gz \
    --output "$temporary/mbx.tar.gz"
echo "decb2c1233d194d9d8f98fa926d86a5f726e9091e92fcff75f44a53ed9cab2b9  $temporary/mbx.tar.gz" | sha256sum --check --strict
tar -xzf "$temporary/mbx.tar.gz" -C "$temporary"
mkdir -p "$HOME/.local/bin"
install -m 755 "$temporary/mbx" "$HOME/.local/bin/mbx"
if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$HOME/.local/bin" >> "$GITHUB_PATH"
fi
"$HOME/.local/bin/mbx" --version

#!/usr/bin/env bash
# publish-if-new.sh <crate> <token>: cargo publish unless that exact version
# already exists on crates.io. Asks the registry API, not cargo, because
# inside the workspace `cargo info` resolves to the local package.
set -euo pipefail
crate="$1"
token="$2"
version=$(cargo pkgid -p "$crate" | sed -E 's/.*[#@]([0-9].*)/\1/')
if curl -sf -A "firn-publish (github actions)" \
    "https://crates.io/api/v1/crates/${crate}/${version}" >/dev/null; then
  echo "${crate} ${version} is already on crates.io; skipping"
  exit 0
fi
cargo publish -p "$crate" --token "$token"

#!/bin/sh
# Install the firn CLI from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/wseaton/firn/stable/install.sh | sh
#
# FIRN_VERSION      release to install, e.g. 0.1.2 (default: latest cli-v* release)
# FIRN_INSTALL_DIR  destination directory (default: ~/.local/bin)
set -eu

repo="wseaton/firn"
install_dir="${FIRN_INSTALL_DIR:-$HOME/.local/bin}"

fail() {
    echo "install.sh: $*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

need curl
need tar

case "$(uname -s)" in
    Darwin) os="apple-darwin" ;;
    Linux)  os="unknown-linux-gnu" ;;
    *)      fail "unsupported OS $(uname -s); download a release from https://github.com/${repo}/releases" ;;
esac

case "$(uname -m)" in
    x86_64 | amd64)  arch="x86_64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *)               fail "unsupported architecture $(uname -m)" ;;
esac
target="${arch}-${os}"

if [ -n "${FIRN_VERSION:-}" ]; then
    version="${FIRN_VERSION#cli-v}"
    version="${version#v}"
else
    version=$(curl -fsSL "https://api.github.com/repos/${repo}/releases?per_page=100" \
        | grep -o '"tag_name": *"cli-v[^"]*"' \
        | head -n 1 \
        | sed 's/.*"cli-v\(.*\)"/\1/')
    [ -n "$version" ] || fail "could not find a cli-v* release for ${repo}"
fi

tag="cli-v${version}"
name="firn-${version}-${target}"
base="https://github.com/${repo}/releases/download/${tag}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading ${name}.tar.gz from ${tag}"
curl -fsSL -o "${tmp}/${name}.tar.gz" "${base}/${name}.tar.gz"
curl -fsSL -o "${tmp}/SHA256SUMS" "${base}/SHA256SUMS"

expected=$(grep " ${name}.tar.gz\$" "${tmp}/SHA256SUMS" | cut -d ' ' -f 1)
[ -n "$expected" ] || fail "${name}.tar.gz is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "${tmp}/${name}.tar.gz" | cut -d ' ' -f 1)
else
    actual=$(shasum -a 256 "${tmp}/${name}.tar.gz" | cut -d ' ' -f 1)
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for ${name}.tar.gz"

tar -C "$tmp" -xzf "${tmp}/${name}.tar.gz"
mkdir -p "$install_dir"
install -m 755 "${tmp}/${name}/firn" "${install_dir}/firn"
echo "installed firn ${version} to ${install_dir}/firn"

case ":${PATH}:" in
    *":${install_dir}:"*) ;;
    *) echo "add ${install_dir} to your PATH" ;;
esac

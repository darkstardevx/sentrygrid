#!/usr/bin/env bash
# Install SentryGrid from the latest GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/darkstardevx/sentrygrid/main/install.sh | sh
#
# Supported: Linux (x86_64, aarch64) only -- SentryGrid shells out to
# `ss` and `ufw`, both Linux-specific, so there's no macOS build.
set -eu

REPO="darkstardevx/sentrygrid"
INSTALL_DIR="${SENTRYGRID_INSTALL_DIR:-$HOME/.local/bin}"

die() {
  echo "error: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found on PATH"
}

need curl
need tar

if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
  die "need either 'shasum' or 'sha256sum' on PATH"
fi

sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$1"
  else
    shasum -a 256 -c "$1"
  fi
}

os="$(uname -s)"
case "$os" in
  Linux) : ;;
  *) die "unsupported OS: $os (SentryGrid shells out to ss/ufw, both Linux-only)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) die "unsupported architecture: $arch" ;;
esac

target="${arch}-unknown-linux-gnu"
archive="sentrygrid-${target}.tar.gz"
base_url="https://github.com/${REPO}/releases/latest/download"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "Downloading ${archive}..."
curl -fsSL "${base_url}/${archive}" -o "${tmp_dir}/${archive}"
curl -fsSL "${base_url}/${archive}.sha256" -o "${tmp_dir}/${archive}.sha256"

echo "Verifying checksum..."
(cd "$tmp_dir" && sha256_check "${archive}.sha256")

echo "Installing to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"
tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir"
install -m 755 "${tmp_dir}/sentrygrid" "${INSTALL_DIR}/sentrygrid"

echo ""
echo "sentrygrid installed to ${INSTALL_DIR}/sentrygrid"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Note: ${INSTALL_DIR} is not on your PATH. Add it, e.g.:" ;
     echo "  export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac
echo "Run 'sentrygrid' to audit listening ports, or 'sentrygrid --help' for more."

#!/usr/bin/env sh
set -eu

owner="${LTG_OWNER:-MananxRobin}"
repo="${LTG_REPO:-localToGlobal}"
version="${LTG_VERSION:-latest}"
install_dir="${LTG_INSTALL_DIR:-$HOME/.local/bin}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: $1 is required for installation" >&2
    exit 1
  fi
}

detect_asset() {
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "$os:$arch" in
    darwin:x86_64)
      echo "ltg-darwin-amd64.tar.gz"
      ;;
    darwin:arm64|darwin:aarch64)
      echo "ltg-darwin-arm64.tar.gz"
      ;;
    linux:x86_64|linux:amd64)
      echo "ltg-linux-amd64.tar.gz"
      ;;
    linux:aarch64|linux:arm64)
      echo "ltg-linux-arm64.tar.gz"
      ;;
    *)
      echo "error: unsupported platform $os/$arch" >&2
      exit 1
      ;;
  esac
}

need curl
need tar

asset="$(detect_asset)"
if [ "$version" = "latest" ]; then
  url="https://github.com/$owner/$repo/releases/latest/download/$asset"
else
  url="https://github.com/$owner/$repo/releases/download/$version/$asset"
fi

tmp="${TMPDIR:-/tmp}/ltg-install.$$"
mkdir -p "$tmp"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $url"
curl -fsSL "$url" -o "$tmp/$asset"
tar -xzf "$tmp/$asset" -C "$tmp"

mkdir -p "$install_dir"
cp "$tmp/ltg" "$install_dir/ltg"
chmod 755 "$install_dir/ltg"

echo "Installed ltg to $install_dir/ltg"

path_ready=1
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *)
    path_ready=0
    echo
    echo "ltg is installed, but $install_dir is not on PATH in this terminal."
    echo "Use it immediately with:"
    echo "  $install_dir/ltg share 3000"
    echo
    echo "To make 'ltg' work as a command, run this once:"
    echo "  export PATH=\"$install_dir:\$PATH\""
    echo
    echo "Add that line to your shell profile to make it permanent."
    ;;
esac

echo
echo "Checking runtime dependencies..."
if "$install_dir/ltg" doctor; then
  echo
  if [ "$path_ready" -eq 1 ]; then
    echo "Ready. Try: ltg share 3000"
  else
    echo "Ready. Try: $install_dir/ltg share 3000"
  fi
else
  echo
  echo "ltg installed, but doctor found something to fix before sharing."
fi

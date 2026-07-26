#!/bin/sh
# net-tui installer.
#
#   curl -fsSL https://raw.githubusercontent.com/badoss/net-tui/main/install.sh | sh
#
# Picks the native package format when there is one and falls back to dropping
# the static binary into place. Every download is checked against the
# SHA256SUMS published with the release.
set -eu

REPO="badoss/net-tui"
BIN="net-tui"

VERSION="${NET_TUI_VERSION:-}"
METHOD="${NET_TUI_METHOD:-auto}"
BINDIR="${NET_TUI_BINDIR:-}"

RED=""; GREEN=""; YELLOW=""; BOLD=""; RESET=""
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m')
    YELLOW=$(printf '\033[33m'); BOLD=$(printf '\033[1m'); RESET=$(printf '\033[0m')
fi

say()  { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s warning:%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

usage() {
    cat <<EOF
${BOLD}net-tui installer${RESET}

Usage: install.sh [options]

  --version <vX.Y.Z>   Install a specific release (default: latest)
  --method <method>    auto | deb | rpm | binary   (default: auto)
  --bindir <dir>       Where the binary method installs to
                       (default: /usr/local/bin, or ~/.local/bin unprivileged)
  --help               Show this message

Environment: NET_TUI_VERSION, NET_TUI_METHOD, NET_TUI_BINDIR
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:-}"; shift 2 ;;
        --method)  METHOD="${2:-}";  shift 2 ;;
        --bindir)  BINDIR="${2:-}";  shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

has() { command -v "$1" >/dev/null 2>&1; }

# --- environment ------------------------------------------------------------

[ "$(uname -s)" = "Linux" ] || die "this installer is for Linux; on macOS build from source (see README)"

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *) die "unsupported architecture: $(uname -m) (amd64 and arm64 are published)" ;;
    esac
}

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif has sudo; then
    SUDO="sudo"
else
    SUDO=""
fi

# True when we can write outside the user's home.
privileged() { [ "$(id -u)" -eq 0 ] || has sudo; }

if has curl; then
    fetch()      { curl -fsSL "$1" -o "$2"; }
    fetch_out()  { curl -fsSL "$1"; }
elif has wget; then
    fetch()      { wget -qO "$2" "$1"; }
    fetch_out()  { wget -qO- "$1"; }
else
    die "need curl or wget"
fi

if has sha256sum; then
    sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
elif has shasum; then
    sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    die "need sha256sum or shasum to verify downloads"
fi

# --- release ----------------------------------------------------------------

latest_version() {
    tag=$(fetch_out "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -1)
    [ -n "$tag" ] || die "could not determine the latest release of ${REPO}"
    echo "$tag"
}

# Finds the artifact for a method in the release manifest. Names are matched
# rather than reconstructed, so a change in how cargo-deb or cargo-generate-rpm
# spells a version cannot break the installer.
find_asset() { # pattern sumsfile
    awk -v pat="$1" '{ n = $2; sub(/^\.\//, "", n); if (n ~ pat) { print n; exit } }' "$2"
}

list_assets() { # sumsfile
    awk '{ n = $2; sub(/^\.\//, "", n); print "  " n }' "$1"
}

# --- install methods --------------------------------------------------------

resolve_method() {
    case "$METHOD" in
        deb|rpm|binary) echo "$METHOD"; return ;;
        auto) ;;
        *) die "unknown method: $METHOD" ;;
    esac

    # A native package is only worth choosing if we can actually install it.
    if privileged && has dpkg && has apt-get; then
        echo deb
    elif privileged && has rpm && { has dnf || has yum; }; then
        echo rpm
    else
        echo binary
    fi
}

install_deb() { # file
    step "Installing $1 with apt"
    $SUDO apt-get install -y "$1"
}

install_rpm() { # file
    if has dnf; then
        step "Installing $1 with dnf"
        $SUDO dnf install -y "$1"
    else
        step "Installing $1 with yum"
        $SUDO yum install -y "$1"
    fi
}

install_binary() { # tarball workdir
    tar -xzf "$1" -C "$2"
    src=$(find "$2" -type f -name "$BIN" -perm -u+x | head -1)
    [ -n "$src" ] || die "no $BIN binary inside the tarball"

    dest="$BINDIR"
    if [ -z "$dest" ]; then
        if privileged; then dest="/usr/local/bin"; else dest="$HOME/.local/bin"; fi
    fi

    step "Installing to ${dest}/${BIN}"
    if [ -w "$dest" ] || { [ ! -e "$dest" ] && [ -w "$(dirname "$dest")" ]; }; then
        mkdir -p "$dest" && install -m755 "$src" "${dest}/${BIN}"
    else
        $SUDO mkdir -p "$dest" && $SUDO install -m755 "$src" "${dest}/${BIN}"
    fi

    case ":${PATH}:" in
        *":${dest}:"*) ;;
        *) warn "${dest} is not on your PATH; add it to your shell profile" ;;
    esac
}

# --- main -------------------------------------------------------------------

arch=$(detect_arch)
[ -n "$VERSION" ] || { step "Looking up the latest release"; VERSION=$(latest_version); }
method=$(resolve_method)

case "$method" in
    deb)    pattern="^${BIN}_.*_${arch}\\.deb$" ;;
    rpm)
        case "$arch" in amd64) rpm_arch=x86_64 ;; *) rpm_arch=aarch64 ;; esac
        pattern="^${BIN}-.*\\.${rpm_arch}\\.rpm$"
        ;;
    binary) pattern="^${BIN}-.*-linux-${arch}\\.tar\\.gz$" ;;
esac

base="https://github.com/${REPO}/releases/download/${VERSION}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

say "${BOLD}net-tui${RESET} ${VERSION}  ${arch}  (${method})"

# The checksum file doubles as the release manifest: it names every artifact,
# and nothing is installed that is not listed in it.
step "Fetching the release manifest"
fetch "${base}/SHA256SUMS" "${work}/SHA256SUMS" \
    || die "no SHA256SUMS for ${VERSION} — is that release published?"

asset=$(find_asset "$pattern" "${work}/SHA256SUMS")
[ -n "$asset" ] || die "release ${VERSION} has no ${method} artifact for ${arch}. It contains:
$(list_assets "${work}/SHA256SUMS")"

step "Downloading ${asset}"
fetch "${base}/${asset}" "${work}/${asset}" \
    || die "could not download ${base}/${asset}"

step "Verifying checksum"
expected=$(awk -v n="$asset" '{ f = $2; sub(/^\.\//, "", f); if (f == n) { print $1; exit } }' \
    "${work}/SHA256SUMS")
actual=$(sha256_of "${work}/${asset}")
[ "$expected" = "$actual" ] || die "checksum mismatch for ${asset}
  expected $expected
  got      $actual"

case "$method" in
    deb)    install_deb "${work}/${asset}" ;;
    rpm)    install_rpm "${work}/${asset}" ;;
    binary) install_binary "${work}/${asset}" "$work" ;;
esac

say ""
say "${GREEN}${BOLD}net-tui installed.${RESET}"
say ""
say "Capturing packets needs elevated privileges:"
say "  ${BOLD}sudo ${BIN}${RESET}"
say ""
say "To let a non-root user capture, grant the binary the capabilities instead."
say "This allows any user on this system to read network traffic:"
say "  sudo setcap cap_net_raw,cap_net_admin=eip \$(command -v ${BIN})"
say ""

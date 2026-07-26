# syntax=docker/dockerfile:1
#
# Produces every Linux artifact for one architecture:
#
#   net-tui_<version>-1_<arch>.deb
#   net-tui-<version>-1.<arch>.rpm
#   net-tui-<version>-linux-<arch>.tar.gz
#
# All three wrap the same statically linked musl binary, so they install on any
# distribution regardless of its glibc or libpcap package name. Build with:
#
#   docker buildx build --platform linux/arm64 -f packaging/Dockerfile \
#       --target artifacts --output type=local,dest=dist .
#
# buildx sets TARGETARCH, so one file covers amd64 and arm64. Run it on a
# runner of the target architecture to avoid emulation.

ARG RUST_VERSION=1

# --- the one binary everything else wraps -----------------------------------
FROM rust:${RUST_VERSION}-alpine AS build

RUN apk add --no-cache musl-dev libpcap-dev file

WORKDIR /src
COPY . .

# Alpine ships both libpcap.so and libpcap.a. Deleting the shared object leaves
# the linker only the archive, so -lpcap is resolved at build time and nothing
# remains to load at runtime.
RUN rm -f /usr/lib/libpcap.so*

# The grep is the real check: if this ever links dynamically, every downstream
# package silently gains a libpcap dependency, so fail the build instead.
RUN cargo build --release --locked \
 && file target/release/net-tui \
 && file target/release/net-tui | grep -q 'statically linked'

# --- .deb, .rpm and tarball -------------------------------------------------
# Packaged on Debian because cargo-deb expects dpkg's conventions to be around,
# but the binary inside comes from the Alpine stage above.
FROM rust:${RUST_VERSION}-bookworm AS packages

RUN cargo install cargo-deb cargo-generate-rpm --locked

WORKDIR /src
COPY . .
COPY --from=build /src/target/release/net-tui target/release/net-tui

ARG TARGETARCH
# gzip rather than the zstd default: rpm on RHEL 8 cannot read zstd payloads.
RUN set -eu; \
    mkdir -p /out; \
    cargo deb --no-build --output /out; \
    cargo generate-rpm --payload-compress gzip --output /out; \
    version="$(grep -m1 '^version *= *"' Cargo.toml | cut -d'"' -f2)"; \
    [ -n "$version" ] || { echo "could not read version from Cargo.toml" >&2; exit 1; }; \
    name="net-tui-${version}-linux-${TARGETARCH}"; \
    install -Dm755 target/release/net-tui "/pkg/${name}/net-tui"; \
    install -Dm644 README.md "/pkg/${name}/README.md"; \
    install -Dm644 LICENSE "/pkg/${name}/LICENSE"; \
    tar -czf "/out/${name}.tar.gz" -C /pkg "${name}"; \
    ls -l /out

# --- collected artifacts ----------------------------------------------------
FROM scratch AS artifacts
COPY --from=packages /out/ /

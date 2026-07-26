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

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked \
 && install -Dm755 target/release/net-tui /out/net-tui

# Kept in its own layer so tightening this check does not force a recompile.
#
# This is the guarantee the whole packaging rests on: were the binary ever to
# link dynamically, all three artifacts would silently gain a libpcap
# dependency and the "installs on any distribution" promise would break.
#
# Both spellings are needed because the architectures differ. On x86_64 Rust
# emits a static PIE and file(1) reports "static-pie linked"; on aarch64 it
# emits a plain static executable reported as "statically linked". Matching
# only the latter passes on arm64 and fails on amd64 — which is exactly how
# this was found.
RUN file /out/net-tui \
 && file /out/net-tui | grep -Eq 'statically linked|static-pie linked'

# --- .deb, .rpm and tarball -------------------------------------------------
# Packaged on Debian because cargo-deb expects dpkg's conventions to be around,
# but the binary inside comes from the Alpine stage above.
FROM rust:${RUST_VERSION}-bookworm AS packages

# Not --locked: these tools' own lockfiles reference crates that have since
# been yanked, and pinning to them turns an unrelated registry change into a
# build failure. Our own build below is still --locked.
RUN cargo install cargo-deb cargo-generate-rpm

WORKDIR /src
COPY . .
COPY --from=build /out/net-tui target/release/net-tui

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

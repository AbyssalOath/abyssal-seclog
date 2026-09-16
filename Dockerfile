# --- Stage 1: build ---
# Full Rust toolchain, used only to compile. This image is large,
# but it never ships -- only its output does.
FROM rust:bookworm AS builder

WORKDIR /app

# Copy dependency manifests first, separately from source code.
# Docker caches each step; if only your .rs files change (not Cargo.toml),
# this dependency-download/compile steps gets reused from cache instead of
# re-running -- much faster rebuilds during development.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY VERSION ./VERSION

# seclog-ebpf-common/seclog-ebpf are workspace members (see the root
# Cargo.toml's `[workspace]` table, added for the optional `telemetry`
# feature) -- Cargo has to load every member's manifest to resolve the
# workspace at all, even though this default (no --features telemetry)
# build never compiles their source or touches the eBPF toolchain
# (build.rs no-ops without that feature, see its own #[cfg]). Without
# these two COPYs, `cargo build` fails immediately at workspace-manifest
# loading, before it even gets to deciding what to build -- hit and fixed
# via an actual `docker build`, not just `cargo build` from the repo
# root, which doesn't reproduce this (the directories already exist
# there).
COPY seclog-ebpf-common ./seclog-ebpf-common
COPY seclog-ebpf ./seclog-ebpf
COPY build.rs ./build.rs

# Builds all binaties in the project (main + shipped) in release mode
# (optimized, slower to compile, much faster to run than a debug build).
RUN cargo build --release

# --- Stage 2: runtime ---
# A minimal Debian base -- no Rust toolchain, no build tools, just enough
# to run a compiled Linux binary plus a couple runtime libraries it needs.
FROM debian:bookworm-slim

# openssl/ca-certificates are commonly needed for outbound HTTPS/TLS,
# even though we don't use it directly yet -- cheap to include now.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy ONLY the compiled binary out of the builder stage -- nothing else
# from that huge first stage makes it into this final image.
COPY --from=builder /app/target/release/seclog /app/seclog

# Also bring in the static frontend files, since our server serves them.
COPY static ./static

EXPOSE 3000

CMD ["./seclog"]

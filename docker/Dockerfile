# SafeShell (Ageis) container image.
#
# This packages the EXISTING Tauri desktop application unchanged — no
# frontend/backend source in this repository is modified for this build.
# Everything here is deployment plumbing: building the same artifacts
# `npm run tauri dev` / `cargo build --release` already produce, then
# giving the resulting native GUI app somewhere to render inside a
# container (a virtual display + VNC, since SafeShell is a real Tauri
# desktop window, not a web server — see docs/deployment.md's
# "Why noVNC" section for the reasoning).
#
# Build context is the REPOSITORY ROOT (see docker-compose.yml's
# `build.context: ..`), not this `docker/` directory, because the Rust
# crate needs `../policies` and `../simulated-root-image` as build-time
# siblings of `src-tauri/` (see the `/build` path note on the `builder`
# stage below).

# ---------------------------------------------------------------------------
# Stage 1: frontend — build the existing Svelte/Vite app to static assets.
# Tauri embeds `frontendDist` (tauri.conf.json) into the compiled binary at
# `cargo build` time via `tauri::generate_context!()`, so this must run
# BEFORE the Rust build, not just before packaging.
# ---------------------------------------------------------------------------
FROM node:22-bookworm-slim AS frontend

WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: rust builder — the same `cargo build --release` a developer runs
# locally, against the same Ubuntu 24.04 package set this repository's own
# working dev environment builds against (webkit2gtk-4.1 / libsoup-3.0).
#
# Everything is rooted at `/build` and kept at the SAME relative layout the
# final runtime stage uses: `src-tauri/src/main.rs::data_dir`-adjacent
# `policies_path`/`base_image_path` are resolved via `CARGO_MANIFEST_DIR`,
# a path baked into the binary AT COMPILE TIME (`main.rs`'s own comment:
# "Dev-only resolution... A packaged, installed build would need these
# bundled as Tauri resources instead"). Rather than patch that resolution
# (a backend source change, out of scope here), this Dockerfile satisfies
# it structurally: `/build/src-tauri` is `CARGO_MANIFEST_DIR` in both this
# stage and the runtime stage, so `../policies` and
# `../simulated-root-image` resolve to the same real directories at
# runtime that existed at build time.
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential pkg-config \
    libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev \
    libgtk-3-dev libsoup-3.0-dev librsvg2-dev \
    libayatana-appindicator3-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY policies/ ./policies/
COPY simulated-root-image/ ./simulated-root-image/
COPY src-tauri/ ./src-tauri/
COPY --from=frontend /build/frontend/dist ./frontend/dist

WORKDIR /build/src-tauri
# Builds every [[bin]] target: `safeshell` (the app) and the seven
# `safeshell-{wc,sort,uniq,cut,head,tail,date}` coreutils sidecars
# (`src/bin/*.rs`) — the same set `cargo build --release` already produces
# locally. The one addition is `--features custom-protocol`
# (`Cargo.toml`) — without it, the compiled binary loads
# `tauri.conf.json`'s `devUrl` (the Vite dev server `npm run tauri dev`
# provides) instead of its own embedded frontend assets, and shows a
# "connection refused" white window standalone. Verified by actually
# running the image: this is not Docker- or sandbox-specific — a plain
# `cargo build --release` run natively hits the identical issue, since
# `custom-protocol` is off by default so `npm run tauri dev` is
# unaffected (see Cargo.toml's comment on this feature).
RUN cargo build --release --features custom-protocol

# Deliberately NOT running `setcap` here: verified empirically that
# `docker build` (BuildKit) never grants `CAP_SETFCAP` to a `RUN` step
# regardless of any `cap_add` on the eventual container, so a build-time
# `setcap` call always fails. The real grant happens once, at container
# start, in docker/entrypoint.sh — see docker-compose.yml's `cap_add:
# SETFCAP` comment for the full reasoning.

# ---------------------------------------------------------------------------
# Stage 3: runtime — the actual container image. Adds only what's needed to
# (a) run the compiled GUI binary and (b) give it somewhere to render:
# Xvfb (virtual display), a minimal window manager, x11vnc, and noVNC.
# None of this touches SafeShell's own sandbox code — `sandbox/syscalls.rs`
# remains the sole `unsafe` boundary, untouched.
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libwebkit2gtk-4.1-0 libjavascriptcoregtk-4.1-0 \
    libgtk-3-0t64 libsoup-3.0-0 librsvg2-2 \
    libayatana-appindicator3-1 ca-certificates \
    libcap2-bin \
    xvfb x11vnc fluxbox x11-utils \
    novnc websockify \
    tini curl \
    && rm -rf /var/lib/apt/lists/*

# Real, non-root user — not just container hygiene: SafeShell's own
# preflight probes unprivileged user/mount/PID namespace creation
# (`sandbox/syscalls.rs`), which is only representative of how a real user
# would run this if the process itself is a real unprivileged UID, not
# UID 0 (root can take shortcuts these probes don't exercise).
RUN useradd --create-home --home-dir /home/ageis --shell /bin/bash ageis

WORKDIR /build
COPY --from=builder /build/policies ./policies
COPY --from=builder /build/simulated-root-image ./simulated-root-image
COPY --from=builder /build/src-tauri/target/release/safeshell ./src-tauri/target/release/safeshell
COPY --from=builder /build/src-tauri/target/release/safeshell-wc ./src-tauri/target/release/safeshell-wc
COPY --from=builder /build/src-tauri/target/release/safeshell-sort ./src-tauri/target/release/safeshell-sort
COPY --from=builder /build/src-tauri/target/release/safeshell-uniq ./src-tauri/target/release/safeshell-uniq
COPY --from=builder /build/src-tauri/target/release/safeshell-cut ./src-tauri/target/release/safeshell-cut
COPY --from=builder /build/src-tauri/target/release/safeshell-head ./src-tauri/target/release/safeshell-head
COPY --from=builder /build/src-tauri/target/release/safeshell-tail ./src-tauri/target/release/safeshell-tail
COPY --from=builder /build/src-tauri/target/release/safeshell-date ./src-tauri/target/release/safeshell-date

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && mkdir -p /data /home/ageis/.local/share \
    && chown -R ageis:ageis /build /data /home/ageis

# Deliberately no `USER ageis` here. The container starts as root so
# docker/entrypoint.sh can run `setcap cap_sys_admin+eip` on the
# `safeshell` binary (needs CAP_SETFCAP, granted to this container via
# docker-compose.yml's `cap_add: SETFCAP` — verified this must happen at
# container start, not build time, see the `builder` stage's comment)
# before dropping to the non-root `ageis` user via `setpriv` for
# everything else it starts, including `safeshell` itself.
ENV HOME=/home/ageis
ENV XDG_DATA_HOME=/data
ENV DISPLAY=:99
# Common, well-documented WebKitGTK-in-Xvfb workarounds — deployment-layer
# environment configuration, not an application code change. Without
# these, WebKitGTK's own compositor/GPU path frequently fails to render
# (or crashes) against a software/virtual display with no real GPU.
ENV WEBKIT_DISABLE_COMPOSITING_MODE=1
ENV LIBGL_ALWAYS_SOFTWARE=1

# noVNC's web UI (used to actually view/interact with the app — see
# docs/deployment.md). VNC's own raw protocol port (5900) is intentionally
# not published in docker-compose.yml; noVNC's websockify already proxies
# it, and there's no reason to also expose the raw port to the host.
EXPOSE 6080

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -fsS http://127.0.0.1:6080/ >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/entrypoint.sh"]

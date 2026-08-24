#!/usr/bin/env bash
# Container entrypoint for the SafeShell (Ageis) image.
#
# Brings up a virtual X display, a minimal window manager, and a VNC/noVNC
# bridge so the *unmodified* Tauri desktop app can actually be viewed and
# used from a browser, then execs the real `safeshell` binary against that
# display. Nothing here is application logic — see docs/deployment.md for
# the reasoning ("Why noVNC") and docker/Dockerfile for how the binary
# itself is built.
#
# Runs as root only for the one step that needs it (`setcap`, which needs
# CAP_SETFCAP — verified empirically that `docker build` never grants this
# to a `RUN` step, so it has to happen here, at container start, not at
# build time), then drops to the non-root `ageis` user via `setpriv` for
# everything else, including `safeshell` itself — see docker/Dockerfile's
# comment on why running as a real unprivileged user matters for
# SafeShell's own preflight probes to mean anything.
set -uo pipefail

DISPLAY_NUM="${DISPLAY#:}"
DISPLAY_NUM="${DISPLAY_NUM:-99}"
SCREEN_GEOMETRY="${SCREEN_GEOMETRY:-1440x900x24}"
SAFESHELL_BIN="/build/src-tauri/target/release/safeshell"
AS_AGEIS=(setpriv --reuid=ageis --regid=ageis --init-groups)

log() { echo "[entrypoint] $*"; }

log "granting CAP_SYS_ADMIN to the safeshell binary (setcap)"
if setcap cap_sys_admin+eip "$SAFESHELL_BIN"; then
    log "setcap OK: $(getcap "$SAFESHELL_BIN")"
else
    log "WARNING: setcap failed — SYS_ADMIN/SETFCAP may not be granted to" \
        "this container (check docker-compose.yml's cap_add). SafeShell" \
        "will still start and will fail closed on capability-gated" \
        "operations exactly as it does outside Docker without this grant."
fi

# `sandbox::cgroups::delegated_subtree_status` (`policy`'s capability
# report) creates its own probe cgroup directly under the container's own
# cgroup root and checks it can write pids.max/memory.max/cpu.max there.
# Docker's cgroup mount (docker-compose.yml's /sys/fs/cgroup bind, itself
# needed because Docker's *default* cgroup mount is read-only even to
# root) is owned root:root with no write bit for anyone else — verified
# empirically that CAP_SYS_ADMIN alone does not let a non-root process
# write there; only a real Unix permission grant does. This mirrors what
# systemd's per-user cgroup delegation does on a bare host (chowning a
# user's own slice to them) — narrowly granting the *specific* non-root
# user SafeShell runs as its own write access, not a broad capability.
if chown ageis:ageis /sys/fs/cgroup 2>/dev/null && chmod u+w /sys/fs/cgroup 2>/dev/null; then
    log "cgroup v2 root delegated to ageis"
else
    log "WARNING: could not chown/chmod /sys/fs/cgroup for the ageis user —" \
        "check docker-compose.yml's /sys/fs/cgroup:/sys/fs/cgroup:rw mount." \
        "SafeShell will report cgroups_v2 unavailable and fail closed on" \
        "capability-gated operations, same as any other missing primitive."
fi

XVFB_PID=""
FLUXBOX_PID=""
X11VNC_PID=""
WEBSOCKIFY_PID=""
SAFESHELL_PID=""

cleanup() {
    log "shutting down..."
    for pid in "$SAFESHELL_PID" "$WEBSOCKIFY_PID" "$X11VNC_PID" "$FLUXBOX_PID" "$XVFB_PID"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup TERM INT

log "starting Xvfb on :${DISPLAY_NUM} (${SCREEN_GEOMETRY})"
"${AS_AGEIS[@]}" Xvfb ":${DISPLAY_NUM}" -screen 0 "${SCREEN_GEOMETRY}" -nolisten tcp >/tmp/xvfb.log 2>&1 &
XVFB_PID=$!

ready=0
for _ in $(seq 1 50); do
    if xdpyinfo -display ":${DISPLAY_NUM}" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.2
done
if [ "$ready" -ne 1 ]; then
    log "ERROR: Xvfb did not come up within 10s — last log lines:"
    tail -n 40 /tmp/xvfb.log 2>/dev/null || true
    exit 1
fi
log "Xvfb ready"

"${AS_AGEIS[@]}" fluxbox >/tmp/fluxbox.log 2>&1 &
FLUXBOX_PID=$!

x11vnc_args=(-display ":${DISPLAY_NUM}" -forever -shared -rfbport 5900 -quiet)
if [ -n "${VNC_PASSWORD:-}" ]; then
    log "VNC_PASSWORD set — starting x11vnc with authentication"
    mkdir -p /tmp/.vnc
    x11vnc -storepasswd "${VNC_PASSWORD}" /tmp/.vnc/passwd >/dev/null 2>&1
    chown ageis:ageis /tmp/.vnc/passwd 2>/dev/null || true
    x11vnc_args+=(-rfbauth /tmp/.vnc/passwd)
else
    log "VNC_PASSWORD not set — noVNC will have no authentication. This is only" \
        "safe because docker-compose.yml binds port 6080 to 127.0.0.1 by" \
        "default; do not change that to publish it beyond localhost without" \
        "also setting VNC_PASSWORD (see .env.example)."
    x11vnc_args+=(-nopw)
fi
"${AS_AGEIS[@]}" x11vnc "${x11vnc_args[@]}" >/tmp/x11vnc.log 2>&1 &
X11VNC_PID=$!

ready=0
for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/5900") 2>/dev/null; then
        exec 3>&- 3<&-
        ready=1
        break
    fi
    sleep 0.2
done
if [ "$ready" -ne 1 ]; then
    log "ERROR: x11vnc did not come up within 10s — last log lines:"
    tail -n 40 /tmp/x11vnc.log 2>/dev/null || true
    exit 1
fi
log "x11vnc ready"

novnc_web=""
for candidate in /usr/share/novnc /usr/lib/novnc; do
    if [ -d "$candidate" ]; then
        novnc_web="$candidate"
        break
    fi
done
if [ -z "$novnc_web" ]; then
    log "ERROR: could not find the noVNC web assets (looked in /usr/share/novnc," \
        "/usr/lib/novnc) — the 'novnc' package layout may have changed; check" \
        "'dpkg -L novnc' inside the image and adjust docker/entrypoint.sh."
    exit 1
fi
"${AS_AGEIS[@]}" websockify --web="${novnc_web}" 6080 127.0.0.1:5900 >/tmp/websockify.log 2>&1 &
WEBSOCKIFY_PID=$!
log "noVNC listening on :6080 (web assets: ${novnc_web})"

log "starting SafeShell (${SAFESHELL_BIN}) as ageis"
"${AS_AGEIS[@]}" "${SAFESHELL_BIN}" &
SAFESHELL_PID=$!

wait "${SAFESHELL_PID}"
status=$?
log "safeshell exited with status ${status}"
cleanup
exit "${status}"

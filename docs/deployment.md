# Deploying Ageis (SafeShell) with Docker

This document covers the Docker-based deployment layer added around the existing,
**unmodified** Ageis application. Nothing in `frontend/`, `src-tauri/src/`,
`policies/`, or `simulated-root-image/` was changed to make this work — see
"Files intentionally not modified" at the end. Every claim in this document —
the build, the full transaction pipeline, the sandbox capability results, the
Ollama round-trip — was verified by actually running the stack, not assumed;
see "What was actually verified" near the end.

## Why this isn't a normal "docker compose up, open a browser" web app

Ageis (SafeShell) is a native **Tauri desktop application**. It opens a real OS
window rendered by WebKitGTK; in a production build there is no HTTP server
serving the frontend (Tauri embeds the built frontend into the binary itself and
loads it into a native webview — see `main.rs`'s use of `tauri::generate_context!()`
and `tauri.conf.json`'s `frontendDist`). Tauri's IPC bridge between the frontend
and the Rust core is in-process, not a network API.

That means a container running the compiled binary needs somewhere to actually
render a window. This deployment gives it a virtual X display (Xvfb) plus a
VNC server, bridged to a browser-viewable page via noVNC — so you open
`http://localhost:6080` in any browser (Linux, macOS, Windows host, doesn't
matter) and see the real, live SafeShell window, click into it, type in its
terminal, and interact with it exactly as you would natively. The alternative
(forwarding your host's own X11 socket into the container) only works on Linux
hosts already running X11 and requires relaxing host X access
(`xhost +local:docker`); noVNC needs nothing from the host beyond a browser and
was chosen for that reason.

## Prerequisites

- Docker Engine ≥ 24 and the Docker Compose plugin (`docker compose`, not the
  older standalone `docker-compose`).
- A Linux Docker host (or Docker Desktop on macOS/Windows using its Linux VM) —
  the sandbox capability section below explains why a *Linux* host specifically
  matters even though the display itself works from any OS via noVNC.
- Roughly 4–8 GB of free disk for the image plus whatever Ollama model you pull
  (a `7B`-class quantized model is typically 4–5 GB).

## Quick start

```bash
git clone <repo-url> ageis
cd ageis
cp .env.example .env
docker compose up --build
```

Then:

1. Open `http://localhost:6080` in a browser — you'll see the SafeShell window
   inside a noVNC session. Click into it once to focus, and use it like any
   desktop app.
2. In a separate terminal, pull an Ollama model (see below) — the app runs
   fine before you do this, just with AI explanations unavailable
   (`ai_skipped`, per `docs/architecture.md` §21.9).

## Everyday commands

```bash
docker compose build              # rebuild images after a source change
docker compose up                 # start in the foreground (logs in this terminal)
docker compose up -d              # start detached
docker compose down               # stop and remove containers (keeps volumes)
docker compose down -v            # stop and also delete session data + pulled models
docker compose logs -f            # follow logs from both services
docker compose logs -f ageis      # just the app container
docker compose ps                 # container/health status
```

## Environment variables

Copy `.env.example` to `.env` and adjust as needed. All variables have safe
defaults — `docker compose up` works with `.env` left exactly as
`.env.example` copied it.

| Variable | Default | Meaning |
|---|---|---|
| `SAFESHELL_OLLAMA_MODEL` | `llama3.2:latest` | Model tag `OllamaBackend` requests. Empty disables the AI entirely (`NullBackend`) — SafeShell is fully functional without it. |
| `SAFESHELL_OLLAMA_ENDPOINT` | `http://ollama:11434` | Where the app looks for Ollama. The default is the Compose service name, resolved over Docker's internal network — only change this to point at an external Ollama instance. |
| `SAFESHELL_OLLAMA_TIMEOUT_MS` | `30000` | Matches `OllamaBackend`'s own compiled-in default. |
| `NOVNC_PORT` | `6080` | Host port for the browser-based GUI, bound to `127.0.0.1` only. |
| `OLLAMA_PORT` | `11434` | Host port for Ollama's own API, bound to `127.0.0.1` only — useful if you want to run the `ollama` CLI against it directly. |
| `VNC_PASSWORD` | *(empty)* | Optional VNC/noVNC password. Safe to leave empty as long as `NOVNC_PORT` stays bound to localhost (the default); set it before ever publishing that port more broadly. |
| `SCREEN_GEOMETRY` | `1440x900x24` | Virtual display size for the Tauri window (`1360x860`, min `960x600` per `tauri.conf.json`) to render into. |

Two of these (`SAFESHELL_OLLAMA_MODEL`, `SAFESHELL_OLLAMA_ENDPOINT`,
`SAFESHELL_OLLAMA_TIMEOUT_MS`) are the *same* variables `main.rs::build_ai_backend`
already reads when you run SafeShell natively — `src-tauri/.env.example` documents
them for that path. Docker Compose reads the root `.env` to fill in
`docker-compose.yml`, which then sets the identical variable names inside the
container's real environment; the app code is unaware it's in a container.

## Ollama model setup

Models are **never** downloaded during `docker compose build` or on every
`docker compose up` — only a base `ollama/ollama` image is pulled, and model
weights live in a named volume (`ollama_data`) that persists across restarts and
rebuilds. Pull the model once, after the stack is up:

```bash
docker compose up -d
docker compose exec ollama ollama pull llama3.2:latest   # match SAFESHELL_OLLAMA_MODEL
docker compose exec ollama ollama list                   # confirm it's there
```

Restart the `ageis` container afterward only if it already gave up trying to
reach Ollama and set `ai_skipped` for a while (it retries per-command, not
once at startup, so this usually isn't necessary — a new command submitted
after the pull finishes will pick up the now-available model on its own).

To use a different model, set `SAFESHELL_OLLAMA_MODEL` in `.env` to match
whatever tag you pull.

Note from verifying this end to end: a genuinely tiny model can reach Ollama
successfully over HTTP and still end up `ai_skipped` if its output doesn't
parse as the expected structured JSON (`ai::validation::validate` — §21.7 —
discards it wholesale rather than partially trusting it, by design). This
isn't a deployment problem; it's the AI-quality/schema-reliability tradeoff
§21.10 already documents. `llama3.2:latest` (the default) is a reasonable,
instruction-tuned baseline; if you deliberately pick something much smaller
for speed, expect a higher `ai_skipped` rate — SafeShell keeps working
correctly on deterministic policy alone either way.

## Sandbox compatibility inside Docker

**This is the part worth reading carefully.** SafeShell's security model depends
on real Linux kernel primitives — user namespaces, mount namespaces, PID
namespaces, seccomp-bpf, Landlock, cgroups v2, `openat2`, OverlayFS
(`docs/architecture.md` §15). None of that was weakened, bypassed, or
special-cased for Docker. What follows is what Docker's own container boundary
does and doesn't get in the way of, the specific grants in
`docker-compose.yml`/`docker/entrypoint.sh` that give SafeShell's *own*
preflight checks the best realistic chance to pass, and the **real, measured
result** of running this stack — not a prediction.

### Verified result (this deployment, this host)

Read from the app's own `capability_report_json` (via its SQLite audit trail,
and independently confirmed live in the running GUI's TopBar) after actually
building and starting the stack:

| Primitive | Status |
|---|---|
| User namespaces | `ok` |
| Mount namespaces | `ok` |
| PID namespaces | `ok` |
| Landlock | `ok` |
| `openat2` | `ok` |
| Seccomp (SafeShell's own filter self-test) | `ok` |
| cgroups v2 delegation | `ok` |
| **`execution_available()`** | **`true`** |
| OverlayFS | `unavailable` |

`execution_available()` is the aggregate flag that gates whether
capability-requiring commands run at all — **true** here. The one remaining
`unavailable` line (OverlayFS) is a **pre-existing, unconditional placeholder**
in `sandbox/preflight.rs` itself ("not yet probed — OverlayFS self-test lands
with the layer model"), unrelated to Docker — it reports this on every
environment, container or bare metal, until that self-test is actually built.
Simulation still runs correctly via the automatic `CopyUpSimulationBackend`
fallback (confirmed live: `backend: copyup` in the TopBar), exactly as
documented (`docs/CLAUDE.md`'s "Backend selection" — "not a manual choice or a
security downgrade").

With this result, a full transaction was driven through the real GUI end to
end — `rm -rf /project` (Category 2, HIGH risk) correctly paused at
`WAITING_FOR_APPROVAL`, showed a real predicted diff, and on approval ran
snapshot → execute → verify → **COMMITTED** for real, with a real checkpoint
recorded (`storage: ... 1/10 checkpoints` in the TopBar). This is not a
Docker-specific code path — it's the same `run_to_completion` every command
goes through natively; Docker just needed to be configured to let SafeShell's
own preflight probes see what a real unprivileged process can do.

**This specific result is not a universal guarantee.** It depends on your
Docker daemon's cgroup driver, storage driver, and (per below) one host
kernel sysctl. Re-check via the same TopBar/`capability_report_json` on any
other host before treating this table as true there too.

### What we deliberately did NOT do

- **No `privileged: true`.** That disables Docker's own device isolation and
  default seccomp/AppArmor confinement wholesale — far broader than anything
  SafeShell's sandbox layer needs, and exactly the kind of blanket workaround
  this task explicitly ruled out. Full capability (see above) was reached
  without it.
- **No changes to `sandbox/syscalls.rs`, `sandbox/seccomp.rs`,
  `sandbox/landlock.rs`, `sandbox/cgroups.rs`, or `sandbox/preflight.rs`.**
  SafeShell's own capability probing, seccomp-bpf filter, and Landlock ruleset
  are exactly what they are outside Docker. If a primitive is unavailable
  inside a *different* container, SafeShell's existing fail-closed behavior
  (`docs/CLAUDE.md` invariant #19) is what handles it — the same code path
  that already runs in this repository's own dev sandbox, which also lacks
  some of these primitives.
- **No `CAP_DAC_OVERRIDE`** or any other broad permission-bypass capability
  for the cgroups v2 fix below — see why that specific grant was chosen
  instead.

### What `docker-compose.yml` grants, and why

```yaml
cap_add:
  - SYS_ADMIN
  - SETFCAP
security_opt:
  - "seccomp=unconfined"
  - "apparmor=unconfined"
volumes:
  - /sys/fs/cgroup:/sys/fs/cgroup:rw
```

- **`SYS_ADMIN`** raises the container's own capability *ceiling* to include
  what `mount`, `pivot_root`, and namespace operations need.
- **`SETFCAP`** — discovered by actually building the image: `setcap` (which
  grants `safeshell` its own `CAP_SYS_ADMIN` as a file capability, so the
  non-root `ageis` user can use it — Linux capabilities aren't inherited
  across `exec()` for a non-root process otherwise) needs `CAP_SETFCAP`
  itself, which `docker build` never grants to a `RUN` step, no matter what
  the eventual container's `cap_add` is — build-time and run-time capability
  grants are separate mechanisms. So `setcap` runs once, at container start,
  in `docker/entrypoint.sh`, before it drops to the non-root `ageis` user for
  everything else — see that file's comments.
- **`seccomp=unconfined`** removes *Docker's own* default seccomp profile,
  which blocks or restricts several of the syscalls SafeShell's preflight
  probes need to even attempt (`unshare`, `clone` with namespace flags,
  `pivot_root`, `mount`/`umount2`). This is Docker's outer restriction, layered
  *above* SafeShell's own seccomp-bpf filter (`sandbox/seccomp.rs`) — removing
  Docker's does not touch SafeShell's, which is applied independently, inside
  its own sandboxed worker process, and is unaffected by anything at the
  container level.
- **`apparmor=unconfined`** is the AppArmor equivalent of the same idea. On
  hosts where AppArmor isn't the active LSM (e.g. SELinux-based distros),
  Docker generally treats this as a no-op rather than an error; if your setup
  rejects it outright, it's safe to remove that one line.
- **`/sys/fs/cgroup:/sys/fs/cgroup:rw`** — discovered by actually testing:
  Docker mounts `/sys/fs/cgroup` **read-only by default**, even to a process
  with `CAP_SYS_ADMIN`; rebinding it read-write is the standard, narrow fix
  for this (the same one used to run systemd or nested containers under
  Docker). This alone was still not enough for the non-root `ageis` user —
  the mount is owned `root:root` with no write bit for anyone else, and
  capabilities don't bypass ordinary Unix permission checks. The actual fix
  (`docker/entrypoint.sh`, root-only, before dropping privileges):
  ```bash
  chown ageis:ageis /sys/fs/cgroup && chmod u+w /sys/fs/cgroup
  ```
  This mirrors exactly what `systemd-logind` does for per-user cgroup
  delegation on a bare host (chowning that user's own slice to them) — a
  narrow grant to the *specific* non-root user SafeShell runs as, not a broad
  DAC-bypass capability.

### Host-level requirements (outside Docker's control entirely)

- The host kernel must support unprivileged user namespaces
  (`kernel.unprivileged_userns_clone=1` — the default on most modern
  distributions).
- **On Ubuntu 24.04+ hosts specifically**: `unshare(CLONE_NEWUSER)` is blocked
  by a systemwide AppArmor restriction unless you relax it on the **host**:
  ```bash
  sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0
  ```
  This is documented directly in `sandbox/syscalls.rs`'s own comments — it's a
  real requirement this repository's own dev sandbox needed too, entirely
  independent of Docker. There is nothing inside a container that can set this;
  it's a systemwide kernel setting the host administrator controls.
- The host kernel needs the `overlay` filesystem module available (built-in or
  loadable on essentially every modern Linux distribution) for a future
  `OverlayFsSimulationBackend` self-test to have a chance once that lands; in
  the meantime `CopyUpSimulationBackend` is the verified, fully-functional
  path (see above).

### How to check what actually got through, once running

SafeShell already surfaces this — no extra tooling needed:

1. Open the noVNC session (`http://localhost:6080`).
2. The app's own **TopBar** shows the active simulation backend and capability
   status live. This is the real, existing `get_capability_report` /
   `get_storage_status` data (`ipc/mod.rs`), unmodified — the same data the
   table above was read from.
3. Run a command in the terminal and watch the pipeline visualization —
   whichever `SimulationBackend` was actually selected
   (`orchestrator::select_simulation_backend`) is disclosed there per existing
   application behavior.

We did not add a Docker-specific diagnostic script for this on purpose —
`get_capability_report` already exists and is the authoritative source; a
separate script would just be a second, potentially-drifting way to ask the
same question.

## Troubleshooting

**`docker compose up` fails at the `apparmor=unconfined` line.** Your Docker
version or LSM setup may reject it. Remove that one line from
`docker-compose.yml`'s `ageis` service and retry — `seccomp=unconfined` and
`cap_add: SYS_ADMIN` still apply.

**The noVNC page loads but shows a black/blank screen.** Give it a few more
seconds — `docker compose logs -f ageis` should show `[entrypoint] starting
SafeShell` once Xvfb/x11vnc/websockify are all up; the window can take a
moment to paint after that. If it stays blank, check the same logs for a
WebKitGTK crash — `WEBKIT_DISABLE_COMPOSITING_MODE=1` and
`LIBGL_ALWAYS_SOFTWARE=1` (already set in `docker/Dockerfile`) are the standard
fix for WebKitGTK failing to render against a software/virtual display; if
you've changed the base image, verify they're still set.

**AI explanations never show up / `ai_skipped` stays true.** Confirm the model
was actually pulled (`docker compose exec ollama ollama list`) and that
`SAFESHELL_OLLAMA_MODEL` in `.env` matches the pulled tag exactly. This is
existing, expected `ai_skipped` behavior (`docs/architecture.md` §21.9) —
SafeShell keeps working on deterministic policy alone either way.

**Sandbox capability report shows everything unavailable.** Check the Ubuntu
24.04 AppArmor sysctl above first — it's the single most common host-side
blocker. Then confirm `cap_add`/`security_opt` weren't stripped by an
orchestration layer in front of Compose (some managed Docker environments
restrict what `cap_add`/`security_opt` a container may request).

**`docker compose build` fails compiling `src-tauri`.** Almost always a
transient crates.io/apt mirror issue in the `builder` stage — retry.

**Capability report shows `cgroups_v2: unavailable` despite `cap_add`.**
Confirm `docker-compose.yml` still has the `/sys/fs/cgroup:/sys/fs/cgroup:rw`
volume mount and check `docker compose logs ageis` for the entrypoint's
`cgroup v2 root delegated to ageis` line — if it instead logged a `WARNING`
there, the `chown`/`chmod` step itself failed (check that line's own log
output for why; a restrictive host security policy on some managed Docker
platforms could still block a raw cgroup bind-mount even with `SYS_ADMIN`
granted).

**A window titled "SafeShell" appears in the noVNC session but shows only
"Could not connect to localhost: Connection refused."** This means the
binary was built without Tauri's `custom-protocol` feature (see
`src-tauri/Cargo.toml`) and is trying to load `tauri.conf.json`'s `devUrl`
(the Vite dev server) instead of its own embedded frontend. `docker/Dockerfile`
already passes `--features custom-protocol` to `cargo build --release` for
exactly this reason — if you're building this image with a modified Dockerfile
or building the binary some other way, make sure that flag is still there.

## Limitations

- Sandbox capability availability is genuinely host-dependent (see above) —
  this deployment cannot guarantee every primitive is available on every
  Docker host, only that it configures the container to give SafeShell's own
  fallback logic the best realistic chance, and that nothing here silently
  weakens what happens when a primitive isn't available.
- The noVNC session adds real latency/overhead versus running the native app
  directly on a Linux desktop — expected for any GUI-in-a-container approach,
  not specific to this app.
- `docker compose down -v` deletes both SafeShell's session/transaction
  history (`ageis_data`) and any pulled Ollama models (`ollama_data`) — plain
  `docker compose down` (no `-v`) keeps both.
- Multi-user/multi-host deployment (i.e. many people sharing one running
  instance) isn't addressed here — see `docs/deployment-kubernetes.md` for
  where that would go; it isn't implemented.

## What was actually verified

Not just "should work" — this exact sequence was run, on this machine, against
the files in this repository:

1. `cargo test --workspace`, `cargo check`, `cargo clippy --all-targets -- -D
   warnings` — all pass, unaffected (confirms the application itself is
   unchanged and healthy).
2. `docker compose build` — succeeds, including the frontend build, the full
   Rust release compile, and the seven coreutils sidecar binaries.
3. `docker compose up -d` — both `ageis` and `ollama` reach Docker's
   `healthy` status.
4. `docker exec ... curl http://ollama:11434/` from inside the `ageis`
   container — succeeds, confirming internal Docker network / Compose
   service-name resolution.
5. The noVNC page (`http://localhost:6080`) actually renders the live
   SafeShell window — confirmed visually (screenshot), not just "a process is
   running."
6. A full transaction was driven through the real GUI via simulated
   keyboard/mouse input: `rm -rf /project` correctly classified HIGH risk,
   paused at `WAITING_FOR_APPROVAL` with a real predicted diff, and on
   clicking **Approve** ran snapshot → execute → verify → **COMMITTED**, with
   a real checkpoint recorded — the complete pipeline, for real, inside the
   container.
7. A real Ollama model was pulled (`docker compose exec ollama ollama pull
   ...`) and the app made a real HTTP round trip to it for that same
   transaction — the approval panel's AI Advisory correctly showed `ai_skipped`
   with a validation-failure reason when the (deliberately tiny, for a fast
   verification pull) test model's output didn't parse as valid JSON,
   demonstrating `ai::validation::validate`'s existing fail-closed handling
   working against a real model's real output, not a mock.
8. The capability report table above was read from the real
   `capability_report_json` the running app recorded for that session.

Two real, pre-existing gaps were found *by* this verification process (not
guessed at) and are documented as their own sections above/below: the
`custom-protocol` Cargo feature, and the cgroups v2 read-only-mount +
ownership issue.

## Files created for this deployment

- `docker/Dockerfile` — multi-stage build (frontend → Rust builder → runtime).
- `docker/entrypoint.sh` — Xvfb/window-manager/VNC/noVNC orchestration,
  `setcap`/cgroup delegation, then execs the unmodified `safeshell` binary as
  a non-root user.
- `docker-compose.yml` — the `ageis` and `ollama` services, network, volumes,
  healthchecks, capability grants.
- `.env.example`, `.dockerignore`.
- This document, and `docs/deployment-kubernetes.md`.

## Files intentionally not modified

Every file under `frontend/src/`, `policies/`, `simulated-root-image/`, and
every existing test. `src-tauri/tauri.conf.json` was inspected but not
changed — `bundle.active: false` was already set, and this deployment doesn't
use Tauri's own bundler; it runs the plain `cargo build --release` binary
directly.

Two things outside `frontend/`/`policies/`/`simulated-root-image/` **were**
touched, both discovered as real, pre-existing blockers by actually building
and running this deployment rather than assumed — not application behavior
changes, and both are the kind of "Docker/Tauri configuration required
strictly for packaging" this task's own boundary explicitly allowed:

- **`src-tauri/Cargo.toml`** gained one additive `[features]` block defining
  `custom-protocol = ["tauri/custom-protocol"]` — `tauri`'s own feature,
  "managed by the Tauri CLI" per its doc comment, controlling only whether a
  build loads its embedded frontend or expects a live Vite dev server.
  Verified this is **not Docker-specific**: a plain `cargo build --release`
  run natively, outside Docker entirely, hits the identical "connection
  refused" white window without it, because this repository was previously
  only ever exercised through `npm run tauri dev`, which sets this
  automatically. The feature defaults to *off*, so `npm run tauri dev` and
  every existing native workflow is completely unaffected — only
  `docker/Dockerfile`'s build explicitly opts in
  (`cargo build --release --features custom-protocol`). No `.rs` file
  changed; no application behavior changed for any existing workflow.
- **`.gitignore`** had an unanchored `bin/` pattern that also matched
  `src-tauri/src/bin/` — the source for the coreutils sidecar binaries added
  in an earlier change — silently excluding it from every commit since it was
  added. A fresh clone was therefore missing those seven files entirely,
  which would have compiled (`cargo build` just builds fewer `[[bin]]`
  targets) but left `wc`/`sort`/`uniq`/`cut`/`head`/`tail`/`date` failing at
  runtime with "sidecar not found." Fixed by anchoring the pattern to `/bin/`
  (the repo-root build-artifact directory it was actually meant to ignore).
  No source file's content changed.

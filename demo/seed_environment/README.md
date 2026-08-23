# Seed Environment

The actual seed content lives in `simulated-root-image/` at the repo root, not here — this file
just documents how it's used, so `demo/scripted_scenario.md` doesn't have to.

## What gets seeded, and how

`orchestrator::create_session` (`src-tauri/src/orchestrator/mod.rs`) calls
`seed_base_from_image(&state.base_image_path, &base)` for every new session, which copies every
*directory* directly under `simulated-root-image/` (`etc/`, `home/`, `opt/`, `project/`, `tmp/`,
`usr/`, `var/`) recursively into that session's `LayerStack::base` — the read-only consolidated
base every checkpoint layers on top of. This is real, load-bearing wiring, not documentation: see
`orchestrator::tests::a_fresh_session_is_seeded_with_the_real_base_image_content`, which drives a
real session through `cat project/README.md` and asserts on the actual seeded text.

`simulated-root-image/`'s three top-level *files* — `nondeterministic-paths.toml`,
`mock-users.json`, `mock-package-db.json` — are SafeShell's own configuration about the image, not
simulated filesystem content, and are deliberately **not** copied into any session's root (checked
by that same test).

## `nondeterministic-paths.toml`

Loaded once at `AppState` construction (`AppState::new_with_capability_report`) and used by every
session's verification pass (§26.3). Currently empty (`paths = []`) — honestly, not as a
placeholder: no handler in this codebase produces genuinely time-varying output yet
(`handlers/mod.rs` implements `pwd, cd, mkdir, touch, ls, cat, echo`, all deterministic given their
inputs), so there is nothing that legitimately needs an entry. See that file's own comment.

## `mock-users.json` / `mock-package-db.json`

Real, well-formed reference data matching docs/architecture.md §40's repository structure. Neither
has a consumer yet — no user-management or package-manager command is implemented — so they're
seed data waiting for a handler, the same honestly-disclosed shape `nondeterministic-paths.toml`
was in before this phase populated it with real directory content.

## Extending the seed

Add a file or directory under the relevant top-level directory in `simulated-root-image/` and it
appears in every new session automatically — no code change needed. To add a genuinely
nondeterministic path once a handler actually produces one, add its session-relative path to
`nondeterministic-paths.toml`'s `paths` array.

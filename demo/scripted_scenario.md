# Demo Scenario

Source of truth for the narrative: `docs/architecture.md` §44. This file adapts that script to
what is actually real in the current build, and says plainly where it isn't — per docs/CLAUDE.md's
own rule ("when you cannot verify something... state that plainly. Do not report unverified work as
done"), a demo script that pretends otherwise would be worse than no script at all.

## What's live today versus scripted

`handlers/mod.rs` implements exactly seven commands: `pwd, cd, mkdir, touch, ls, cat, echo`. Risk
classification (`policy/risk.rs`) only has rules for `rm`, `chmod`, `chown` — none of which have a
handler yet. Two consequences for this script:

- **Every step below except 3 and 6 is fully live-demoable in the running app today**, using only
  real commands against real seeded content.
- **Steps 3 and 6** — the approval-gated dangerous operation, and the live-triggered verification
  mismatch — need `rm`/`chmod`/`chown` (a real diff-producing command that also requires approval)
  to perform live. That combination doesn't exist yet with the current handler set, so those two
  steps are demonstrated via the automated fixtures named inline below, not free-typed in the
  terminal. This is disclosed here, not glossed over — closing it is a straightforward,
  independent follow-up (implement `rm`'s handler; its risk rule and containment checks already
  exist and are tested).

## Setup

1. `npm --prefix frontend run build` (or leave the dev server running).
2. `cargo run` from `src-tauri/` (or `npx tauri dev` from `src-tauri/` once `@tauri-apps/cli` is
   available at the repo root — see `frontend/package.json`).
3. The app creates a session on launch and seeds it from `simulated-root-image/` (see
   `demo/seed_environment/README.md`) — `project/README.md`, `project/src/main.rs`,
   `home/user/notes.txt`, `etc/hostname`, `etc/os-release` all exist from the first prompt.

## Script

1. **Launch.** Top bar shows session id, simulation backend (`copyup` unless the run has real
   OverlayFS/fuse-overlayfs — see `sandbox/overlayfs.rs`'s own doc comment), capability status, and
   storage (checkpoints retained / ceiling). On a machine without unprivileged user namespaces —
   this project's own dev sandbox, honestly, see `sandbox/preflight.rs` — capabilities show
   unavailable and every command denies with `DENY_CAPABILITY_UNAVAILABLE`; run this on a host with
   real user/mount/PID namespaces and cgroups v2 for the rest of the script to execute for real.
2. **Normal use — fully live.** Type `ls`, `cd project`, `cat README.md`, `pwd`. Category-1
   (`safe`), no approval pause; the pipeline flow (§32) flashes Parse→Policy→AI→Simulation→Diff→
   Snapshot→Execute→Verify→Commit through in well under 100 ms each, real timings from real
   `transaction_events.duration_ms` rows. Establishes that SafeShell does not get in the way.
3. **The core moment: dangerous, permitted, previewed — via fixture, not live typing.** The
   architecture's own example is `rm -rf /project`; `rm` isn't implemented yet (see above). The
   real mechanics this step is about — deterministic risk classification routing a dangerous-but-
   supported operation to `RequireApproval` rather than `Deny`, and the approval panel rendering the
   predicted diff, reason codes, and AI advisory before anything executes — are exercised for real
   by `tests/policy_engine_tests`'s "must not be denied" corpus (`rm -rf /project`, `rm -rf /`,
   `chmod -R 777 /`, `chown -R`, mock package removal — all resolve to `RequireApproval`, never
   `Deny`) and by `orchestrator::tests::a_high_risk_command_pauses_for_approval_and_resumes_on_approve`,
   which drives the real `ApprovalPanel` data all the way from `submit_command` through a real
   `approve_transaction` call. Run either with `cargo test` to show the mechanism working; narrate
   this as "the same approval panel you'll see live the day `rm` ships" rather than performing it
   in the terminal.
4. **Recovery — fully live.** Click **Undo Last Transaction** (next to the history strip). The
   pipeline flow animates the reverse connector from wherever execution reached back to
   `Snapshotting` (§32's "on `ROLLING_BACK`, a reverse-direction connector animates... visually
   distinct from the forward flow" — the same visual language, driven by the same component, for a
   user-initiated undo as for an automatic rollback). `ls` on the affected directory confirms the
   prior state is back. State the point explicitly: SafeShell did not stop the user from doing
   something destructive — it made doing it safe.
5. **The boundary — fully live.** Type `bash`. Category-3, `DENIED`, rendered in the visually
   distinct `DenyPanel` (no approve control anywhere in that component — not styled-away, structurally
   absent), with the deterministic reason code `DENY_SHELL_INVOCATION` and its canonical text. Note
   that there is no configuration that produces an approve button here, and that this is the same
   guarantee that made step 4 safe to permit.
6. **Verification catching divergence — via fixture, not live typing.** Same handler-set limitation
   as step 3: producing a genuine execution-time mismatch through the live UI needs a real
   diff-producing command that also pauses for approval (so a test can inject drift in the gap
   between snapshot and execution), which doesn't exist with today's handlers. The mechanism is
   real and thoroughly tested: `tests/verification_tolerance_tests/meaningful_mismatch.rs`'s two
   scenarios inject real drift into the active write layer and the consolidated base between
   simulate and execute, and show `VERIFYING` → mismatch → automatic `ROLLING_BACK` → `RESTORED`
   with no user action required, via the real `Transaction` state machine and real
   `rollback::automatic_rollback`. Run `cargo test --test verification_tolerance_tests` to show it.
7. **Audit — data is real, viewer isn't built yet.** The audit log (`db::audit_queries`, §35) is
   real and hash-chained today — every policy decision, approval, denial, and rollback in this
   script writes a row, and `Database::verify_audit_chain_integrity()` really re-walks and verifies
   the chain (see that method's own tests). There is no in-app viewer for it yet — no IPC command
   exposes it and no frontend panel renders it. For this step, either query
   `sqlite3 <data dir>/safeshell.db "select * from audit_log order by id"` directly, or note it as
   the one piece of this script that's real data without a real UI in front of it yet.
8. **Honest close.** One sentence, verbatim from docs/security_claims.md's scoping statement:
   "SafeShell's guarantees are scoped to its supported command model and its isolated simulated
   environment... operations that would take it outside that scope are denied rather than
   attempted." Namespaces share the host kernel — that boundary, not the AI, is what makes the
   guarantee meaningful.

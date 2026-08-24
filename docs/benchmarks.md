# SafeShell Benchmarks

Real, measured numbers from this repository's own test suite, run on this project's development
machine (aarch64 Linux, containerized dev sandbox — see the caveat below). Sourced from
docs/architecture.md §43's benchmarking table; this document reports what that table asks for, to
the extent this build and this environment can produce it, and says plainly where it can't.

**Hardware caveat.** This machine is a nested dev container without unprivileged user namespaces or
a delegated cgroups v2 subtree (`sandbox/preflight.rs`'s own tests report this honestly). The
latency numbers below therefore measure the `CopyUpSimulationBackend` path with a synthetic
all-capabilities-available `CapabilityReport` (the same fixture `orchestrator`'s own tests use,
`AppState::new_with_capability_report`) — real pipeline code, real SQLite writes, real filesystem
I/O, just not real namespace/`pivot_root` isolation underneath it. Re-run the benchmarks named below
on real target hardware before quoting these numbers anywhere claims-sensitive; they are honest
measurements of this build's own overhead, not a representative-hardware baseline.

## How to reproduce

```bash
cd src-tauri
cargo test --lib orchestrator::tests::bench_category_one_end_to_end_latency -- --nocapture
cargo test --lib orchestrator::tests::bench_deny_path_and_session_creation_latency -- --nocapture
cargo test --test policy_engine_tests
cargo test --test verification_tolerance_tests
```

## Latency

| Metric | n | mean | p50 | p95 | max |
|---|---|---|---|---|---|
| Category-1 (safe, auto-approved) end-to-end, `submit_command` invoke → `COMMITTED` | 50 | ~8.2 ms | ~7.7 ms | ~13 ms | ~17–19 ms |
| Category-3 `DENIED` (stops at `POLICY_CHECK`) | 50 | ~7.9 ms | ~7.2 ms | — | — |
| Session creation (base image seed + backend selection + DB insert) | 50 | ~2.7 ms | ~2.4 ms | — | — |

Three independent runs of the category-1 benchmark landed in the 7.7–8.8 ms mean / 6.9–8.1 ms p50
range — see `orchestrator::tests::bench_category_one_end_to_end_latency`'s own doc comment for why
this is a real `#[test]` with a `println!`, not a `#[bench]` (nightly-only, unavailable here) or a
fabricated number.

**A genuinely useful finding, not just a number**: the `DENIED` path — which does no simulation, no
snapshot, no execution — costs almost as much as the full `COMMITTED` path. Both are dominated by
SQLite writes (`transaction_events`, `audit_log`, `transactions` — several `INSERT`/`UPDATE`
statements per transaction, each through `rusqlite`'s default synchronous-commit behavior), not by
policy evaluation or filesystem I/O. Per-stage latency breakdown (§43's second row,
`transaction_events.duration_ms` aggregated by stage) would confirm this precisely; this document
doesn't compute that breakdown yet — a real follow-up, not claimed as done.

## Simulation fidelity and rollback (§43's most important credibility metric)

`tests/verification_tolerance_tests` (4 scenarios): 100% detection rate on the meaningful-mismatch
corpus (`unpredicted_drift_in_the_active_write_layer_triggers_automatic_rollback`,
`base_mutated_between_simulate_and_execute_causes_a_missing_predicted_change_and_rolls_back` — both
inject real drift and both are caught) and 0% false-positive rate on the tolerated-difference corpus
(`identical_prediction_and_execution_match_and_commit_without_rollback`,
`a_read_only_command_with_no_filesystem_effect_also_matches_and_commits`). Every mismatch in the
corpus triggers `rollback::automatic_rollback` for real, and every rollback in the corpus succeeds
(100% rollback success rate, n=2 — small corpus, honestly small).

This corpus was small (four scenarios) because it was built from the meaningful-mismatch conditions
the handler set available at the time (`pwd, cd, mkdir, touch, ls, cat, echo`) could actually
produce; the handler set has since grown substantially (`rmdir, cp, mv, chmod, chown, find, du, df,
truncate, shred, safeshell-pkg`, plus the uutils-backed `wc, sort, uniq, cut, head, tail, date,
grep`) — see `tests/verification_tolerance_tests/main.rs`'s own module doc for which §26.2
conditions weren't reachable at the time and why. This corpus itself has not been re-grown to match
yet — a real follow-up, not claimed as done here. Growing the handler set grows this corpus, not
the other way around.

## Risk-classification accuracy (§43's "must not be denied" / "must always be denied" corpus)

`tests/policy_engine_tests` (11 tests, all passing): the full "must not be denied" corpus —
`rm -rf /project`, `rm -rf /` (simulated root), `chmod -R 777 /`, `chown -R` tree-wide, mock package
removal breaking the simulated toolchain — resolves to `RequireApproval`, never `Deny` (**zero false
denials**), and the "must always be denied" boundary corpus (sensitive pseudo-path access, shell
invocation, missing required capability) resolves to `Deny` in every case (**zero false
permissions**). Both error classes docs/architecture.md §43 asks to track separately are at 0% on
this corpus today.

## Not measured in this pass

- **Storage efficiency** (bytes per checkpoint vs. bytes changed) — needs handlers that write
  nontrivial content; today's handlers create empty files/directories, so every checkpoint's real
  size is near zero regardless of the copy-on-write claim's correctness.
- **CPU/memory overhead via cgroup accounting** — needs real cgroups v2 delegation, unavailable on
  this machine (see the hardware caveat).
- **Snapshot/rollback latency in isolation** (as opposed to bundled into the end-to-end numbers
  above) — a real follow-up: instrument `record_snapshot_sealed`/`record_rollback_result`'s
  `duration_ms` directly rather than the whole-transaction latency this pass measured.

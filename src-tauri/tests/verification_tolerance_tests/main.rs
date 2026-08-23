//! Build order phase 8's required suite (docs/CLAUDE.md's testing table):
//! "Each meaningful-mismatch condition triggers rollback; each tolerated
//! difference does not." This is also where "automatic rollback wiring"
//! (the last item in phase 8's own description) is demonstrated for
//! real: `harness::run_pipeline` drives an actual
//! `snapshot::backend::CopyUpSimulationBackend`, a real `db::Database`,
//! a real `transaction::manager::Transaction` through the real state
//! machine, `simulation::manager::simulate`, `executor::execute`, and
//! `verification::verify` — no hand-rolled stand-in for any of them.
//!
//! **Honest scope**: `handlers/mod.rs`'s current command set (`pwd, cd,
//! mkdir, touch, ls, cat, echo`) is fully deterministic and never
//! modifies an existing file's content, deletes anything, or changes
//! permissions/ownership — so two conditions from §26.2/§26.3 cannot be
//! produced by actually running this pipeline twice, only by
//! constructing `SimulationDiff`s directly:
//! - "content hash differs for a modified file" (and its allowlisted-path
//!   exemption) — no handler here ever modifies existing content, so no
//!   run of this pipeline ever produces a `files_modified` entry to
//!   diverge in the first place.
//! - "exit code class matches but the exact code differs" — no handler
//!   here produces varying nonzero exit codes.
//!
//! Both are covered for real at the function level by
//! `src/verification/mod.rs`'s own `#[cfg(test)]` module
//! (`content_hash_differing_for_a_modified_file_is_a_mismatch`,
//! `content_hash_differing_on_an_allowlisted_path_is_tolerated`,
//! `matching_exit_failure_on_both_sides_is_not_a_mismatch`) — that is a
//! real, complete test of `verification::verify`'s logic, just not
//! reachable through this end-to-end pipeline given today's handler set.
//! The remaining §26.2 conditions this suite's own module docs don't
//! reach (permission/ownership/symlink/process-effect mismatches) are
//! structurally unreachable everywhere in this crate right now — see
//! `simulation::diff`'s and `verification`'s own module docs.
//!
//! What *is* produced for real here is genuine divergence between two
//! independent runs of the same deterministic handler against two
//! different on-disk states — exactly the class of bug (an environment
//! that changed between simulate-time and execute-time) the Verification
//! Engine exists to catch, using drift injected directly into the real
//! layer directories rather than a mocked diff.

mod harness;
mod meaningful_mismatch;
mod tolerated_differences;

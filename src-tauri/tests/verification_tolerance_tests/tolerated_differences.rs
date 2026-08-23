//! §26.3's tolerated differences. Most of that table's entries
//! (`atime`/`mtime`/`ctime`, inode/device/link-count allocation,
//! ephemeral files) have no representation in `SimulationDiff` at all —
//! there is nothing for `verification::verify` to even compare, which
//! *is* the tolerance, not a gap. Directory entry ordering is proven not
//! to matter by `verification::mod.rs`'s own
//! `directory_entry_ordering_is_not_compared_at_all` unit test
//! (`compare_path_sets` is set-based). What this file adds is the
//! baseline this pipeline *can* produce for real: two independent runs of
//! the same deterministic handler, with no drift injected at all, must
//! match and commit — proving the "no divergence" path through the exact
//! same real wiring `meaningful_mismatch.rs` exercises for the divergent
//! case.

use safeshell::transaction::TransactionState;

use crate::harness::run_pipeline;

#[test]
fn identical_prediction_and_execution_match_and_commit_without_rollback() {
    let tmp = tempfile::tempdir().unwrap();

    let outcome = run_pipeline(tmp.path(), "mkdir project", |_backend, _stack| {
        // No drift: the active write layer and base are left exactly as
        // the snapshot sealed them.
    });

    assert!(
        outcome.verification.matched,
        "two runs of the same deterministic handler against unmodified state must match: {:?}",
        outcome.verification.mismatches
    );
    assert!(outcome.verification.mismatches.is_empty());
    assert!(
        outcome.rollback_outcome.is_none(),
        "a match must never trigger rollback"
    );
    assert_eq!(outcome.final_state, TransactionState::Committed);
    assert!(outcome.stack.active_write.join("project").exists());
}

#[test]
fn a_read_only_command_with_no_filesystem_effect_also_matches_and_commits() {
    let tmp = tempfile::tempdir().unwrap();

    let outcome = run_pipeline(tmp.path(), "pwd", |_backend, _stack| {});

    assert!(outcome.verification.matched);
    assert_eq!(outcome.final_state, TransactionState::Committed);
}

//! §26.2's meaningful-mismatch conditions this pipeline can actually
//! produce — see `main.rs`'s module doc for the two it can't (content
//! hash on a modified file; same-class-different-code exit codes), which
//! are covered instead by `src/verification/mod.rs`'s own unit tests.

use safeshell::transaction::TransactionState;

use crate::harness::run_pipeline;

/// Drift injected directly into the persistent active write layer,
/// between the pre-execution snapshot and execution, produces a real
/// `UnexpectedChange` — a path present in the actual diff with no
/// counterpart in the prediction — and the full rollback wiring
/// (`Transaction::record_verification_result` → `RollingBack` →
/// `rollback::automatic_rollback` → `record_rollback_result` →
/// `Restored`) runs for real in response to it.
#[test]
fn unpredicted_drift_in_the_active_write_layer_triggers_automatic_rollback() {
    let tmp = tempfile::tempdir().unwrap();

    let outcome = run_pipeline(tmp.path(), "mkdir project", |_backend, stack| {
        std::fs::write(stack.active_write.join("unexpected.txt"), b"drift").unwrap();
    });

    assert!(
        !outcome.verification.matched,
        "unpredicted drift must be detected as a mismatch: {:?}",
        outcome.verification.mismatches
    );
    assert!(outcome
        .verification
        .mismatches
        .iter()
        .any(|m| m.to_string().contains("unexpected.txt")));

    let rollback = outcome
        .rollback_outcome
        .expect("a mismatch must trigger automatic rollback");
    assert!(rollback.success);

    assert_eq!(outcome.final_state, TransactionState::Restored);
    assert!(
        !outcome.stack.active_write.join("unexpected.txt").exists(),
        "rollback must discard the drifted active write layer"
    );
    assert!(
        !outcome.stack.active_write.join("project").exists(),
        "rollback must also discard whatever the handler itself wrote"
    );
    assert_eq!(
        outcome.stack.checkpoints.len(),
        1,
        "automatic rollback keeps the sealed checkpoint — only the write layer above it is discarded"
    );
}

/// The consolidated base changing between simulate-time and execute-time
/// (simulating an environment mutated by something outside this
/// transaction) makes a predicted `mkdir` fail for real at execution
/// time: `mkdir` refuses to recreate a directory that already exists
/// anywhere in the stack (`LayeredResolver::mkdir`), so the actual run
/// produces neither the predicted directory nor a successful exit code.
/// Both a `PredictedChangeMissing` and an `ExitCodeClassDiffers` mismatch
/// come out of one real divergence.
#[test]
fn base_mutated_between_simulate_and_execute_causes_a_missing_predicted_change_and_rolls_back() {
    let tmp = tempfile::tempdir().unwrap();

    let outcome = run_pipeline(tmp.path(), "mkdir project", |_backend, stack| {
        std::fs::create_dir_all(stack.base.join("project")).unwrap();
    });

    assert!(!outcome.verification.matched);
    assert!(
        outcome
            .verification
            .mismatches
            .iter()
            .any(|m| m.to_string().contains("project")),
        "the predicted directory that never actually got created must be reported: {:?}",
        outcome.verification.mismatches
    );
    assert!(
        outcome
            .verification
            .mismatches
            .iter()
            .any(|m| m.to_string().contains("exit code class differs")),
        "mkdir failing outright at execution time must also surface as an exit-code-class mismatch: {:?}",
        outcome.verification.mismatches
    );

    let rollback = outcome
        .rollback_outcome
        .expect("a mismatch must trigger automatic rollback");
    assert!(rollback.success);
    assert_eq!(outcome.final_state, TransactionState::Restored);
}

//! Verification Engine: re-runs the same diff computation used during
//! simulation (§22.3) against the actual post-execution state and
//! compares it to the prediction (§26.1). Match within tolerance →
//! `COMMITTED`; meaningful mismatch → `ROLLING_BACK` (§26.2/§26.3).
//!
//! **Honest scope**: §26.2 lists seven mismatch conditions. Given
//! `handlers/mod.rs`'s current command set (`pwd, cd, mkdir, touch, ls,
//! cat, echo, rm`) — same set `simulation::diff`'s own module doc already
//! scopes — permission/ownership changes, symlinks, and process effects
//! never occur in any diff this crate can currently produce, so the
//! mismatch conditions built on them (`permission_changes`,
//! `ownership_changes`, `symlink_changes`, sandbox-local process
//! start/stop) are structurally unreachable right now rather than
//! silently unimplemented: [`Mismatch`] simply has no variant for them
//! yet, and this module's tests only exercise what current handlers can
//! actually produce — path presence/absence (including deletion),
//! content-hash divergence, and exit-code class. The remaining ones
//! become real the moment `chmod`/`chown`/`ln` handlers exist and
//! `SimulationDiff` grows the corresponding fields.

pub mod tolerance;

use std::collections::HashSet;

use crate::simulation::diff::SimulationDiff;
use crate::verification::tolerance::NondeterminismAllowlist;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    FileCreated,
    FileModified,
    DirectoryCreated,
    FileDeleted,
    DirectoryDeleted,
}

impl std::fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ChangeKind::FileCreated => "file created",
            ChangeKind::FileModified => "file modified",
            ChangeKind::DirectoryCreated => "directory created",
            ChangeKind::FileDeleted => "file deleted",
            ChangeKind::DirectoryDeleted => "directory deleted",
        };
        write!(f, "{s}")
    }
}

/// One instance of a §26.2 meaningful-mismatch condition. `Display`
/// renders the human-readable detail that feeds
/// `transaction::manager::Transaction::record_verification_result`'s
/// `mismatch_detail` parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    /// "A path was created, modified, or deleted in actual but not
    /// predicted" (§26.2).
    UnexpectedChange { path: String, kind: ChangeKind },
    /// "A path was predicted to be created, modified, or deleted but was
    /// not" (§26.2).
    PredictedChangeMissing { path: String, kind: ChangeKind },
    /// "Content hash differs for a modified file not on the declared
    /// nondeterminism allowlist" (§26.2). Only raised for paths present
    /// in *both* diffs as created-or-modified — a path missing from one
    /// side entirely is an `UnexpectedChange`/`PredictedChangeMissing`
    /// instead, not this.
    ContentHashDiffers { path: String },
    /// "Exit code class differs (success vs failure)" (§26.2).
    ExitCodeClassDiffers {
        predicted_success: bool,
        actual_success: bool,
    },
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mismatch::UnexpectedChange { path, kind } => {
                write!(f, "{path}: unexpected {kind} not present in the prediction")
            }
            Mismatch::PredictedChangeMissing { path, kind } => {
                write!(f, "{path}: predicted {kind} did not occur")
            }
            Mismatch::ContentHashDiffers { path } => {
                write!(f, "{path}: content hash differs from the prediction")
            }
            Mismatch::ExitCodeClassDiffers {
                predicted_success,
                actual_success,
            } => write!(
                f,
                "exit code class differs: predicted {}, actual {}",
                success_label(*predicted_success),
                success_label(*actual_success)
            ),
        }
    }
}

fn success_label(success: bool) -> &'static str {
    if success {
        "success"
    } else {
        "failure"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    pub matched: bool,
    pub mismatches: Vec<Mismatch>,
}

impl VerificationResult {
    /// Joins every mismatch's `Display` into one string — the
    /// `mismatch_detail` `record_verification_result` expects, `None` when
    /// there is nothing to report.
    pub fn detail(&self) -> Option<String> {
        if self.mismatches.is_empty() {
            None
        } else {
            Some(
                self.mismatches
                    .iter()
                    .map(|m| m.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        }
    }
}

/// §26.1's comparison. `predicted_diff`/`predicted_exit_code` come from
/// `simulation::manager::simulate`'s `SimulationOutcome`; `actual_diff`/
/// `actual_exit_code` come from `executor`'s equivalent. `allowlist` is
/// §26.3's declared nondeterminism allowlist.
pub fn verify(
    predicted_diff: &SimulationDiff,
    predicted_exit_code: i32,
    actual_diff: &SimulationDiff,
    actual_exit_code: i32,
    allowlist: &NondeterminismAllowlist,
) -> VerificationResult {
    let mut mismatches = Vec::new();

    compare_path_sets(
        &predicted_diff.files_created,
        &actual_diff.files_created,
        ChangeKind::FileCreated,
        &mut mismatches,
    );
    compare_path_sets(
        &predicted_diff.files_modified,
        &actual_diff.files_modified,
        ChangeKind::FileModified,
        &mut mismatches,
    );
    compare_path_sets(
        &predicted_diff.directories_created,
        &actual_diff.directories_created,
        ChangeKind::DirectoryCreated,
        &mut mismatches,
    );
    compare_path_sets(
        &predicted_diff.files_deleted,
        &actual_diff.files_deleted,
        ChangeKind::FileDeleted,
        &mut mismatches,
    );
    compare_path_sets(
        &predicted_diff.directories_deleted,
        &actual_diff.directories_deleted,
        ChangeKind::DirectoryDeleted,
        &mut mismatches,
    );

    // Content-hash check: only for paths both sides agree were
    // created-or-modified (a presence disagreement was already reported
    // above by compare_path_sets, and reporting it again here as a hash
    // mismatch too would be redundant noise about the same underlying
    // fact).
    let predicted_touched = touched_paths(predicted_diff);
    let actual_touched = touched_paths(actual_diff);
    for path in predicted_touched.intersection(&actual_touched) {
        if allowlist.is_allowed(path) {
            continue;
        }
        let predicted_hash = predicted_diff.content_hashes.get(path);
        let actual_hash = actual_diff.content_hashes.get(path);
        if predicted_hash != actual_hash {
            mismatches.push(Mismatch::ContentHashDiffers { path: path.clone() });
        }
    }

    let predicted_success = predicted_exit_code == 0;
    let actual_success = actual_exit_code == 0;
    if predicted_success != actual_success {
        mismatches.push(Mismatch::ExitCodeClassDiffers {
            predicted_success,
            actual_success,
        });
    }

    VerificationResult {
        matched: mismatches.is_empty(),
        mismatches,
    }
}

fn touched_paths(diff: &SimulationDiff) -> HashSet<String> {
    diff.files_created
        .iter()
        .chain(diff.files_modified.iter())
        .cloned()
        .collect()
}

fn compare_path_sets(
    predicted: &[String],
    actual: &[String],
    kind: ChangeKind,
    mismatches: &mut Vec<Mismatch>,
) {
    let predicted_set: HashSet<&String> = predicted.iter().collect();
    let actual_set: HashSet<&String> = actual.iter().collect();

    for path in actual_set.difference(&predicted_set) {
        mismatches.push(Mismatch::UnexpectedChange {
            path: (*path).clone(),
            kind,
        });
    }
    for path in predicted_set.difference(&actual_set) {
        mismatches.push(Mismatch::PredictedChangeMissing {
            path: (*path).clone(),
            kind,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diff_with(created: &[&str], modified: &[&str], dirs: &[&str]) -> SimulationDiff {
        SimulationDiff {
            files_created: created.iter().map(|s| s.to_string()).collect(),
            files_modified: modified.iter().map(|s| s.to_string()).collect(),
            directories_created: dirs.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn diff_with_deletions(files_deleted: &[&str], directories_deleted: &[&str]) -> SimulationDiff {
        SimulationDiff {
            files_deleted: files_deleted.iter().map(|s| s.to_string()).collect(),
            directories_deleted: directories_deleted.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    // --- §26.2 meaningful mismatches ---

    #[test]
    fn identical_predicted_and_actual_diffs_match() {
        let predicted = diff_with(&["a.txt"], &[], &["project"]);
        let actual = diff_with(&["a.txt"], &[], &["project"]);
        let result = verify(&predicted, 0, &actual, 0, &NondeterminismAllowlist::empty());
        assert!(result.matched);
        assert!(result.mismatches.is_empty());
    }

    #[test]
    fn a_path_created_in_actual_but_not_predicted_is_a_mismatch() {
        let predicted = diff_with(&[], &[], &[]);
        let actual = diff_with(&["surprise.txt"], &[], &[]);
        let result = verify(&predicted, 0, &actual, 0, &NondeterminismAllowlist::empty());
        assert!(!result.matched);
        assert_eq!(
            result.mismatches,
            vec![Mismatch::UnexpectedChange {
                path: "surprise.txt".into(),
                kind: ChangeKind::FileCreated,
            }]
        );
    }

    #[test]
    fn a_path_predicted_but_not_actually_created_is_a_mismatch() {
        let predicted = diff_with(&["expected.txt"], &[], &[]);
        let actual = diff_with(&[], &[], &[]);
        let result = verify(&predicted, 0, &actual, 0, &NondeterminismAllowlist::empty());
        assert!(!result.matched);
        assert_eq!(
            result.mismatches,
            vec![Mismatch::PredictedChangeMissing {
                path: "expected.txt".into(),
                kind: ChangeKind::FileCreated,
            }]
        );
    }

    #[test]
    fn an_unpredicted_directory_is_a_mismatch() {
        let predicted = diff_with(&[], &[], &[]);
        let actual = diff_with(&[], &[], &["unexpected_dir"]);
        let result = verify(&predicted, 0, &actual, 0, &NondeterminismAllowlist::empty());
        assert!(!result.matched);
        assert_eq!(
            result.mismatches,
            vec![Mismatch::UnexpectedChange {
                path: "unexpected_dir".into(),
                kind: ChangeKind::DirectoryCreated,
            }]
        );
    }

    #[test]
    fn a_predicted_file_deletion_that_did_not_happen_is_a_mismatch() {
        let predicted = diff_with_deletions(&["a.txt"], &[]);
        let actual = diff_with_deletions(&[], &[]);
        let result = verify(&predicted, 0, &actual, 0, &NondeterminismAllowlist::empty());
        assert!(!result.matched);
        assert_eq!(
            result.mismatches,
            vec![Mismatch::PredictedChangeMissing {
                path: "a.txt".into(),
                kind: ChangeKind::FileDeleted,
            }]
        );
    }

    #[test]
    fn an_unpredicted_directory_deletion_is_a_mismatch() {
        let predicted = diff_with_deletions(&[], &[]);
        let actual = diff_with_deletions(&[], &["project"]);
        let result = verify(&predicted, 0, &actual, 0, &NondeterminismAllowlist::empty());
        assert!(!result.matched);
        assert_eq!(
            result.mismatches,
            vec![Mismatch::UnexpectedChange {
                path: "project".into(),
                kind: ChangeKind::DirectoryDeleted,
            }]
        );
    }

    #[test]
    fn matching_deletions_on_both_sides_are_not_a_mismatch() {
        let predicted = diff_with_deletions(&["a.txt"], &["project"]);
        let actual = diff_with_deletions(&["a.txt"], &["project"]);
        let result = verify(&predicted, 0, &actual, 0, &NondeterminismAllowlist::empty());
        assert!(result.matched);
    }

    #[test]
    fn exit_code_class_differing_is_a_mismatch() {
        let predicted = diff_with(&[], &[], &[]);
        let actual = diff_with(&[], &[], &[]);
        let result = verify(&predicted, 0, &actual, 1, &NondeterminismAllowlist::empty());
        assert!(!result.matched);
        assert_eq!(
            result.mismatches,
            vec![Mismatch::ExitCodeClassDiffers {
                predicted_success: true,
                actual_success: false,
            }]
        );
    }

    #[test]
    fn content_hash_differing_for_a_modified_file_is_a_mismatch() {
        let mut predicted = diff_with(&[], &["a.txt"], &[]);
        predicted
            .content_hashes
            .insert("a.txt".into(), "hash_predicted".into());
        let mut actual = diff_with(&[], &["a.txt"], &[]);
        actual
            .content_hashes
            .insert("a.txt".into(), "hash_actual".into());

        let result = verify(&predicted, 0, &actual, 0, &NondeterminismAllowlist::empty());
        assert!(!result.matched);
        assert_eq!(
            result.mismatches,
            vec![Mismatch::ContentHashDiffers {
                path: "a.txt".into()
            }]
        );
    }

    // --- §26.3 tolerated differences ---

    #[test]
    fn content_hash_differing_on_an_allowlisted_path_is_tolerated() {
        let mut predicted = diff_with(&[], &["var/log/mock.log"], &[]);
        predicted
            .content_hashes
            .insert("var/log/mock.log".into(), "hash_predicted".into());
        let mut actual = diff_with(&[], &["var/log/mock.log"], &[]);
        actual
            .content_hashes
            .insert("var/log/mock.log".into(), "hash_actual".into());

        let allowlist = NondeterminismAllowlist::parse(
            r#"schema_version = "1"
                   paths = ["var/log/mock.log"]"#,
            "test",
        )
        .unwrap();
        let result = verify(&predicted, 0, &actual, 0, &allowlist);
        assert!(
            result.matched,
            "an allowlisted path's content hash must not trigger a mismatch: {:?}",
            result.mismatches
        );
    }

    #[test]
    fn matching_exit_failure_on_both_sides_is_not_a_mismatch() {
        let predicted = diff_with(&[], &[], &[]);
        let actual = diff_with(&[], &[], &[]);
        let result = verify(&predicted, 1, &actual, 2, &NondeterminismAllowlist::empty());
        assert!(
            result.matched,
            "both are 'failure' class even though the exact codes differ"
        );
    }

    #[test]
    fn directory_entry_ordering_is_not_compared_at_all() {
        // compare_path_sets is set-based, not order-based — construct the
        // same paths in different Vec order on each side and confirm that
        // alone never produces a mismatch.
        let predicted = diff_with(&["b.txt", "a.txt"], &[], &[]);
        let actual = diff_with(&["a.txt", "b.txt"], &[], &[]);
        let result = verify(&predicted, 0, &actual, 0, &NondeterminismAllowlist::empty());
        assert!(result.matched);
    }

    #[test]
    fn detail_joins_multiple_mismatches_and_is_none_when_matched() {
        let predicted = diff_with(&[], &[], &[]);
        let actual = diff_with(&["a.txt"], &[], &[]);
        let mismatched = verify(&predicted, 0, &actual, 0, &NondeterminismAllowlist::empty());
        assert!(mismatched.detail().unwrap().contains("a.txt"));

        let matched = verify(
            &predicted,
            0,
            &predicted,
            0,
            &NondeterminismAllowlist::empty(),
        );
        assert_eq!(matched.detail(), None);
    }
}

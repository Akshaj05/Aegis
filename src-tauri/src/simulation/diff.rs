// Computes what a simulation pass changed by walking the transient
// layer and classifying each entry against the layers beneath it.

use std::collections::HashMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::sandbox::worker::protocol::FileKind;
use crate::sandbox::worker::resolver::WHITEOUT_PREFIX;
use crate::simulation::resolver::LayeredResolver;
use crate::snapshot::backend::MountedView;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimulationDiff {
    pub files_created: Vec<String>,
    pub files_modified: Vec<String>,
    pub directories_created: Vec<String>,
    pub files_deleted: Vec<String>,
    pub directories_deleted: Vec<String>,
    pub bytes_deleted: u64,
    pub bytes_affected: u64,
    pub content_hashes: HashMap<String, String>,
}

impl SimulationDiff {
    pub fn files_affected(&self) -> u64 {
        (self.files_created.len() + self.files_modified.len() + self.files_deleted.len()) as u64
    }
}

pub fn compute(
    transient_layer_path: &Path,
    lower_view: &MountedView,
) -> std::io::Result<SimulationDiff> {
    let lower_only = MountedView {
        layers: lower_view.layers[1..].to_vec(),
    };
    let lower_resolver = if lower_only.layers.is_empty() {
        None
    } else {
        Some(LayeredResolver::from_mounted_view(&lower_only)?)
    };

    let mut diff = SimulationDiff::default();
    walk(
        transient_layer_path,
        transient_layer_path,
        lower_resolver.as_ref(),
        &mut diff,
    )?;
    Ok(diff)
}

fn walk(
    root: &Path,
    current: &Path,
    lower: Option<&LayeredResolver>,
    diff: &mut SimulationDiff,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        let rel_path = relative_path_str(root, &path);

        if let Some(real_name) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.strip_prefix(WHITEOUT_PREFIX))
        {
            let deleted_rel = match rel_path.rsplit_once('/') {
                Some((parent, _marker_name)) => format!("{parent}/{real_name}"),
                None => real_name.to_string(),
            };
            match lower.and_then(|l| l.stat(&deleted_rel).ok()) {
                Some(info) if info.kind == FileKind::Directory => {
                    diff.directories_deleted.push(deleted_rel);
                }
                Some(info) => {
                    diff.bytes_deleted += info.len;
                    diff.files_deleted.push(deleted_rel);
                }
                None => {}
            }
            continue;
        }

        if metadata.is_dir() {
            let existed_before = lower.is_some_and(|l| l.stat(&rel_path).is_ok());
            if !existed_before {
                diff.directories_created.push(rel_path);
            }
            walk(root, &path, lower, diff)?;
        } else {
            let bytes = std::fs::read(&path)?;
            diff.bytes_affected += bytes.len() as u64;

            let existed_before = lower.and_then(|l| l.read_file(&rel_path).ok());
            match existed_before {
                Some(previous_contents) if previous_contents == bytes => {}
                Some(_) => {
                    diff.content_hashes
                        .insert(rel_path.clone(), hex_sha256(&bytes));
                    diff.files_modified.push(rel_path);
                }
                None => {
                    diff.content_hashes
                        .insert(rel_path.clone(), hex_sha256(&bytes));
                    diff.files_created.push(rel_path);
                }
            }
        }
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn relative_path_str(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("walk() always passes a descendant of root")
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn view_of(dirs: &[&Path]) -> MountedView {
        MountedView {
            layers: dirs.iter().map(PathBuf::from).collect(),
        }
    }

    #[test]
    fn a_new_file_in_the_transient_layer_is_created() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::fs::write(transient.path().join("new.txt"), b"hello").unwrap();

        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();

        assert_eq!(diff.files_created, vec!["new.txt".to_string()]);
        assert!(diff.files_modified.is_empty());
        assert_eq!(diff.bytes_affected, 5);
    }

    #[test]
    fn a_copied_up_but_unchanged_file_is_not_reported_as_a_change() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("a.txt"), b"same content").unwrap();
        std::fs::write(transient.path().join("a.txt"), b"same content").unwrap();

        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();

        assert!(diff.files_created.is_empty());
        assert!(diff.files_modified.is_empty());
    }

    #[test]
    fn a_copied_up_and_changed_file_is_modified() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("a.txt"), b"original").unwrap();
        std::fs::write(transient.path().join("a.txt"), b"changed").unwrap();

        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();

        assert_eq!(diff.files_modified, vec!["a.txt".to_string()]);
        assert!(diff.files_created.is_empty());
    }

    #[test]
    fn a_new_directory_is_reported_as_created() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir(transient.path().join("project")).unwrap();

        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();

        assert_eq!(diff.directories_created, vec!["project".to_string()]);
    }

    #[test]
    fn nested_entries_get_correct_relative_paths() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir(transient.path().join("project")).unwrap();
        std::fs::write(transient.path().join("project/file.txt"), b"nested").unwrap();

        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();

        assert_eq!(diff.directories_created, vec!["project".to_string()]);
        assert_eq!(diff.files_created, vec!["project/file.txt".to_string()]);
    }

    #[test]
    fn empty_transient_layer_is_an_empty_diff() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();
        assert_eq!(diff, SimulationDiff::default());
    }

    #[test]
    fn files_affected_counts_created_and_modified() {
        let mut diff = SimulationDiff::default();
        diff.files_created.push("a".into());
        diff.files_modified.push("b".into());
        diff.files_modified.push("c".into());
        assert_eq!(diff.files_affected(), 3);
    }

    #[test]
    fn content_hash_is_recorded_for_created_and_modified_files() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("a.txt"), b"original").unwrap();
        std::fs::write(transient.path().join("a.txt"), b"changed").unwrap();
        std::fs::write(transient.path().join("new.txt"), b"brand new").unwrap();

        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();

        assert_eq!(diff.content_hashes.len(), 2);
        assert_eq!(
            diff.content_hashes["a.txt"],
            hex_sha256(b"changed"),
            "modified file's hash must reflect its new content, not the original"
        );
        assert_eq!(diff.content_hashes["new.txt"], hex_sha256(b"brand new"));
    }

    #[test]
    fn a_whiteout_marker_for_a_lower_layer_file_is_reported_as_a_file_deletion() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("a.txt"), b"gone soon").unwrap();
        std::fs::write(transient.path().join(".wh.a.txt"), b"").unwrap();

        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();

        assert_eq!(diff.files_deleted, vec!["a.txt".to_string()]);
        assert!(diff.directories_deleted.is_empty());
        assert!(diff.files_created.is_empty());
    }

    #[test]
    fn a_whiteout_marker_for_a_lower_layer_directory_is_reported_as_a_directory_deletion() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir(base.path().join("project")).unwrap();
        std::fs::write(transient.path().join(".wh.project"), b"").unwrap();

        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();

        assert_eq!(diff.directories_deleted, vec!["project".to_string()]);
        assert!(diff.files_deleted.is_empty());
    }

    #[test]
    fn a_deleted_files_size_is_recorded_in_bytes_deleted_and_counted_as_affected() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("a.txt"), b"twelve bytes").unwrap();
        std::fs::write(transient.path().join(".wh.a.txt"), b"").unwrap();

        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();

        assert_eq!(diff.bytes_deleted, 12);
        assert_eq!(diff.files_affected(), 1);
    }

    #[test]
    fn a_nested_whiteout_marker_gets_the_correct_relative_deleted_path() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(base.path().join("project")).unwrap();
        std::fs::write(base.path().join("project/file.txt"), b"data").unwrap();
        std::fs::create_dir_all(transient.path().join("project")).unwrap();
        std::fs::write(transient.path().join("project/.wh.file.txt"), b"").unwrap();

        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();

        assert_eq!(diff.files_deleted, vec!["project/file.txt".to_string()]);
    }

    #[test]
    fn content_hash_is_not_recorded_for_an_unchanged_copy_up() {
        let transient = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("a.txt"), b"same content").unwrap();
        std::fs::write(transient.path().join("a.txt"), b"same content").unwrap();

        let view = view_of(&[transient.path(), base.path()]);
        let diff = compute(transient.path(), &view).unwrap();

        assert!(diff.content_hashes.is_empty());
    }
}

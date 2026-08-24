// Loads and validates the nondeterministic-paths allowlist manifest used to
// tolerate declared, expected content differences during verification.

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NondeterministicPathsFile {
    #[allow(dead_code)]
    schema_version: String,
    paths: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ToleranceLoadError {
    #[error("could not read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("could not parse {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NondeterminismAllowlist {
    paths: HashSet<String>,
}

impl NondeterminismAllowlist {
    pub fn load(path: &Path) -> Result<Self, ToleranceLoadError> {
        let path_str = path.display().to_string();
        let contents = std::fs::read_to_string(path).map_err(|e| ToleranceLoadError::Read {
            path: path_str.clone(),
            source: e,
        })?;
        Self::parse(&contents, &path_str)
    }

    pub(crate) fn parse(contents: &str, path_str: &str) -> Result<Self, ToleranceLoadError> {
        let file: NondeterministicPathsFile =
            toml::from_str(contents).map_err(|e| ToleranceLoadError::Parse {
                path: path_str.to_string(),
                source: e,
            })?;
        Ok(NondeterminismAllowlist {
            paths: file.paths.into_iter().collect(),
        })
    }

    pub fn empty() -> Self {
        NondeterminismAllowlist::default()
    }

    pub fn is_allowed(&self, rel_path: &str) -> bool {
        self.paths.contains(rel_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listed_path_is_allowed() {
        let allowlist = NondeterminismAllowlist::parse(
            r#"
            schema_version = "1"
            paths = ["var/log/mock.log"]
            "#,
            "test",
        )
        .unwrap();
        assert!(allowlist.is_allowed("var/log/mock.log"));
    }

    #[test]
    fn an_unlisted_path_is_not_allowed() {
        let allowlist = NondeterminismAllowlist::parse(
            r#"
            schema_version = "1"
            paths = ["var/log/mock.log"]
            "#,
            "test",
        )
        .unwrap();
        assert!(!allowlist.is_allowed("project/important.txt"));
    }

    #[test]
    fn empty_allowlist_tolerates_nothing() {
        let allowlist = NondeterminismAllowlist::empty();
        assert!(!allowlist.is_allowed("anything"));
    }

    #[test]
    fn malformed_toml_is_a_load_error_not_a_silently_empty_allowlist() {
        let result = NondeterminismAllowlist::parse("not valid toml [[[", "test");
        assert!(matches!(result, Err(ToleranceLoadError::Parse { .. })));
    }

    #[test]
    fn missing_file_is_a_read_error() {
        let result = NondeterminismAllowlist::load(Path::new("/does/not/exist.toml"));
        assert!(matches!(result, Err(ToleranceLoadError::Read { .. })));
    }

    #[test]
    fn the_real_project_manifest_loads_and_self_validates() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("simulated-root-image/nondeterministic-paths.toml");
        NondeterminismAllowlist::load(&path).unwrap();
    }
}

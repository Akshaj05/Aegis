//! Loads `simulated-root-image/mock-package-db.json` — the mock package
//! database `handlers::pkg`'s `safeshell-pkg` handler reads/mutates,
//! per-session. Same posture as `verification::tolerance`'s
//! `NondeterminismAllowlist::load` and `policy::support_tiers`'s
//! `SupportTierTable::load`: self-validates on load, fails closed on a
//! malformed file rather than silently starting every session with an
//! empty package list that happens to look the same as "genuinely no
//! packages."
//!
//! This file was real, well-formed seed data sitting unread since Build
//! order phase 3 (its own `_comment` field said so: "No handler reads
//! this file yet... a disclosed gap, not a silent one") — this module is
//! what closes that gap.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// One entry in the mock package database. `essential` mirrors real
/// package managers' "removing this breaks the system" flag — SafeShell's
/// policy/risk classifier (`policy::risk::TOOLCHAIN_CRITICAL_PACKAGES`)
/// can't read this file itself (pure command-line classification, no
/// session access — see that constant's doc comment), so it hardcodes the
/// one seeded essential package's name instead; this field is what the
/// handler itself uses to decide whether a removal is *allowed* to
/// proceed at all as a "just do it" versus something worth a stronger
/// warning in its own output, independent of the separate policy-level
/// approval gate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MockPackage {
    pub name: String,
    pub version: String,
    pub essential: bool,
}

#[derive(Debug, Deserialize)]
struct MockPackageDbFile {
    #[allow(dead_code)] // read for validation only; not consulted at runtime
    schema_version: String,
    packages: Vec<MockPackage>,
}

#[derive(Debug, thiserror::Error)]
pub enum MockPackageDbLoadError {
    #[error("could not read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("could not parse {path}: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
}

pub fn load(path: &Path) -> Result<Vec<MockPackage>, MockPackageDbLoadError> {
    let path_str = path.display().to_string();
    let contents = std::fs::read_to_string(path).map_err(|e| MockPackageDbLoadError::Read {
        path: path_str.clone(),
        source: e,
    })?;
    let file: MockPackageDbFile =
        serde_json::from_str(&contents).map_err(|e| MockPackageDbLoadError::Parse {
            path: path_str,
            source: e,
        })?;
    Ok(file.packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_real_seed_file_loads_and_contains_the_essential_toolchain_package() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../simulated-root-image/mock-package-db.json"
        );
        let packages = load(Path::new(path)).unwrap();
        let toolchain = packages
            .iter()
            .find(|p| p.name == "safeshell-toolchain")
            .expect("the real seed file must list safeshell-toolchain");
        assert!(toolchain.essential);
    }

    #[test]
    fn a_missing_file_is_a_read_error() {
        let result = load(Path::new("/does/not/exist.json"));
        assert!(matches!(result, Err(MockPackageDbLoadError::Read { .. })));
    }

    #[test]
    fn malformed_json_is_a_parse_error_not_a_silently_empty_list() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "not json at all").unwrap();
        let result = load(tmp.path());
        assert!(matches!(result, Err(MockPackageDbLoadError::Parse { .. })));
    }
}

// Loads and validates the mock package database (mock-package-db.json)
// used by the safeshell-pkg handler to track a session's installed packages.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MockPackage {
    pub name: String,
    pub version: String,
    pub essential: bool,
}

#[derive(Debug, Deserialize)]
struct MockPackageDbFile {
    #[allow(dead_code)]
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

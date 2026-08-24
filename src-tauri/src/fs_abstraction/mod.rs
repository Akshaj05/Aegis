// Path types and resolution: SandboxPath (validated, sandbox-relative
// paths) and HostManagedPath (host paths derived only from configuration).

use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SandboxPath(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxPathError {
    #[error("path is empty")]
    Empty,
    #[error("path contains a NUL byte")]
    ContainsNul,
    #[error("path component `..` is not allowed: {0}")]
    ParentComponent(String),
    #[error("path component is empty (repeated or trailing separator): {0}")]
    EmptyComponent(String),
}

impl SandboxPath {
    pub fn parse(input: &str) -> Result<Self, SandboxPathError> {
        if input.is_empty() {
            return Err(SandboxPathError::Empty);
        }
        if input.contains('\0') {
            return Err(SandboxPathError::ContainsNul);
        }

        let mut normalized_parts: Vec<&str> = Vec::new();
        for component in input.split('/') {
            match component {
                "" | "." => continue,
                ".." => return Err(SandboxPathError::ParentComponent(input.to_string())),
                c => normalized_parts.push(c),
            }
        }

        Ok(SandboxPath(normalized_parts.join("/")))
    }

    pub fn root() -> Self {
        SandboxPath(String::new())
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn join(&self, component: &str) -> Result<Self, SandboxPathError> {
        if component.is_empty() {
            return Err(SandboxPathError::EmptyComponent(component.to_string()));
        }
        if component == ".." {
            return Err(SandboxPathError::ParentComponent(component.to_string()));
        }
        if component.contains('/') || component.contains('\0') {
            return Err(SandboxPathError::EmptyComponent(component.to_string()));
        }
        if self.0.is_empty() {
            Ok(SandboxPath(component.to_string()))
        } else {
            Ok(SandboxPath(format!("{}/{}", self.0, component)))
        }
    }

    pub fn parent(&self) -> Option<Self> {
        if self.0.is_empty() {
            return None;
        }
        match self.0.rsplit_once('/') {
            Some((parent, _)) => Some(SandboxPath(parent.to_string())),
            None => Some(SandboxPath::root()),
        }
    }

    pub fn file_name(&self) -> Option<&str> {
        if self.0.is_empty() {
            None
        } else {
            Some(self.0.rsplit('/').next().unwrap())
        }
    }

    pub fn resolve_relative(&self, raw: &str) -> Result<Self, SandboxPathError> {
        if raw.contains('\0') {
            return Err(SandboxPathError::ContainsNul);
        }

        let mut parts: Vec<&str> = if raw.starts_with('/') {
            Vec::new()
        } else {
            self.0.split('/').filter(|s| !s.is_empty()).collect()
        };

        for component in raw.split('/') {
            match component {
                "" | "." => continue,
                ".." => {
                    parts.pop();
                }
                c => parts.push(c),
            }
        }

        Ok(SandboxPath(parts.join("/")))
    }
}

impl fmt::Display for SandboxPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostManagedPath(PathBuf);

impl HostManagedPath {
    pub fn from_config(path: PathBuf) -> Self {
        HostManagedPath(path)
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_relative_path() {
        let p = SandboxPath::parse("project/build").unwrap();
        assert_eq!(p.as_str(), "project/build");
    }

    #[test]
    fn treats_leading_slash_as_relative_to_sandbox_root() {
        let p = SandboxPath::parse("/project/build").unwrap();
        assert_eq!(p.as_str(), "project/build");
    }

    #[test]
    fn rejects_parent_component() {
        let err = SandboxPath::parse("project/../etc").unwrap_err();
        assert_eq!(
            err,
            SandboxPathError::ParentComponent("project/../etc".into())
        );
    }

    #[test]
    fn rejects_bare_parent_component() {
        assert!(SandboxPath::parse("..").is_err());
        assert!(SandboxPath::parse("../../etc/passwd").is_err());
    }

    #[test]
    fn rejects_nul_byte() {
        assert!(SandboxPath::parse("foo\0bar").is_err());
    }

    #[test]
    fn collapses_dot_and_repeated_slashes() {
        let p = SandboxPath::parse("./project//build/./").unwrap();
        assert_eq!(p.as_str(), "project/build");
    }

    #[test]
    fn root_is_root() {
        assert!(SandboxPath::root().is_root());
        assert!(SandboxPath::parse("/").unwrap().is_root());
    }

    #[test]
    fn join_rejects_parent_and_separators() {
        let base = SandboxPath::parse("project").unwrap();
        assert!(base.join("..").is_err());
        assert!(base.join("a/b").is_err());
        assert!(base.join("").is_err());
    }

    #[test]
    fn join_and_parent_roundtrip() {
        let base = SandboxPath::root();
        let child = base.join("project").unwrap().join("build").unwrap();
        assert_eq!(child.as_str(), "project/build");
        assert_eq!(child.parent().unwrap().as_str(), "project");
        assert_eq!(child.file_name(), Some("build"));
    }

    #[test]
    fn resolve_relative_handles_dotdot_by_popping() {
        let base = SandboxPath::parse("project/build").unwrap();
        let resolved = base.resolve_relative("..").unwrap();
        assert_eq!(resolved.as_str(), "project");
    }

    #[test]
    fn resolve_relative_clamps_dotdot_at_root() {
        let base = SandboxPath::root();
        let resolved = base.resolve_relative("../../../etc").unwrap();
        assert_eq!(resolved.as_str(), "etc");
    }

    #[test]
    fn resolve_relative_leading_slash_restarts_from_root() {
        let base = SandboxPath::parse("project/build").unwrap();
        let resolved = base.resolve_relative("/etc/passwd").unwrap();
        assert_eq!(resolved.as_str(), "etc/passwd");
    }

    #[test]
    fn resolve_relative_relative_component_appends() {
        let base = SandboxPath::parse("project").unwrap();
        let resolved = base.resolve_relative("build/../src").unwrap();
        assert_eq!(resolved.as_str(), "project/src");
    }
}

//! Loads `policies/supported_commands.toml` and resolves a command name to
//! its support tier (§19.1, §19.2). Self-validates on load — §28's
//! "Policy engine failure" row: "A policy engine that cannot answer is
//! treated as a Deny for everything, not an Allow" — so a malformed or
//! missing file must surface as a load error the caller fails closed on,
//! never as a silently-empty table that defaults everything to
//! `Unsupported`-and-therefore-harmless.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::policy::types::{ReasonCode, SupportTier};

#[derive(Debug, Deserialize)]
struct SupportedCommandsFile {
    #[allow(dead_code)] // read for validation only; not consulted at runtime
    schema_version: String,
    tiers: TiersSection,
}

#[derive(Debug, Deserialize)]
struct TiersSection {
    supported: TierCommands,
    partially_supported: PartiallySupportedTier,
    unsupported: TierCommands,
    denied: DeniedTier,
}

#[derive(Debug, Deserialize)]
struct TierCommands {
    commands: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PartiallySupportedTier {
    commands: Vec<String>,
    #[serde(default)]
    divergences: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct DeniedTier {
    commands: Vec<String>,
    reason_code: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SupportTierLoadError {
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
    #[error("{path}: command {command:?} appears in more than one tier ({first} and {second})")]
    DuplicateCommand {
        path: String,
        command: String,
        first: &'static str,
        second: &'static str,
    },
    #[error("{path}: denied-tier reason_code {reason_code:?} is not a recognized ReasonCode")]
    UnknownDeniedReasonCode { path: String, reason_code: String },
}

/// A loaded, self-validated support-tier table. Immutable once
/// constructed — reloading (e.g. on a config change) means constructing a
/// new one, never mutating this in place, so a `PolicyEngine` holding an
/// `Arc<SupportTierTable>` can't observe a table half-updated mid-read.
#[derive(Debug)]
pub struct SupportTierTable {
    tiers: HashMap<String, SupportTier>,
    divergences: HashMap<String, String>,
    denied_reason_code: ReasonCode,
}

impl SupportTierTable {
    pub fn load(path: &Path) -> Result<Self, SupportTierLoadError> {
        let path_str = path.display().to_string();
        let contents = std::fs::read_to_string(path).map_err(|e| SupportTierLoadError::Read {
            path: path_str.clone(),
            source: e,
        })?;
        Self::parse(&contents, &path_str)
    }

    /// `pub(crate)` rather than private: `policy::engine`'s tests build
    /// fixture tables directly from inline TOML strings via this, rather
    /// than round-tripping through a temp file just to reach `load`.
    pub(crate) fn parse(contents: &str, path_str: &str) -> Result<Self, SupportTierLoadError> {
        let file: SupportedCommandsFile =
            toml::from_str(contents).map_err(|e| SupportTierLoadError::Parse {
                path: path_str.to_string(),
                source: e,
            })?;

        let mut tiers = HashMap::new();
        let mut seen: HashMap<String, &'static str> = HashMap::new();

        let insert = |commands: &[String],
                      tier: SupportTier,
                      label: &'static str,
                      tiers: &mut HashMap<String, SupportTier>,
                      seen: &mut HashMap<String, &'static str>|
         -> Result<(), SupportTierLoadError> {
            for name in commands {
                if let Some(&first) = seen.get(name) {
                    return Err(SupportTierLoadError::DuplicateCommand {
                        path: path_str.to_string(),
                        command: name.clone(),
                        first,
                        second: label,
                    });
                }
                seen.insert(name.clone(), label);
                tiers.insert(name.clone(), tier);
            }
            Ok(())
        };

        insert(
            &file.tiers.supported.commands,
            SupportTier::Supported,
            "supported",
            &mut tiers,
            &mut seen,
        )?;
        insert(
            &file.tiers.partially_supported.commands,
            SupportTier::PartiallySupported,
            "partially_supported",
            &mut tiers,
            &mut seen,
        )?;
        insert(
            &file.tiers.unsupported.commands,
            SupportTier::Unsupported,
            "unsupported",
            &mut tiers,
            &mut seen,
        )?;
        insert(
            &file.tiers.denied.commands,
            SupportTier::Denied,
            "denied",
            &mut tiers,
            &mut seen,
        )?;

        let denied_reason_code =
            parse_reason_code(&file.tiers.denied.reason_code).ok_or_else(|| {
                SupportTierLoadError::UnknownDeniedReasonCode {
                    path: path_str.to_string(),
                    reason_code: file.tiers.denied.reason_code.clone(),
                }
            })?;

        Ok(SupportTierTable {
            tiers,
            divergences: file.tiers.partially_supported.divergences,
            denied_reason_code,
        })
    }

    /// Resolves a command name. Absent from every tier list resolves to
    /// `Unsupported` by default, matching `supported_commands.toml`'s own
    /// documented convention ("any command name not present... resolves
    /// to unsupported by default") — §19's closed-world assumption is
    /// about the *supported* set being closed, not about requiring every
    /// possible command name to be enumerated as unsupported explicitly.
    pub fn resolve(&self, command_name: &str) -> SupportTier {
        self.tiers
            .get(command_name)
            .copied()
            .unwrap_or(SupportTier::Unsupported)
    }

    /// The reason code for a `Denied`-tier command (always
    /// `DenyShellInvocation` for the MVP list, but read from the file
    /// rather than hardcoded so the file stays the single source of
    /// truth).
    pub fn denied_reason_code(&self) -> ReasonCode {
        self.denied_reason_code
    }

    /// The documented semantic divergence for a `PartiallySupported`
    /// command, if any (§19.1: "must never silently pretend to be
    /// complete").
    pub fn divergence(&self, command_name: &str) -> Option<&str> {
        self.divergences.get(command_name).map(String::as_str)
    }

    #[cfg(test)]
    fn known_denied_commands(&self) -> std::collections::HashSet<&str> {
        self.tiers
            .iter()
            .filter(|(_, tier)| **tier == SupportTier::Denied)
            .map(|(name, _)| name.as_str())
            .collect()
    }
}

fn parse_reason_code(s: &str) -> Option<ReasonCode> {
    match s {
        "DENY_HOST_PATH_ACCESS" => Some(ReasonCode::DenyHostPathAccess),
        "DENY_SANDBOX_ESCAPE_ATTEMPT" => Some(ReasonCode::DenySandboxEscapeAttempt),
        "DENY_HOST_PROCESS_MANIPULATION" => Some(ReasonCode::DenyHostProcessManipulation),
        "DENY_SANDBOX_WEAKENING" => Some(ReasonCode::DenySandboxWeakening),
        "DENY_REQUIRES_HOST_PRIVILEGE" => Some(ReasonCode::DenyRequiresHostPrivilege),
        "DENY_UNSIMULATABLE" => Some(ReasonCode::DenyUnsimulatable),
        "DENY_NO_RECOVERY_GUARANTEE" => Some(ReasonCode::DenyNoRecoveryGuarantee),
        "DENY_CAPABILITY_UNAVAILABLE" => Some(ReasonCode::DenyCapabilityUnavailable),
        "DENY_SHELL_INVOCATION" => Some(ReasonCode::DenyShellInvocation),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_toml() -> &'static str {
        r#"
schema_version = "1.0"

[tiers.supported]
commands = ["ls", "cd"]

[tiers.partially_supported]
commands = ["ps"]
[tiers.partially_supported.divergences]
ps = "sandbox-local PIDs only"

[tiers.unsupported]
commands = ["awk"]

[tiers.denied]
commands = ["sh", "bash"]
reason_code = "DENY_SHELL_INVOCATION"
"#
    }

    #[test]
    fn resolves_each_tier_correctly() {
        let table = SupportTierTable::parse(sample_toml(), "test").unwrap();
        assert_eq!(table.resolve("ls"), SupportTier::Supported);
        assert_eq!(table.resolve("ps"), SupportTier::PartiallySupported);
        assert_eq!(table.resolve("awk"), SupportTier::Unsupported);
        assert_eq!(table.resolve("sh"), SupportTier::Denied);
    }

    #[test]
    fn unknown_command_defaults_to_unsupported() {
        let table = SupportTierTable::parse(sample_toml(), "test").unwrap();
        assert_eq!(
            table.resolve("totally-made-up-command"),
            SupportTier::Unsupported
        );
    }

    #[test]
    fn divergence_is_available_for_partially_supported_commands() {
        let table = SupportTierTable::parse(sample_toml(), "test").unwrap();
        assert_eq!(table.divergence("ps"), Some("sandbox-local PIDs only"));
        assert_eq!(table.divergence("ls"), None);
    }

    #[test]
    fn denied_reason_code_is_read_from_the_file() {
        let table = SupportTierTable::parse(sample_toml(), "test").unwrap();
        assert_eq!(table.denied_reason_code(), ReasonCode::DenyShellInvocation);
        assert!(table.known_denied_commands().contains("sh"));
        assert!(table.known_denied_commands().contains("bash"));
    }

    #[test]
    fn duplicate_command_across_tiers_fails_to_load() {
        let toml = r#"
schema_version = "1.0"
[tiers.supported]
commands = ["ls"]
[tiers.partially_supported]
commands = ["ls"]
[tiers.unsupported]
commands = []
[tiers.denied]
commands = []
reason_code = "DENY_SHELL_INVOCATION"
"#;
        let result = SupportTierTable::parse(toml, "test");
        assert!(matches!(
            result,
            Err(SupportTierLoadError::DuplicateCommand { .. })
        ));
    }

    #[test]
    fn unknown_denied_reason_code_fails_to_load() {
        let toml = r#"
schema_version = "1.0"
[tiers.supported]
commands = []
[tiers.partially_supported]
commands = []
[tiers.unsupported]
commands = []
[tiers.denied]
commands = ["sh"]
reason_code = "DENY_NONSENSE"
"#;
        let result = SupportTierTable::parse(toml, "test");
        assert!(matches!(
            result,
            Err(SupportTierLoadError::UnknownDeniedReasonCode { .. })
        ));
    }

    #[test]
    fn the_real_policies_supported_commands_toml_loads_and_self_validates() {
        // This is the actual file this project ships — load it for real,
        // the same way the Policy Engine will, rather than only ever
        // testing against inline fixtures that could drift from it.
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/supported_commands.toml");
        let table = SupportTierTable::load(&path)
            .expect("policies/supported_commands.toml must load and self-validate");

        // Spot-check a handful of entries from each tier, matching §19.2.
        assert_eq!(table.resolve("rm"), SupportTier::Supported);
        assert_eq!(table.resolve("ps"), SupportTier::PartiallySupported);
        assert_eq!(table.resolve("git"), SupportTier::Unsupported);
        assert_eq!(table.resolve("bash"), SupportTier::Denied);
        assert_eq!(table.denied_reason_code(), ReasonCode::DenyShellInvocation);
    }
}

//! Risk classification rules (§20.4) — may only ever produce
//! `RequireApproval`, never `Deny` (§20.2: "A rule that denies a
//! supported, containable operation is a defect"). This is where the
//! "must not be denied" corpus lives conceptually: `rm -rf /project`,
//! `rm -rf /`, `chmod -R 777 /`, `chown -R` across a tree, and mock
//! package removal must all resolve to a `RiskLevel`, never a `Deny` —
//! see `tests/policy_engine_tests/must_not_be_denied.rs` for the actual
//! corpus running against the full `PolicyEngine`, not just this module.

use crate::parser::{ParsedCommand, RedirectionKind};
use crate::policy::types::RiskLevel;

/// Top-level **system** directories — §20.4's exact phrase for the
/// CRITICAL-escalation trigger is "the simulated root or a top-level
/// *system* directory," not merely "a top-level directory." `project` is
/// structurally top-level in `simulated-root-image/`'s layout too, but it
/// is the user's own working directory, not OS/environment infrastructure
/// — and it's §44's own canonical example of a HIGH-severity (not
/// CRITICAL) `rm -rf`. An earlier version of this list included `project`
/// and made `rm -rf /project` wrongly CRITICAL; the corpus test this file
/// is required to pass (`tests/policy_engine_tests`'s "must not be
/// denied" corpus, mirrored in `policy::engine`'s tests) is what caught
/// it. Hardcoded against `simulated-root-image/`'s current layout rather
/// than derived from a base-image manifest, because no such manifest
/// exists yet — a real gap worth closing once the base image is populated
/// for real (Build order phase 3's simulated-root-image content, or phase
/// 13's demo seed).
const TOP_LEVEL_SYSTEM_DIRS: &[&str] = &["etc", "home", "var", "tmp", "opt", "usr"];

/// §20.4: "Operations on paths flagged as environment-critical in the base
/// image (`/etc`, simulated package DB)." The package DB path isn't fixed
/// yet either (no `safeshell-pkg` handler exists to define its on-disk
/// location) — `etc` is the one piece of this rule with a real answer
/// today.
const ENVIRONMENT_CRITICAL_DIRS: &[&str] = &["etc"];

/// §20.4's illustrative "toolchain-critical" package set for mock package
/// removal risk escalation. `safeshell-pkg` itself doesn't have a handler
/// yet (Build order phase 1 only implemented the seven commands listed in
/// `handlers/mod.rs`'s module doc), so this list has no real package
/// database to check against — it's a placeholder shape for when one
/// exists, not real data.
const TOOLCHAIN_CRITICAL_PACKAGES: &[&str] = &["core-utils", "bash-compat"];

/// A path argument's structural properties, relative to the reasoning
/// §20.4 needs: is it (conceptually) the sandbox root or a top-level
/// system directory, and is it under an environment-critical directory.
/// Computed from the raw argument string via `SandboxPath`'s own
/// normalization, so "risk classification" and "how a path actually
/// resolves" can't drift apart from using two different parsers.
struct TargetScope {
    is_root_or_top_level: bool,
    is_environment_critical: bool,
}

/// Returns `None` for a raw argument `SandboxPath::parse` rejects (e.g. one
/// containing `..`) rather than guessing at its scope — resolving
/// navigation needs a base cwd this function doesn't have
/// (`SandboxPath::resolve_relative` is the right tool for that, elsewhere).
fn classify_target(raw: &str) -> Option<TargetScope> {
    let path = crate::fs_abstraction::SandboxPath::parse(raw).ok()?;

    if path.is_root() {
        return Some(TargetScope {
            is_root_or_top_level: true,
            is_environment_critical: false,
        });
    }

    let first_component = path.as_str().split('/').next().unwrap_or("");
    let is_top_level =
        path.as_str() == first_component && TOP_LEVEL_SYSTEM_DIRS.contains(&first_component);
    let is_env_critical = ENVIRONMENT_CRITICAL_DIRS.contains(&first_component);

    Some(TargetScope {
        is_root_or_top_level: is_top_level,
        is_environment_critical: is_env_critical,
    })
}

/// Detects a short-flag cluster containing `flag_char` (e.g. `-rf`, `-fr`,
/// `-r` all match `flag_char == 'r'`). Deliberately narrow: only a single
/// leading `-` followed by letters, not `--long-form` flags — matching
/// exactly the `rm -r`/`rm -rf`/`chmod -R`/`chown -R` forms §20.4 names,
/// not attempting to parse every real-world flag spelling those commands
/// accept.
fn has_short_flag(args: &[crate::parser::Arg], flag_char: char) -> bool {
    args.iter().any(|arg| {
        let s = arg.as_str();
        s.len() > 1 && s.starts_with('-') && !s.starts_with("--") && s[1..].contains(flag_char)
    })
}

/// Non-flag arguments, in order. A real handler's argument parsing (once
/// one exists for a given command) may be more precise about which
/// argument is the actual target versus an option value — this is
/// deliberately the simple, conservative approximation risk
/// classification needs, not a full argument grammar per command.
fn non_flag_args(args: &[crate::parser::Arg]) -> impl Iterator<Item = &str> {
    args.iter()
        .map(|a| a.as_str())
        .filter(|s| !s.starts_with('-'))
}

/// `rm FILE...`: the first non-flag argument is already a target.
fn first_non_flag_arg(args: &[crate::parser::Arg]) -> Option<&str> {
    non_flag_args(args).next()
}

/// `chmod MODE FILE...` / `chown OWNER FILE...`: unlike `rm`, the first
/// non-flag argument is the mode/owner spec, not a target — skip it. Real
/// `chmod`/`chown` accept multiple file targets, so this checks all of
/// them for CRITICAL scope rather than just one; a fix for the exact bug
/// that let `chmod -R 777 /` classify as HIGH instead of CRITICAL (an
/// earlier version of this function used `first_non_flag_arg` here too,
/// which picked up `"777"` as "the target" and never looked at `"/"` at
/// all — caught by this project's own "must not be denied" corpus test).
fn mode_or_owner_command_targets(args: &[crate::parser::Arg]) -> impl Iterator<Item = &str> {
    non_flag_args(args).skip(1)
}

/// One risk rule's result: a level plus the human-readable reason that
/// justified it (feeds `PolicyDecision.reasons`, alongside the
/// deterministic reason codes DENY rules use — risk rules don't have
/// enumerated codes of their own per §20, only DENY does).
pub struct RiskFinding {
    pub level: RiskLevel,
    pub reason: String,
}

/// Classifies one parsed command (a single pipeline stage — callers
/// evaluating a pipeline apply this per stage and take the maximum, since
/// §20.4's rules are all about what an individual command does). Returns
/// `None` for commands with no applicable risk rule, i.e. `RiskLevel::Low`
/// by omission — most of the supported command set (`ls`, `cat`, `pwd`,
/// ...) has no risk rule and is Low by default (§10.2's table).
pub fn classify(cmd: &ParsedCommand, divergence: Option<&str>) -> Option<RiskFinding> {
    let mut findings = Vec::new();

    match cmd.name.as_str() {
        "rm" if has_short_flag(&cmd.args, 'r') => {
            if let Some(target) = first_non_flag_arg(&cmd.args) {
                let scope = classify_target(target);
                let critical = scope.as_ref().is_some_and(|s| s.is_root_or_top_level);
                findings.push(RiskFinding {
                    level: if critical {
                        RiskLevel::Critical
                    } else {
                        RiskLevel::High
                    },
                    reason: format!(
                        "recursive deletion of {target}{}",
                        if critical {
                            " — targets the simulated root or a top-level directory"
                        } else {
                            ""
                        }
                    ),
                });
            }
        }
        "chmod" if has_short_flag(&cmd.args, 'R') => {
            let targets: Vec<&str> = mode_or_owner_command_targets(&cmd.args).collect();
            if !targets.is_empty() {
                let critical = targets
                    .iter()
                    .any(|t| classify_target(t).is_some_and(|s| s.is_root_or_top_level));
                findings.push(RiskFinding {
                    level: if critical {
                        RiskLevel::Critical
                    } else {
                        RiskLevel::High
                    },
                    reason: format!(
                        "recursive permission change on {}{}",
                        targets.join(", "),
                        if critical {
                            " — targets the simulated root or a top-level directory"
                        } else {
                            ""
                        }
                    ),
                });
            }
        }
        "chown" if has_short_flag(&cmd.args, 'R') => {
            let targets: Vec<&str> = mode_or_owner_command_targets(&cmd.args).collect();
            if !targets.is_empty() {
                let critical = targets
                    .iter()
                    .any(|t| classify_target(t).is_some_and(|s| s.is_root_or_top_level));
                findings.push(RiskFinding {
                    level: if critical {
                        RiskLevel::Critical
                    } else {
                        RiskLevel::High
                    },
                    reason: format!(
                        "recursive ownership change on {}{}",
                        targets.join(", "),
                        if critical {
                            " — targets the simulated root or a top-level directory"
                        } else {
                            ""
                        }
                    ),
                });
            }
        }
        "mv" => {
            // §20.4: "MEDIUM; HIGH for directory trees." Whether the
            // destination already exists (a real "clobber") is
            // filesystem state the Policy Engine doesn't have — see
            // `escalate_for_scope` below for where the post-simulation
            // diff (§20.5) is meant to sharpen this once Build order
            // phase 6 wires a real diff through.
            findings.push(RiskFinding {
                level: RiskLevel::Medium,
                reason: "mv may overwrite an existing path at the destination".into(),
            });
        }
        "kill" => {
            findings.push(RiskFinding {
                level: RiskLevel::Medium,
                reason: "signals a sandbox-local process".into(),
            });
        }
        "safeshell-pkg" if cmd.args.first().map(|a| a.as_str()) == Some("remove") => {
            let package = cmd.args.get(1).map(|a| a.as_str());
            let toolchain_critical =
                package.is_some_and(|p| TOOLCHAIN_CRITICAL_PACKAGES.contains(&p));
            findings.push(RiskFinding {
                level: if toolchain_critical {
                    RiskLevel::High
                } else {
                    RiskLevel::Medium
                },
                reason: format!(
                    "removes package {}{}",
                    package.unwrap_or("<unspecified>"),
                    if toolchain_critical {
                        " — a dependency of the simulated toolchain"
                    } else {
                        ""
                    }
                ),
            });
        }
        _ => {}
    }

    // Overwrite/truncate via `>` (§20.4), independent of command name —
    // any command's `>` redirection carries this risk. `>>` (append) does
    // not, matching §20.4's specific wording.
    if cmd
        .redirections
        .iter()
        .any(|r| r.kind == RedirectionKind::Truncate)
    {
        findings.push(RiskFinding {
            level: RiskLevel::Medium,
            reason: "truncates or overwrites a file via `>` redirection".into(),
        });
    }

    // Environment-critical path targeting (§20.4), independent of which
    // command it is.
    for arg in &cmd.args {
        if let Some(scope) = classify_target(arg.as_str()) {
            if scope.is_environment_critical {
                findings.push(RiskFinding {
                    level: RiskLevel::High,
                    reason: format!("targets an environment-critical path: {}", arg.as_str()),
                });
                break;
            }
        }
    }

    // Partially-supported divergence (§20.4: "at least MEDIUM, so the
    // user sees the divergence notice before approving").
    if let Some(text) = divergence {
        findings.push(RiskFinding {
            level: RiskLevel::Medium,
            reason: format!("partially supported: {text}"),
        });
    }

    findings.into_iter().max_by_key(|f| f.level)
}

/// §20.5's post-simulation scale thresholds. A `SimulationDiff` type to
/// compute these from doesn't exist yet (Build order phase 6) — this is
/// the pure escalation *policy*, ready to receive a real diff's stats once
/// one exists, and independently testable against synthetic stats now
/// rather than left unwritten until phase 6 arrives.
#[derive(Debug, Clone, Copy, Default)]
pub struct SimulationDiffStats {
    pub files_affected: u64,
    pub directories_affected: u64,
    pub bytes_deleted: u64,
    pub permission_changes: u64,
}

const FILES_AFFECTED_THRESHOLD: u64 = 100;
const DIRECTORIES_AFFECTED_THRESHOLD: u64 = 25;
const BYTES_DELETED_THRESHOLD: u64 = 50 * 1024 * 1024;
const PERMISSION_CHANGES_THRESHOLD: u64 = 100;

/// §20.5: "Escalation can move a transaction from Allow to
/// RequireApproval. It can never move it to Deny, and it can never
/// de-escalate below the pre-simulation classification" — enforced here
/// structurally: this function only ever calls
/// `RiskLevel::escalate_one_level` (which itself only ever goes up) or
/// returns the input unchanged, so there's no code path that could lower
/// the level even by mistake.
pub fn escalate_for_scope(current: RiskLevel, stats: &SimulationDiffStats) -> RiskLevel {
    let exceeds_threshold = stats.files_affected > FILES_AFFECTED_THRESHOLD
        || stats.directories_affected > DIRECTORIES_AFFECTED_THRESHOLD
        || stats.bytes_deleted > BYTES_DELETED_THRESHOLD
        || stats.permission_changes > PERMISSION_CHANGES_THRESHOLD;

    if exceeds_threshold {
        current.escalate_one_level()
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_line;
    use std::collections::HashMap;

    fn parse(line: &str) -> ParsedCommand {
        parse_line(line, &HashMap::new())
            .unwrap()
            .segments
            .into_iter()
            .next()
            .unwrap()
            .0
    }

    #[test]
    fn rm_rf_on_project_is_high_not_critical() {
        let cmd = parse("rm -rf /project");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::High);
    }

    #[test]
    fn rm_rf_on_simulated_root_is_critical() {
        let cmd = parse("rm -rf /");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::Critical);
    }

    #[test]
    fn rm_rf_on_a_top_level_dir_is_critical() {
        let cmd = parse("rm -rf /etc");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::Critical);
    }

    #[test]
    fn rm_without_recursive_flag_has_no_rm_specific_finding() {
        let cmd = parse("rm /project/file.txt");
        // No -r/-rf, no redirection, no env-critical path: Low by
        // omission (None from this function).
        assert!(classify(&cmd, None).is_none());
    }

    #[test]
    fn chmod_r_777_on_root_is_critical() {
        let cmd = parse("chmod -R 777 /");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::Critical);
    }

    #[test]
    fn chmod_r_on_a_project_subdir_is_high() {
        let cmd = parse("chmod -R 755 /project/build");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::High);
    }

    #[test]
    fn chown_r_tree_wide_is_high_or_critical() {
        let cmd = parse("chown -R user:user /project");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::High);
    }

    #[test]
    fn overwrite_redirection_is_medium() {
        let cmd = parse("echo hi > /project/out.txt");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::Medium);
    }

    #[test]
    fn append_redirection_has_no_overwrite_finding() {
        let cmd = parse("echo hi >> /project/out.txt");
        assert!(classify(&cmd, None).is_none());
    }

    #[test]
    fn environment_critical_path_is_high() {
        let cmd = parse("cat /etc/passwd");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::High);
    }

    #[test]
    fn partially_supported_divergence_is_at_least_medium() {
        let cmd = parse("ps");
        let finding = classify(&cmd, Some("sandbox-local PIDs only")).unwrap();
        assert_eq!(finding.level, RiskLevel::Medium);
    }

    #[test]
    fn mock_package_removal_of_toolchain_dependency_is_high() {
        let cmd = parse("safeshell-pkg remove core-utils");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::High);
    }

    #[test]
    fn mock_package_removal_of_ordinary_package_is_medium() {
        let cmd = parse("safeshell-pkg remove some-random-package");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::Medium);
    }

    #[test]
    fn multiple_findings_take_the_maximum() {
        // Recursive delete of root (Critical) plus, hypothetically, other
        // findings — Critical must win regardless of ordering.
        let cmd = parse("rm -rf /etc");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::Critical);
    }

    #[test]
    fn escalate_for_scope_bumps_one_level_over_threshold() {
        let stats = SimulationDiffStats {
            files_affected: 150,
            ..Default::default()
        };
        assert_eq!(
            escalate_for_scope(RiskLevel::Medium, &stats),
            RiskLevel::High
        );
    }

    #[test]
    fn escalate_for_scope_never_escalates_below_threshold() {
        let stats = SimulationDiffStats {
            files_affected: 10,
            ..Default::default()
        };
        assert_eq!(
            escalate_for_scope(RiskLevel::Medium, &stats),
            RiskLevel::Medium
        );
    }

    #[test]
    fn escalate_for_scope_saturates_at_critical() {
        let stats = SimulationDiffStats {
            bytes_deleted: 100 * 1024 * 1024,
            ..Default::default()
        };
        assert_eq!(
            escalate_for_scope(RiskLevel::Critical, &stats),
            RiskLevel::Critical
        );
    }

    #[test]
    fn escalate_for_scope_each_threshold_triggers_independently() {
        assert_eq!(
            escalate_for_scope(
                RiskLevel::Low,
                &SimulationDiffStats {
                    directories_affected: 26,
                    ..Default::default()
                }
            ),
            RiskLevel::Medium
        );
        assert_eq!(
            escalate_for_scope(
                RiskLevel::Low,
                &SimulationDiffStats {
                    permission_changes: 101,
                    ..Default::default()
                }
            ),
            RiskLevel::Medium
        );
    }
}

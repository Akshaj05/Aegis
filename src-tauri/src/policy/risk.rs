// Risk classification rules: assigns a RiskLevel and reason to a parsed
// command (never a Deny) and escalates risk based on post-simulation diff
// scale.

use crate::parser::{ParsedCommand, RedirectionKind};
use crate::policy::types::RiskLevel;

const TOP_LEVEL_SYSTEM_DIRS: &[&str] = &["etc", "home", "var", "tmp", "opt", "usr"];

const ENVIRONMENT_CRITICAL_DIRS: &[&str] = &["etc"];

const TOOLCHAIN_CRITICAL_PACKAGES: &[&str] = &["core-utils", "bash-compat", "safeshell-toolchain"];

struct TargetScope {
    is_root_or_top_level: bool,
    is_environment_critical: bool,
}

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

fn has_short_flag(args: &[crate::parser::Arg], flag_char: char) -> bool {
    args.iter().any(|arg| {
        let s = arg.as_str();
        s.len() > 1 && s.starts_with('-') && !s.starts_with("--") && s[1..].contains(flag_char)
    })
}

fn non_flag_args(args: &[crate::parser::Arg]) -> impl Iterator<Item = &str> {
    args.iter()
        .map(|a| a.as_str())
        .filter(|s| !s.starts_with('-'))
}

fn first_non_flag_arg(args: &[crate::parser::Arg]) -> Option<&str> {
    non_flag_args(args).next()
}

fn mode_or_owner_command_targets(args: &[crate::parser::Arg]) -> impl Iterator<Item = &str> {
    non_flag_args(args).skip(1)
}

fn chmod_mode_is_world_writable(mode: &str) -> bool {
    if !mode.is_empty() && mode.chars().all(|c| c.is_ascii_digit()) {
        return mode
            .chars()
            .next_back()
            .and_then(|c| c.to_digit(8))
            .is_some_and(|other| other & 0b010 != 0);
    }
    ["o+w", "a+w", "ugo+w", "+w"]
        .iter()
        .any(|pattern| mode.contains(pattern))
}

pub struct RiskFinding {
    pub level: RiskLevel,
    pub reason: String,
}

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

        "chmod" if !has_short_flag(&cmd.args, 'R') => {
            let targets: Vec<&str> = mode_or_owner_command_targets(&cmd.args).collect();
            if let (Some(mode), false) = (non_flag_args(&cmd.args).next(), targets.is_empty()) {
                if chmod_mode_is_world_writable(mode) {
                    let critical_target = targets
                        .iter()
                        .any(|t| classify_target(t).is_some_and(|s| s.is_root_or_top_level));
                    findings.push(RiskFinding {
                        level: if critical_target {
                            RiskLevel::High
                        } else {
                            RiskLevel::Medium
                        },
                        reason: format!(
                            "makes {} world-writable ({mode}){}",
                            targets.join(", "),
                            if critical_target {
                                " — targets the simulated root or a top-level directory"
                            } else {
                                ""
                            }
                        ),
                    });
                }
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

        "truncate" => {
            let targets: Vec<&str> = non_flag_args(&cmd.args).collect();
            if !targets.is_empty() {
                findings.push(RiskFinding {
                    level: RiskLevel::Medium,
                    reason: format!(
                        "truncates {} — may discard file content",
                        targets.join(", ")
                    ),
                });
            }
        }

        "shred" => {
            let targets: Vec<&str> = non_flag_args(&cmd.args).collect();
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
                        "irrecoverably destroys the content of {}{}",
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

    if let Some(text) = divergence {
        findings.push(RiskFinding {
            level: RiskLevel::Medium,
            reason: format!("partially supported: {text}"),
        });
    }

    findings.into_iter().max_by_key(|f| f.level)
}

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
    fn mock_package_removal_of_the_real_seeded_essential_package_is_high() {

        let cmd = parse("safeshell-pkg remove safeshell-toolchain");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::High);
    }

    #[test]
    fn chmod_777_on_a_single_file_is_medium_not_low() {
        let cmd = parse("chmod 777 secret.txt");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::Medium);
    }

    #[test]
    fn chmod_777_on_a_top_level_dir_without_recursion_is_high() {
        let cmd = parse("chmod 777 /etc");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::High);
    }

    #[test]
    fn chmod_symbolic_world_write_is_flagged_the_same_as_octal() {
        let cmd = parse("chmod o+w secret.txt");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::Medium);
    }

    #[test]
    fn chmod_644_is_not_flagged_at_all() {
        let cmd = parse("chmod 644 ordinary.txt");
        assert!(classify(&cmd, None).is_none());
    }

    #[test]
    fn chmod_recursive_777_still_uses_the_recursive_rule_not_the_new_one() {

        let cmd = parse("chmod -R 777 /project");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::High);
        assert!(finding.reason.contains("recursive"));
    }

    #[test]
    fn truncate_a_file_is_medium() {
        let cmd = parse("truncate -s 0 important.log");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::Medium);
    }

    #[test]
    fn shred_an_ordinary_file_is_high() {
        let cmd = parse("shred secret.txt");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::High);
    }

    #[test]
    fn shred_a_top_level_dir_is_critical() {
        let cmd = parse("shred /etc");
        let finding = classify(&cmd, None).unwrap();
        assert_eq!(finding.level, RiskLevel::Critical);
    }

    #[test]
    fn multiple_findings_take_the_maximum() {

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

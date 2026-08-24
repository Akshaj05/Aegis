// Containment-boundary rules: the only source of policy Deny verdicts,
// covering sensitive pseudo-path detection and sandbox capability gating.

use crate::parser::ParsedCommand;
use crate::policy::types::ReasonCode;
use crate::sandbox::backend::CapabilityReport;

const SENSITIVE_PSEUDO_PATH_PREFIXES: &[&str] = &["proc/sys", "proc/sysrq-trigger", "sys"];

fn looks_like_sensitive_pseudo_path(raw: &str) -> bool {
    let trimmed = raw.trim_start_matches('/');
    SENSITIVE_PSEUDO_PATH_PREFIXES
        .iter()
        .any(|prefix| trimmed == *prefix || trimmed.starts_with(&format!("{prefix}/")))
}

pub fn check_sensitive_pseudo_paths(cmd: &ParsedCommand) -> Option<(ReasonCode, String)> {
    let mut stage = Some(cmd);
    while let Some(current) = stage {
        for arg in &current.args {
            if looks_like_sensitive_pseudo_path(arg.as_str()) {
                return Some((
                    ReasonCode::DenyUnsimulatable,
                    format!("{}: refers to a kernel pseudo-filesystem path SafeShell does not simulate effects for", arg.as_str()),
                ));
            }
        }
        for redirection in &current.redirections {
            if looks_like_sensitive_pseudo_path(&redirection.target) {
                return Some((
                    ReasonCode::DenyUnsimulatable,
                    format!("{}: refers to a kernel pseudo-filesystem path SafeShell does not simulate effects for", redirection.target),
                ));
            }
        }
        stage = current.pipeline_next.as_deref();
    }
    None
}

pub fn check_capability_gate(
    report: &CapabilityReport,
    process_commands: bool,
) -> Option<(ReasonCode, String)> {
    let available = if process_commands {
        report.process_commands_available()
    } else {
        report.execution_available()
    };

    if available {
        return None;
    }

    let reason = if process_commands && report.execution_available() {
        format!(
            "process-representation commands require a working PID namespace: {}",
            report.pid_namespaces
        )
    } else {
        "required sandbox capabilities are unavailable in this session — see the capability report"
            .to_string()
    };
    Some((ReasonCode::DenyCapabilityUnavailable, reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse_line, Redirection, RedirectionKind};
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
    fn detects_sensitive_path_in_a_plain_argument() {
        let cmd = parse("cat /proc/sys/kernel/whatever");
        let result = check_sensitive_pseudo_paths(&cmd);
        assert!(matches!(result, Some((ReasonCode::DenyUnsimulatable, _))));
    }

    #[test]
    fn detects_sensitive_path_in_a_redirection_target() {
        let mut cmd = parse("echo 1");
        cmd.redirections.push(Redirection {
            kind: RedirectionKind::Truncate,
            target: "/proc/sysrq-trigger".into(),
        });
        let result = check_sensitive_pseudo_paths(&cmd);
        assert!(matches!(result, Some((ReasonCode::DenyUnsimulatable, _))));
    }

    #[test]
    fn detects_sensitive_path_in_a_later_pipeline_stage() {
        let cmd = parse("cat foo | tee /sys/class/whatever");
        let result = check_sensitive_pseudo_paths(&cmd);
        assert!(matches!(result, Some((ReasonCode::DenyUnsimulatable, _))));
    }

    #[test]
    fn does_not_flag_ordinary_paths() {
        let cmd = parse("cat /project/README");
        assert_eq!(check_sensitive_pseudo_paths(&cmd), None);
    }

    #[test]
    fn does_not_flag_a_substring_coincidence() {

        let cmd = parse("cat sysadmin-notes.txt");
        assert_eq!(check_sensitive_pseudo_paths(&cmd), None);
    }

    fn report_with(execution_available: bool, pid_namespaces_ok: bool) -> CapabilityReport {
        use crate::sandbox::backend::PrimitiveStatus;
        let ok_or_unavailable = |ok: bool| {
            if ok {
                PrimitiveStatus::Ok
            } else {
                PrimitiveStatus::Unavailable {
                    reason: "test".into(),
                }
            }
        };
        CapabilityReport {
            user_namespaces: ok_or_unavailable(execution_available),
            mount_namespaces: ok_or_unavailable(execution_available),
            pid_namespaces: ok_or_unavailable(pid_namespaces_ok),
            seccomp: ok_or_unavailable(execution_available),
            cgroups_v2: ok_or_unavailable(execution_available),
            landlock: PrimitiveStatus::Ok,
            overlayfs: PrimitiveStatus::Ok,
            openat2: PrimitiveStatus::Ok,
            degradations: vec![],
        }
    }

    #[test]
    fn capability_gate_allows_filesystem_ops_without_pid_namespace() {
        let report = report_with(true, false);
        assert_eq!(check_capability_gate(&report, false), None);
    }

    #[test]
    fn capability_gate_denies_process_commands_without_pid_namespace() {
        let report = report_with(true, false);
        let result = check_capability_gate(&report, true);
        assert!(matches!(
            result,
            Some((ReasonCode::DenyCapabilityUnavailable, _))
        ));
    }

    #[test]
    fn capability_gate_denies_everything_when_execution_is_unavailable() {
        let report = report_with(false, false);
        assert!(check_capability_gate(&report, false).is_some());
        assert!(check_capability_gate(&report, true).is_some());
    }

    #[test]
    fn capability_gate_matches_this_machines_real_preflight_report() {

        use crate::sandbox::preflight::PreflightCapabilityChecker;
        let report = PreflightCapabilityChecker::new().run();
        let result = check_capability_gate(&report, false);
        if report.execution_available() {
            assert_eq!(result, None);
        } else {
            assert!(result.is_some());
        }
    }
}

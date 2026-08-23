//! Containment-boundary rules — the only source of `Deny` (§20.3, §4.2).
//!
//! **Honest scope note.** §20.3 lists nine reason codes as exhaustive for
//! the MVU. This module gives three of them a real, precisely-specified
//! trigger from a *parsed command alone* (before simulation):
//! `DenyShellInvocation` (command-name denylist, §19.2), `DenyUnsimulatable`
//! (a concrete sensitive-pseudo-path list — see below), and
//! `DenyCapabilityUnavailable` (§15's real `CapabilityReport`, wired for
//! real to `sandbox/`'s Preflight Capability Checker).
//!
//! The remaining six (`DenyHostPathAccess`, `DenySandboxEscapeAttempt`,
//! `DenyHostProcessManipulation`, `DenySandboxWeakening`,
//! `DenyRequiresHostPrivilege`, `DenyNoRecoveryGuarantee`) are defined in
//! full in `policy::types` — the enum is exhaustive, per §20.3's own
//! requirement — but this pass does **not** invent a heuristic trigger for
//! them, for a specific reason worth stating rather than leaving as a
//! silent gap: MVP's command grammar and structural protections mean none
//! of them currently has a legitimate, well-specified pre-simulation
//! detection rule.
//!
//! - `DenyHostPathAccess` / `DenySandboxEscapeAttempt`: `SandboxPath`
//!   already makes true escape structurally impossible before a path ever
//!   reaches this layer (`resolve_relative` clamps `..` at the root rather
//!   than erroring — see `fs_abstraction`). A user typing `cd
//!   ../../../../etc` lands at `/etc` *inside* the sandbox, harmlessly;
//!   there is no path string this grammar can construct that resolves
//!   outside the sandbox root even before Landlock or `RESOLVE_BENEATH`
//!   get involved. The real enforcement of these two codes is structural
//!   (mount namespace + `pivot_root`, `openat2`/`RESOLVE_BENEATH` in
//!   `sandbox/worker/resolver.rs`) and the worker-level `Deny`
//!   surfaces through this same enum when Build order phase 6 wires the
//!   worker into the transaction pipeline — inventing a *second*,
//!   independent syntactic detector here, that could disagree with the
//!   structural one, would be worse than not having one.
//! - `DenyHostProcessManipulation`: whether a `kill` target is a real
//!   sandbox-local PID is live process-table state the Policy Engine
//!   (which sees only the parsed command, per §20's stated inputs) does
//!   not have. The executor, which has PID-namespace visibility, is where
//!   this genuinely gets checked.
//! - `DenySandboxWeakening` / `DenyRequiresHostPrivilege`: no command in
//!   the MVP grammar (§19.2) can reconfigure the sandbox or request a host
//!   privilege at all — there is no `mount`, no `sudo`, no capability-
//!   granting operation to check *against*. A rule with nothing that can
//!   ever match it isn't a rule, it's dead code with a false sense of
//!   coverage.
//! - `DenyNoRecoveryGuarantee`: §23.6 states this directly — "Not
//!   reversible by snapshot | None in the MVP command set."
//!
//! Every one of these six stays fully defined and ready; extending this
//! module when a future command genuinely needs one is adding a rule, not
//! redesigning the enum.

use crate::parser::ParsedCommand;
use crate::policy::types::ReasonCode;
use crate::sandbox::backend::CapabilityReport;

/// §20.3: paths whose *effect* is defined by the kernel outside the
/// simulated filesystem's semantics, even confined to the sandbox's own
/// namespace — writing to a sandbox-local `/proc/sys` entry can still
/// affect kernel state that isn't properly namespaced (a known, general
/// Linux property, not specific to SafeShell). Denied unconditionally as
/// defense in depth, per docs/CLAUDE.md's tie-break rule ("stricter
/// enforcement at the boundary") rather than reasoned about case by case.
const SENSITIVE_PSEUDO_PATH_PREFIXES: &[&str] = &["proc/sys", "proc/sysrq-trigger", "sys"];

fn looks_like_sensitive_pseudo_path(raw: &str) -> bool {
    let trimmed = raw.trim_start_matches('/');
    SENSITIVE_PSEUDO_PATH_PREFIXES
        .iter()
        .any(|prefix| trimmed == *prefix || trimmed.starts_with(&format!("{prefix}/")))
}

/// Checks one pipeline (following `pipeline_next`) for a sensitive
/// pseudo-path in any argument or redirection target, at any stage.
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

/// §15.2/§20.1 step 3: a required capability missing for this operation's
/// execution mode. `process_commands` should be `true` when the command
/// is process-affecting (`ps`, `kill`, mock service operations) — those
/// need `CapabilityReport::process_commands_available()`, everything else
/// needs only `execution_available()` (§15.2's PID-namespace row: "Filesystem-only
/// operation may continue" without it).
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
        // "sysadmin" starts with "sys" as a string, but not as a path
        // component — must not false-positive on this.
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
        // The actual, currently-true state of this dev environment (see
        // sandbox/syscalls.rs's "Honesty note"): cgroups_v2 unavailable,
        // so execution_available() is false here, so the capability gate
        // must deny everything — a real, not synthetic, check.
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

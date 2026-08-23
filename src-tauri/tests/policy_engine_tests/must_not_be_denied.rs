//! The "must not be denied" and "must always be denied" corpora,
//! docs/CLAUDE.md's Testing table for `tests/policy_engine_tests/`. Runs
//! against the *real* `PolicyEngine` loading the *real*
//! `policies/supported_commands.toml`, as an external integration test
//! (linking `safeshell` as a library) rather than only as inline unit
//! tests inside `src/policy/engine.rs` — this is genuinely the location
//! docs/CLAUDE.md names for this corpus, so it lives here for real rather
//! than only being described as living here.
//!
//! Uses a synthetic, fully-`Ok` `CapabilityReport` rather than the real
//! `PreflightCapabilityChecker`'s output: this corpus is about the
//! Policy Engine's own rule logic and must pass identically on every
//! machine, not about this specific development environment's sandbox
//! capabilities (which `sandbox::preflight`'s own tests already cover —
//! see `src/policy/containment.rs`'s
//! `capability_gate_matches_this_machines_real_preflight_report` for
//! where the *real*, environment-dependent report is exercised).

use std::collections::HashMap;
use std::path::Path;

use safeshell::parser::{parse_line, ParsedCommand};
use safeshell::policy::{PolicyEngine, ReasonCode, Verdict};
use safeshell::sandbox::backend::{CapabilityReport, PrimitiveStatus};

fn engine() -> PolicyEngine {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/supported_commands.toml");
    PolicyEngine::load(&path).expect("policies/supported_commands.toml must load")
}

fn full_capability_report() -> CapabilityReport {
    CapabilityReport {
        user_namespaces: PrimitiveStatus::Ok,
        mount_namespaces: PrimitiveStatus::Ok,
        pid_namespaces: PrimitiveStatus::Ok,
        seccomp: PrimitiveStatus::Ok,
        cgroups_v2: PrimitiveStatus::Ok,
        landlock: PrimitiveStatus::Ok,
        overlayfs: PrimitiveStatus::Ok,
        openat2: PrimitiveStatus::Ok,
        degradations: vec![],
    }
}

fn parse(line: &str) -> ParsedCommand {
    parse_line(line, &HashMap::new())
        .unwrap()
        .segments
        .into_iter()
        .next()
        .unwrap()
        .0
}

// --- "Must not be denied": docs/CLAUDE.md names these five exact
// scenarios. Every one is dangerous and must resolve to RequireApproval,
// never Deny — denying any of them is, per docs/architecture.md §20.2, "a
// defect [in the rule set], not a safety feature." ---

#[test]
fn rm_rf_project_is_not_denied() {
    let decision = engine().evaluate(&parse("rm -rf /project"), &full_capability_report());
    assert_eq!(
        decision.verdict,
        Verdict::RequireApproval,
        "rm -rf /project must require approval, not be denied"
    );
}

#[test]
fn rm_rf_simulated_root_is_not_denied() {
    let decision = engine().evaluate(&parse("rm -rf /"), &full_capability_report());
    assert_eq!(
        decision.verdict,
        Verdict::RequireApproval,
        "rm -rf / (simulated root) must require approval, not be denied"
    );
}

#[test]
fn chmod_r_777_root_is_not_denied() {
    let decision = engine().evaluate(&parse("chmod -R 777 /"), &full_capability_report());
    assert_eq!(
        decision.verdict,
        Verdict::RequireApproval,
        "chmod -R 777 / must require approval, not be denied"
    );
}

#[test]
fn chown_r_tree_wide_is_not_denied() {
    let decision = engine().evaluate(
        &parse("chown -R user:user /project"),
        &full_capability_report(),
    );
    assert_eq!(
        decision.verdict,
        Verdict::RequireApproval,
        "chown -R across a tree must require approval, not be denied"
    );
}

#[test]
fn mock_package_removal_breaking_toolchain_is_not_denied() {
    let decision = engine().evaluate(
        &parse("safeshell-pkg remove core-utils"),
        &full_capability_report(),
    );
    assert_eq!(decision.verdict, Verdict::RequireApproval, "mock package removal breaking the simulated toolchain must require approval, not be denied");
}

// --- "Must always be denied": the boundary corpus. Every one of these
// must resolve to Deny with the specific reason code named, and a DENY
// must never be overridable — there is no argument to these functions
// that produces anything but Deny. ---

#[test]
fn shell_invocation_is_always_denied() {
    for shell in ["sh", "bash", "zsh", "dash", "ksh"] {
        let decision = engine().evaluate(&parse(shell), &full_capability_report());
        assert_eq!(
            decision.verdict,
            Verdict::Deny,
            "{shell} must always be denied"
        );
        assert_eq!(decision.reason_codes, vec![ReasonCode::DenyShellInvocation]);
    }
}

#[test]
fn sensitive_pseudo_path_access_is_always_denied() {
    for line in [
        "cat /proc/sys/kernel/whatever",
        "echo 1 > /proc/sysrq-trigger",
        "cat /sys/class/whatever",
    ] {
        let decision = engine().evaluate(&parse(line), &full_capability_report());
        assert_eq!(
            decision.verdict,
            Verdict::Deny,
            "{line:?} must always be denied"
        );
        assert_eq!(decision.reason_codes, vec![ReasonCode::DenyUnsimulatable]);
    }
}

#[test]
fn missing_required_capability_is_always_denied() {
    let mut report = full_capability_report();
    report.user_namespaces = PrimitiveStatus::Unavailable {
        reason: "test".into(),
    };
    let decision = engine().evaluate(&parse("ls"), &report);
    assert_eq!(decision.verdict, Verdict::Deny);
    assert_eq!(
        decision.reason_codes,
        vec![ReasonCode::DenyCapabilityUnavailable]
    );
}

#[test]
fn a_deny_verdict_carries_no_risk_level() {
    // §20.3 vs §20.4: Deny is a containment-boundary matter, never a risk
    // judgment — this is a type-shape invariant every Deny in the corpus
    // above should already satisfy; asserted once, explicitly, here.
    let decision = engine().evaluate(&parse("bash"), &full_capability_report());
    assert_eq!(decision.risk_level, None);
}

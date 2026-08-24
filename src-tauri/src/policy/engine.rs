// PolicyEngine: orchestrates the deterministic evaluation order over
// support tiers, containment rules, and risk classification to produce a
// PolicyDecision for a parsed command or pipeline.

use std::path::Path;

use crate::parser::ParsedCommand;
use crate::policy::containment;
use crate::policy::risk::{self, SimulationDiffStats};
use crate::policy::support_tiers::{SupportTierLoadError, SupportTierTable};
use crate::policy::types::{Category, PolicyDecision, ReasonCode, RiskLevel, SupportTier, Verdict};
use crate::sandbox::backend::CapabilityReport;

fn is_process_affecting(command_name: &str) -> bool {
    matches!(command_name, "ps" | "kill")
}

pub struct PolicyEngine {
    support_tiers: SupportTierTable,
}

impl PolicyEngine {
    pub fn load(support_tiers_path: &Path) -> Result<Self, SupportTierLoadError> {
        Ok(PolicyEngine {
            support_tiers: SupportTierTable::load(support_tiers_path)?,
        })
    }

    #[cfg(test)]
    fn from_table(support_tiers: SupportTierTable) -> Self {
        PolicyEngine { support_tiers }
    }

    pub fn evaluate(
        &self,
        cmd: &ParsedCommand,
        capability_report: &CapabilityReport,
    ) -> PolicyDecision {
        let tier = self.support_tiers.resolve(&cmd.name);

        if tier == SupportTier::Unsupported {
            return PolicyDecision {
                support_tier: tier,
                verdict: Verdict::RejectUnsupported,
                category: None,
                risk_level: None,
                reason_codes: vec![],
                reasons: vec![format!(
                    "`{}` is recognized but not implemented in SafeShell (tier: unsupported)",
                    cmd.name
                )],
            };
        }

        if tier == SupportTier::Denied {
            let code = self.support_tiers.denied_reason_code();
            return deny(tier, code, code.canonical_text().to_string());
        }

        if let Some((code, reason)) = containment::check_sensitive_pseudo_paths(cmd) {
            return deny(tier, code, reason);
        }

        let process_commands = is_process_affecting(&cmd.name);
        if let Some((code, reason)) =
            containment::check_capability_gate(capability_report, process_commands)
        {
            return deny(tier, code, reason);
        }

        let divergence = self.support_tiers.divergence(&cmd.name);
        let finding = risk::classify(cmd, divergence);
        let risk_level = finding.as_ref().map(|f| f.level).unwrap_or(RiskLevel::Low);
        let reasons = finding.map(|f| vec![f.reason]).unwrap_or_default();

        allow_or_require_approval(tier, risk_level, reasons)
    }

    pub fn evaluate_pipeline(
        &self,
        cmd: &ParsedCommand,
        capability_report: &CapabilityReport,
    ) -> PolicyDecision {
        let mut stage = Some(cmd);
        let mut worst: Option<PolicyDecision> = None;

        while let Some(current) = stage {
            let decision = self.evaluate(current, capability_report);
            if decision.verdict == Verdict::Deny || decision.verdict == Verdict::RejectUnsupported {
                return decision;
            }
            worst = Some(match worst {
                None => decision,
                Some(prev) if decision.risk_level > prev.risk_level => decision,
                Some(prev) => prev,
            });
            stage = current.pipeline_next.as_deref();
        }

        worst.expect("a ParsedCommand always has at least one stage")
    }
}

fn deny(tier: SupportTier, code: ReasonCode, reason: String) -> PolicyDecision {
    PolicyDecision {
        support_tier: tier,
        verdict: Verdict::Deny,
        category: Some(Category::UnsafeToContain),
        risk_level: None,
        reason_codes: vec![code],
        reasons: vec![reason],
    }
}

fn allow_or_require_approval(
    tier: SupportTier,
    risk_level: RiskLevel,
    reasons: Vec<String>,
) -> PolicyDecision {

    let (verdict, category) = if risk_level == RiskLevel::Low {
        (Verdict::Allow, Category::Safe)
    } else {
        (Verdict::RequireApproval, Category::DangerousContainable)
    };

    PolicyDecision {
        support_tier: tier,
        verdict,
        category: Some(category),
        risk_level: Some(risk_level),
        reason_codes: vec![],
        reasons,
    }
}

pub fn apply_post_simulation_escalation(
    decision: PolicyDecision,
    stats: &SimulationDiffStats,
) -> PolicyDecision {
    let Some(current_risk) = decision.risk_level else {
        return decision;
    };
    if decision.verdict == Verdict::Deny || decision.verdict == Verdict::RejectUnsupported {
        return decision;
    }

    let escalated = risk::escalate_for_scope(current_risk, stats);
    if escalated == current_risk {
        return decision;
    }

    let (verdict, category) = if escalated == RiskLevel::Low {
        (Verdict::Allow, Category::Safe)
    } else {
        (Verdict::RequireApproval, Category::DangerousContainable)
    };

    PolicyDecision {
        risk_level: Some(escalated),
        verdict,
        category: Some(category),
        ..decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_line;
    use crate::sandbox::backend::PrimitiveStatus;
    use std::collections::HashMap;

    fn engine() -> PolicyEngine {
        let toml = r#"
schema_version = "1.0"
[tiers.supported]
commands = ["ls", "cd", "rm", "chmod", "chown", "mv", "cat", "echo"]
[tiers.partially_supported]
commands = ["ps", "safeshell-pkg"]
[tiers.partially_supported.divergences]
ps = "sandbox-local PIDs only"
[tiers.unsupported]
commands = ["awk"]
[tiers.denied]
commands = ["sh", "bash"]
reason_code = "DENY_SHELL_INVOCATION"
"#;
        PolicyEngine::from_table(SupportTierTable::parse(toml, "test").unwrap())
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

    #[test]
    fn must_not_be_denied_rm_rf_project() {
        let decision = engine().evaluate(&parse("rm -rf /project"), &full_capability_report());
        assert_eq!(decision.verdict, Verdict::RequireApproval);
        assert_eq!(decision.risk_level, Some(RiskLevel::High));
    }

    #[test]
    fn must_not_be_denied_rm_rf_simulated_root() {
        let decision = engine().evaluate(&parse("rm -rf /"), &full_capability_report());
        assert_eq!(decision.verdict, Verdict::RequireApproval);
        assert_eq!(decision.risk_level, Some(RiskLevel::Critical));
    }

    #[test]
    fn must_not_be_denied_chmod_r_777_root() {
        let decision = engine().evaluate(&parse("chmod -R 777 /"), &full_capability_report());
        assert_eq!(decision.verdict, Verdict::RequireApproval);
        assert_eq!(decision.risk_level, Some(RiskLevel::Critical));
    }

    #[test]
    fn must_not_be_denied_chown_r_tree_wide() {
        let decision = engine().evaluate(
            &parse("chown -R user:user /project"),
            &full_capability_report(),
        );
        assert_eq!(decision.verdict, Verdict::RequireApproval);
    }

    #[test]
    fn must_not_be_denied_mock_package_removal_breaking_toolchain() {
        let decision = engine().evaluate(
            &parse("safeshell-pkg remove core-utils"),
            &full_capability_report(),
        );
        assert_eq!(decision.verdict, Verdict::RequireApproval);
        assert_eq!(decision.risk_level, Some(RiskLevel::High));
    }

    #[test]
    fn must_always_be_denied_shell_invocation() {
        let decision = engine().evaluate(&parse("bash"), &full_capability_report());
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.reason_codes, vec![ReasonCode::DenyShellInvocation]);
    }

    #[test]
    fn must_always_be_denied_sensitive_pseudo_path() {
        let decision = engine().evaluate(
            &parse("cat /proc/sys/kernel/whatever"),
            &full_capability_report(),
        );
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.reason_codes, vec![ReasonCode::DenyUnsimulatable]);
    }

    #[test]
    fn must_always_be_denied_when_required_capability_unavailable() {
        let mut report = full_capability_report();
        report.cgroups_v2 = PrimitiveStatus::Unavailable {
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
    fn unsupported_command_rejects_without_deny() {
        let decision = engine().evaluate(&parse("awk '{print}'"), &full_capability_report());
        assert_eq!(decision.verdict, Verdict::RejectUnsupported);
        assert_eq!(decision.category, None);
        assert_eq!(decision.risk_level, None);
        assert!(
            decision.reason_codes.is_empty(),
            "RejectUnsupported is not a security denial and must carry no DENY reason codes"
        );
    }

    #[test]
    fn low_risk_supported_command_is_allow_with_no_approval_pause() {
        let decision = engine().evaluate(&parse("ls /project"), &full_capability_report());
        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(decision.category, Some(Category::Safe));
        assert_eq!(decision.risk_level, Some(RiskLevel::Low));
        assert!(!decision.requires_approval());
    }

    #[test]
    fn deny_never_carries_a_risk_level() {
        let decision = engine().evaluate(&parse("bash"), &full_capability_report());
        assert_eq!(
            decision.risk_level, None,
            "Deny is a containment-boundary matter, not a risk judgment (§20.3 vs §20.4)"
        );
    }

    #[test]
    fn partially_supported_divergence_forces_at_least_medium() {
        let decision = engine().evaluate(&parse("ps"), &full_capability_report());
        assert_eq!(decision.verdict, Verdict::RequireApproval);
        assert_eq!(decision.risk_level, Some(RiskLevel::Medium));
    }

    #[test]
    fn pipeline_takes_the_most_severe_stage() {
        let decision = engine().evaluate_pipeline(
            &parse("cat /project/f | echo hi > /project/out.txt"),
            &full_capability_report(),
        );
        assert_eq!(decision.verdict, Verdict::RequireApproval);
        assert_eq!(decision.risk_level, Some(RiskLevel::Medium));
    }

    #[test]
    fn pipeline_denies_if_any_stage_denies() {
        let decision =
            engine().evaluate_pipeline(&parse("cat /project/f | bash"), &full_capability_report());
        assert_eq!(decision.verdict, Verdict::Deny);
    }

    #[test]
    fn pipeline_of_all_low_risk_commands_is_allow() {
        let decision =
            engine().evaluate_pipeline(&parse("cat /project/f"), &full_capability_report());
        assert_eq!(decision.verdict, Verdict::Allow);
    }

    #[test]
    fn post_simulation_escalation_upgrades_verdict_when_it_crosses_out_of_low() {
        let decision = engine().evaluate(&parse("ls /project"), &full_capability_report());
        assert_eq!(decision.verdict, Verdict::Allow);

        let stats = SimulationDiffStats {
            files_affected: 500,
            ..Default::default()
        };
        let escalated = apply_post_simulation_escalation(decision, &stats);
        assert_eq!(escalated.verdict, Verdict::RequireApproval);
        assert_eq!(escalated.risk_level, Some(RiskLevel::Medium));
    }

    #[test]
    fn post_simulation_escalation_never_touches_a_deny() {
        let decision = engine().evaluate(&parse("bash"), &full_capability_report());
        let stats = SimulationDiffStats {
            files_affected: 99999,
            ..Default::default()
        };
        let escalated = apply_post_simulation_escalation(decision, &stats);
        assert_eq!(escalated.verdict, Verdict::Deny);
    }

    #[test]
    fn post_simulation_escalation_never_touches_reject_unsupported() {
        let decision = engine().evaluate(&parse("awk x"), &full_capability_report());
        let stats = SimulationDiffStats {
            files_affected: 99999,
            ..Default::default()
        };
        let escalated = apply_post_simulation_escalation(decision, &stats);
        assert_eq!(escalated.verdict, Verdict::RejectUnsupported);
    }

    #[test]
    fn engine_loads_the_real_shipped_policy_file() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/supported_commands.toml");
        let engine =
            PolicyEngine::load(&path).expect("the real policies/supported_commands.toml must load");
        let decision = engine.evaluate(&parse("rm -rf /project"), &full_capability_report());
        assert_eq!(decision.verdict, Verdict::RequireApproval);
    }
}

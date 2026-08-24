// Detects and records divergence between what the AI plan claims and what
// the deterministic policy/simulation results actually show, for display
// only — never used to change a routing decision.

use std::collections::HashSet;

use crate::ai::schema::AiPlan;
use crate::simulation::diff::SimulationDiff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DivergedField {
    EscapesSandbox,
    AffectedResources,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceFinding {
    pub field: DivergedField,
    pub ai_claimed: String,
    pub ground_truth: String,
}

pub fn detect_escapes_sandbox_divergence(plan: &AiPlan) -> Option<DivergenceFinding> {
    if plan.predicted_effects.escapes_sandbox {
        Some(DivergenceFinding {
            field: DivergedField::EscapesSandbox,
            ai_claimed: "true".to_string(),
            ground_truth: "false".to_string(),
        })
    } else {
        None
    }
}

pub fn detect_affected_resources_divergence(
    plan: &AiPlan,
    diff: &SimulationDiff,
) -> Option<DivergenceFinding> {
    let claimed: HashSet<&str> = plan.affected_resources.iter().map(String::as_str).collect();
    let actual: HashSet<&str> = diff
        .files_created
        .iter()
        .chain(diff.files_modified.iter())
        .chain(diff.directories_created.iter())
        .map(String::as_str)
        .collect();

    if claimed.is_empty() && actual.is_empty() {
        return None;
    }
    if claimed.intersection(&actual).next().is_some() {
        return None;
    }

    Some(DivergenceFinding {
        field: DivergedField::AffectedResources,
        ai_claimed: format!("{:?}", plan.affected_resources),
        ground_truth: format!("{:?}", actual.iter().collect::<Vec<_>>()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::schema::{Intent, PredictedEffects, RecoveryRecommendation, RecoveryStrategy};
    use crate::policy::RiskLevel;

    fn plan_with(escapes_sandbox: bool, affected_resources: &[&str]) -> AiPlan {
        AiPlan {
            schema_version: "1.0".into(),
            command: "mkdir project".into(),
            intent: Intent::DirectoryCreate,
            risk_level: RiskLevel::Low,
            affected_resources: affected_resources.iter().map(|s| s.to_string()).collect(),
            predicted_effects: PredictedEffects {
                files_deleted_estimate: 0,
                directories_deleted_estimate: 0,
                escapes_sandbox,
            },
            preconditions: vec![],
            reversible_within_safeshell: true,
            recovery_recommendation: RecoveryRecommendation {
                strategy: RecoveryStrategy::NoRecoveryNeeded,
                description: String::new(),
            },
            external_side_effects: false,
            confidence: 0.9,
            explanation: String::new(),
        }
    }

    #[test]
    fn no_divergence_when_ai_correctly_claims_containment() {
        let plan = plan_with(false, &["project"]);
        assert!(detect_escapes_sandbox_divergence(&plan).is_none());
    }

    #[test]
    fn divergence_when_ai_claims_a_sandbox_escape_policy_already_ruled_out() {
        let plan = plan_with(true, &["project"]);
        let finding = detect_escapes_sandbox_divergence(&plan).unwrap();
        assert_eq!(finding.field, DivergedField::EscapesSandbox);
    }

    #[test]
    fn no_affected_resources_divergence_on_overlap() {
        let plan = plan_with(false, &["project"]);
        let diff = SimulationDiff {
            directories_created: vec!["project".to_string()],
            ..Default::default()
        };
        assert!(detect_affected_resources_divergence(&plan, &diff).is_none());
    }

    #[test]
    fn no_divergence_when_both_are_empty() {
        let plan = plan_with(false, &[]);
        let diff = SimulationDiff::default();
        assert!(detect_affected_resources_divergence(&plan, &diff).is_none());
    }

    #[test]
    fn divergence_when_ai_and_diff_share_no_paths_at_all() {
        let plan = plan_with(false, &["totally/wrong/path"]);
        let diff = SimulationDiff {
            directories_created: vec!["project".to_string()],
            ..Default::default()
        };
        let finding = detect_affected_resources_divergence(&plan, &diff).unwrap();
        assert_eq!(finding.field, DivergedField::AffectedResources);
    }
}

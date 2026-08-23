//! §21.7's independent cross-checking: "`affected_resources` is
//! independently recomputed by the parser and diff engine... flagged
//! visibly when it diverges" and §21.6's "`escapes_sandbox` is a claim
//! the AI makes and the Rust core independently verifies; a mismatch is
//! logged as an AI-divergence event." Neither check ever changes a
//! routing decision (§28: "AI claims higher risk than policy — never
//! de-escalates anything... divergence recorded... default is to display
//! the divergence to the user without changing routing") — these
//! functions only ever produce a [`DivergenceFinding`] to record and
//! display, never a value anything else branches on.

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

/// Checkable the moment an `AiPlan` is validated, before simulation ever
/// runs: a transaction only reaches the `AI_ANALYSIS` state at all when
/// the Policy Engine's verdict was `Allow` or `RequireApproval` (§13.2:
/// `POLICY_CHECK -> DENIED | AI_ANALYSIS` — a `Deny` verdict exits
/// straight to the terminal `DENIED` state and never reaches here). So
/// the ground truth at this point is structurally always "does not
/// escape the sandbox" — an `AiPlan` claiming `escapes_sandbox: true` for
/// an operation the Policy Engine already determined is safely
/// containable is exactly the divergence §21.6 exists to catch.
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

/// Only meaningful once a `SimulationDiff` exists (post-`SIMULATING`) —
/// `affected_resources` is the AI's guess made before simulation ran,
/// compared against what the deterministic simulation pass actually
/// found. Set comparison, not exact-match: the AI's list is prose-derived
/// and may reasonably include a parent directory a file lives under, so
/// only a *complete absence of overlap* in either direction is reported,
/// mirroring how `verification::verify`'s own path-set comparison treats
/// "reported at all" as the meaningful signal rather than exact
/// formatting.
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

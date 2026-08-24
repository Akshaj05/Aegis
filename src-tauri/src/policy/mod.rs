// Policy module root: wires together the support-tier table, containment
// rules, risk classification, and the PolicyEngine that orchestrates them.

pub mod containment;
pub mod engine;
pub mod risk;
pub mod support_tiers;
pub mod types;

pub use engine::{apply_post_simulation_escalation, PolicyEngine};
pub use types::{Category, PolicyDecision, ReasonCode, RiskLevel, SupportTier, Verdict};

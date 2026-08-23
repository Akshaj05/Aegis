//! Deterministic Policy/Risk Engine — the sole security authority. See
//! `docs/architecture.md` §20. Must never depend on `ai/`
//! (docs/CLAUDE.md invariant #7); checked by
//! `tests/policy_engine_tests/main.rs`'s `guarded_modules_never_reference_ai_module`.
//!
//! **Deviation from this module's own earlier stub comment**, which said
//! this would read `policies/containment_rules.toml` and
//! `policies/risk_rules.toml`. In practice, only `supported_commands.toml`
//! turned out to hold genuinely declarative data (a command name -> tier
//! lookup table); the containment and risk *rules* themselves
//! (§20.3/§20.4) are per-command logic — "is this `rm` invocation
//! recursive and targeting the root" isn't naturally a TOML fact table
//! without inventing a small rule-matching DSL, which would be more
//! machinery than nine containment codes and a dozen risk rules warrant
//! (docs/CLAUDE.md: "Don't add features... beyond what the task
//! requires"). So the rules live as Rust in `containment.rs`/`risk.rs`,
//! and `policies/containment_rules.toml`/`risk_rules.toml` remain the
//! reference documentation of what those rules must produce (the
//! reason-code list, the risk-rule table) rather than data those modules
//! parse at runtime. If this policy needs to become hot-reloadable or
//! operator-tunable without a rebuild, moving thresholds and path lists
//! (already isolated as `const`s in `risk.rs`/`containment.rs`) into TOML
//! is a mechanical follow-up, not a redesign.
//!
//! - `types.rs` — `Category`, `Verdict`, `RiskLevel`, `SupportTier`,
//!   `ReasonCode`, `PolicyDecision`.
//! - `support_tiers.rs` — loads and self-validates `supported_commands.toml`
//!   (§19), the one real TOML-backed piece.
//! - `containment.rs` — §20.3's `Deny` rules; see its module doc for
//!   exactly which of the nine reason codes have a real trigger in this
//!   pass and why the rest don't yet.
//! - `risk.rs` — §20.4's `RequireApproval` rules and §20.5's
//!   post-simulation scope escalation.
//! - `engine.rs` — `PolicyEngine`, orchestrating §20.1's evaluation order
//!   over the above. Its tests include the "must not be denied" and "must
//!   always be denied" corpora docs/CLAUDE.md's Testing table requires.

pub mod containment;
pub mod engine;
pub mod risk;
pub mod support_tiers;
pub mod types;

pub use engine::{apply_post_simulation_escalation, PolicyEngine};
pub use types::{Category, PolicyDecision, ReasonCode, RiskLevel, SupportTier, Verdict};

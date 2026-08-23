//! Build order phase 9's required suite (docs/CLAUDE.md's testing table):
//! "Malformed output discarded wholesale; AI-claimed lower risk ignored;
//! adversarial/injected output cannot alter any decision."
//!
//! `malformed_output.rs` exercises `ai::validation::validate` directly
//! against a wider range of malformed/adversarial raw text than
//! `src/ai/validation.rs`'s own unit tests bother with (that module's
//! tests prove the mechanism works at all; this suite's job is breadth).
//! `lower_risk_ignored.rs` and `adversarial_injection.rs` drive a real
//! `transaction::manager::Transaction` through the real state machine
//! with a validated, adversarially-crafted `AiPlan` and prove routing is
//! unaffected — not by inspecting AI output for "did it try," but by
//! showing the actual `WAITING_FOR_APPROVAL` transition still fires
//! exactly when the deterministic `PolicyDecision` says it should,
//! regardless of what the AI plan claims.

mod adversarial_injection;
mod lower_risk_ignored;
mod malformed_output;

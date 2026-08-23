//! Advisory-only AI planner: `AiBackend` trait, backends, schema
//! validation, divergence detection. See `docs/architecture.md` §21.
//!
//! `policy/`, `executor/`, and `rollback/` must never depend on this
//! module (docs/CLAUDE.md invariant #7) — enforced by the
//! `policy_engine_tests` integration test
//! (`tests/policy_engine_tests/main.rs`). `transaction/` is not in that
//! guarded list and does depend on this module — deliberately: the
//! Transaction Manager persists what the AI said (§34's `ai_plans` table)
//! and records divergence findings, but never reads AI output to decide
//! anything (§21.1: "never sets or influences a security decision"). See
//! `transaction::manager::Transaction::record_ai_analysis_and_enter_simulation`.
//!
//! - `schema.rs` — [`AiPlan`] and the rest of §21.6's structured output
//!   shape, plus the outgoing [`schema::AiRequest`].
//! - `validation.rs` — §21.7's deterministic validation: the only way to
//!   turn raw response text into a trusted `AiPlan`.
//! - `backend.rs` — [`AiBackend`], [`NullBackend`], [`RemoteBackend`],
//!   [`OllamaBackend`] (§21.10's local-model deployment option, speaking
//!   a real local Ollama server's actual `/api/generate` contract rather
//!   than `RemoteBackend`'s vendor-agnostic passthrough).
//! - `divergence.rs` — §21.6/§21.7's independent cross-checks
//!   (`escapes_sandbox`, `affected_resources`). Never influences routing.
//! - `deny_explanation.rs` — §21.5's grounded DENY rendering. Deliberately
//!   *not* wired through `transaction::manager` — see that module's doc
//!   comment for why a `DENIED` transaction never reaches `AI_ANALYSIS`
//!   at all.

pub mod backend;
pub mod deny_explanation;
pub mod divergence;
pub mod schema;
pub mod validation;

pub use backend::{AiBackend, AiOutcome, NullBackend, OllamaBackend, RemoteBackend};
pub use deny_explanation::GroundedDenyExplanation;
pub use divergence::DivergenceFinding;
pub use schema::{AiPlan, AiRequest};

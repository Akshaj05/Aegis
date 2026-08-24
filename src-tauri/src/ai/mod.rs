// Advisory-only AI planner module: backends, schema, validation,
// divergence detection, and DENY explanation rendering.

pub mod backend;
pub mod deny_explanation;
pub mod divergence;
pub mod schema;
pub mod validation;

pub use backend::{AiBackend, AiOutcome, NullBackend, OllamaBackend, RemoteBackend};
pub use deny_explanation::GroundedDenyExplanation;
pub use divergence::DivergenceFinding;
pub use schema::{AiPlan, AiRequest};

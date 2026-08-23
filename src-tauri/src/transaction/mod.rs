//! Transaction state machine, transition table, and event emission — the
//! only component permitted to change transaction state. See
//! `docs/architecture.md` §13.
//!
//! - `state.rs` — `TransactionState`, the legal-transition table, and
//!   property tests covering every one of the 17*17 ordered state pairs
//!   plus §13.3's seven impossibility invariants.
//! - `token.rs` — `ApprovedExecutionToken`, constructible only from within
//!   this module (§13.3, §24, docs/CLAUDE.md invariant #11).
//! - `events.rs` — `TransactionEvent` (§29.2's schema) and the
//!   `EventSink` trait a real Tauri emitter slots into later.
//! - `manager.rs` — `Transaction`, one method per legal state edge. See
//!   its module doc for this pass's scope (stage *outcomes* are supplied
//!   by callers; only the AI planner (Build order phase 9) still doesn't
//!   produce its outcome for real — simulation (phase 6), snapshotting and
//!   rollback (phase 7), and now execution and verification (phase 8) all
//!   do) and for how it resolves `Verdict::RejectUnsupported` not having
//!   its own state in §13.1's list. As of Build order phase 7,
//!   `record_snapshot_sealed` inserts the `snapshots` row for real (see
//!   `db::snapshot_queries`) and `record_rollback_result`'s failure path
//!   quarantines the session (§27.4) — `Transaction::begin` refuses to
//!   start on a quarantined session until `rollback/`'s explicit recovery
//!   actions run. As of Build order phase 8, the outcomes fed to
//!   `record_execution_complete`/`record_verification_result` come from
//!   real `executor::execute` and `verification::verify` calls — see
//!   `tests/verification_tolerance_tests/harness.rs` for the full pipeline
//!   wired together end to end.

pub mod events;
pub mod manager;
pub mod state;
pub mod token;

pub use events::{EventSink, EventStatus, TransactionEvent};
pub use manager::{Transaction, TransactionError, TransactionId};
pub use state::TransactionState;
pub use token::ApprovedExecutionToken;

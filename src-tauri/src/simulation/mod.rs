//! Simulation Manager and Diff Engine: runs a command's handler against a
//! disposable transient layer. See `docs/architecture.md` §22.
//!
//! - `resolver.rs` — `LayeredResolver`, the merged read/write API over a
//!   `snapshot::backend::MountedView` that Build order phase 3 explicitly
//!   deferred to this phase.
//! - `diff.rs` — computes what changed in a transient layer relative to
//!   the layers beneath it (§22.3).
//! - `manager.rs` — ties transient-layer lifecycle, `LayeredResolver`, and
//!   `handlers::dispatch` together into one simulation pass (§22.2).
//!
//! Shares handler code with `executor/` (§19.3) — never a separate dry-run
//! implementation (docs/CLAUDE.md invariant #20): `handlers/mod.rs` runs
//! against `LayeredResolver` for both simulation (this module, writing to
//! a transient layer) and real execution (`executor/`, Build order phase
//! 8, writing to the active write layer), with the same dispatcher and
//! the same handler functions either way.

pub mod diff;
pub mod manager;
pub mod resolver;

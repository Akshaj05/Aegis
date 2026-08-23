//! SafeShell core library.
//!
//! Module layout mirrors `docs/architecture.md` §40. Implementation proceeds
//! in the phase order defined in `docs/CLAUDE.md` ("Build order"); modules
//! not yet reached by that order are present as stubs so the full shape of
//! the system is visible from the start, per the architecture's module list.
//!
//! Dependency-direction invariants enforced by this crate (see
//! `docs/CLAUDE.md` "Authority" #7): `policy`, `executor`, and `rollback`
//! must never depend on `ai`. That rule is checked by the
//! `policy_engine_tests` integration test (`tests/policy_engine_tests/main.rs`),
//! which scans source text for forbidden `use` paths — a real
//! compiler-enforced crate boundary would
//! require splitting these into separate crates, which is a bigger
//! restructuring than this phase calls for; the scan is the CI-enforced
//! check the architecture asks for in the meantime.

pub mod fs_abstraction;
pub mod handlers;
pub mod parser;
pub mod session;

pub mod ai;
pub mod audit;
pub mod db;
pub mod executor;
pub mod ipc;
pub mod orchestrator;
pub mod policy;
pub mod rollback;
pub mod sandbox;
pub mod simulation;
pub mod snapshot;
pub mod transaction;
pub mod verification;

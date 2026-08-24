// SafeShell library crate root: declares and exposes the crate's module
// tree (parser, policy, orchestrator, sandbox, snapshot, etc.).

pub mod fs_abstraction;
pub mod handlers;
pub mod mock_packages;
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

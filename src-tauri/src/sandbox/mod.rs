//! `SandboxBackend` trait, namespace implementation, preflight capability
//! checker, sandbox worker + typed protocol. See `docs/architecture.md` §14-15.
//!
//! Build order phase 2 so far, in two slices:
//!
//! 1. The Preflight Capability Checker: `backend.rs` (trait +
//!    `CapabilityReport`), `preflight.rs` (the aggregator), and the
//!    individual probes (`syscalls.rs`, `seccomp.rs`, `landlock.rs`,
//!    `cgroups.rs`).
//! 2. The sandbox worker's typed request protocol end to end —
//!    `worker/protocol.rs` (the wire types), `worker/transport.rs`
//!    (length-prefixed framing over a `UnixStream`), `worker/resolver.rs`
//!    (the `openat2`+`RESOLVE_BENEATH` path resolution — the real
//!    containment control), `worker/dispatch.rs`, and `worker/mod.rs`'s
//!    request loop. All real-tested against a plain host directory,
//!    including proving `RESOLVE_BENEATH` refuses escape attempts on this
//!    kernel — see `worker/mod.rs`'s doc comment for exactly what's
//!    verified versus deferred.
//!
//! 3. `NamespaceSandboxBackend` (`namespace_backend.rs`): forks, enters
//!    namespaces, `pivot_root`s, applies the real seccomp baseline and a
//!    Landlock ruleset, joins a resource-limited cgroup, and hands the
//!    result to `worker::serve`. Its `create_session` fail-closed refusal
//!    (§15.3) when required capabilities are unavailable is real-verified
//!    on this machine — everything past that gate is not, because this
//!    machine never gets past it. See that module's doc comment for
//!    exactly where verification stops.
//!
//! `syscalls.rs` is the only module in this crate permitted to contain
//! `unsafe` (docs/CLAUDE.md code conventions); see its own doc comment for
//! an honest account of which probes were actually exercised on their
//! success path in this project's development environment versus only on
//! their failure path.

pub mod backend;
pub mod cgroups;
pub mod landlock;
pub mod namespace_backend;
pub mod preflight;
pub mod seccomp;
pub mod syscalls;
pub mod worker;

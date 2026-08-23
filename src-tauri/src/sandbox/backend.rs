//! `SandboxBackend` trait and the capability-report types it deals in. See
//! `docs/architecture.md` §11, §14.4, §15.
//!
//! `SandboxOp`/`OpResult` are the already-real, already-tested worker
//! protocol types (`docs/architecture.md` §25.2) — no separate abstraction
//! needed over them at this layer. `SandboxConfig`/`SandboxHandle` carry
//! what `namespace_backend.rs`'s `NamespaceSandboxBackend` actually needs;
//! see that module for the implementation this trait is written against.

use std::fmt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::sandbox::cgroups::CgroupLimits;
pub use crate::sandbox::worker::protocol::{
    WorkerRequest as SandboxOp, WorkerResponse as OpResult,
};

/// Per-primitive preflight status. Mirrors the strings used in
/// `get_capability_report` (§41: `"ok"`, `"unavailable"`,
/// `"fallback:fuse-overlayfs"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimitiveStatus {
    Ok,
    /// A required primitive is missing. Per §15.3, this must never be
    /// silently substituted — it is either fail-closed (for required
    /// primitives) or surfaced as a named degradation (for optional ones).
    Unavailable {
        reason: String,
    },
    /// A non-security-degrading substitution is in effect (e.g. OverlayFS
    /// falling back to fuse-overlayfs, or `openat2` falling back to a
    /// component-walk `openat`). Distinct from `Unavailable`: the affected
    /// execution mode still works, just via a different mechanism, and
    /// that mechanism is named here for the audit trail.
    Fallback {
        using: String,
        reason: String,
    },
    /// The primitive works but with reduced hardening relative to the
    /// preferred configuration (Landlock's "continue with disclosure"
    /// case, §15.2).
    Degraded {
        detail: String,
    },
}

impl PrimitiveStatus {
    pub fn is_ok(&self) -> bool {
        matches!(self, PrimitiveStatus::Ok)
    }

    pub fn is_unavailable(&self) -> bool {
        matches!(self, PrimitiveStatus::Unavailable { .. })
    }
}

impl fmt::Display for PrimitiveStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrimitiveStatus::Ok => write!(f, "ok"),
            PrimitiveStatus::Unavailable { reason } => write!(f, "unavailable ({reason})"),
            PrimitiveStatus::Fallback { using, reason } => write!(f, "fallback:{using} ({reason})"),
            PrimitiveStatus::Degraded { detail } => write!(f, "degraded ({detail})"),
        }
    }
}

/// Aggregate preflight result. See `docs/architecture.md` §15.2 (the
/// per-primitive table this mirrors) and §41 (`get_capability_report`'s
/// IPC shape, which this type is the Rust-side source of truth for).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    pub user_namespaces: PrimitiveStatus,
    pub mount_namespaces: PrimitiveStatus,
    pub pid_namespaces: PrimitiveStatus,
    pub seccomp: PrimitiveStatus,
    pub cgroups_v2: PrimitiveStatus,
    pub landlock: PrimitiveStatus,
    /// Not probed by this pass — real multi-lowerdir OverlayFS self-testing
    /// belongs with the layer model (Build order phase 3). Always
    /// `Unavailable` with a reason saying so until then; never guessed at.
    pub overlayfs: PrimitiveStatus,
    pub openat2: PrimitiveStatus,
    /// Named degradations for the audit trail (§15.2's capability report
    /// persisted per session), e.g. `"landlock_unavailable"`.
    pub degradations: Vec<String>,
}

impl CapabilityReport {
    /// Whether sandboxed execution is available at all, per §15.3's
    /// fail-closed rule: every primitive whose row in §15.2 says "fail
    /// closed" must be `Ok`. PID namespaces gate only process-affecting
    /// commands, not overall availability (§15.2's PID namespace row).
    /// Landlock and OverlayFS degrade rather than block.
    pub fn execution_available(&self) -> bool {
        self.user_namespaces.is_ok()
            && self.mount_namespaces.is_ok()
            && self.seccomp.is_ok()
            && self.cgroups_v2.is_ok()
    }

    /// Whether process-representation commands (`ps`, `kill`, mock
    /// services) are available, per §15.2's PID-namespace row: filesystem
    /// operation may continue without it, but process-affecting commands
    /// must report DENIED with a capability reason.
    pub fn process_commands_available(&self) -> bool {
        self.execution_available() && self.pid_namespaces.is_ok()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("required security capability unavailable: {0}")]
    CapabilityUnavailable(String),
    #[error("sandbox session creation failed: {0}")]
    SessionCreationFailed(String),
    #[error("sandbox operation failed: {0}")]
    OperationFailed(String),
}

/// Everything `NamespaceSandboxBackend::create_session` needs, supplied by
/// the caller (eventually the Transaction Manager / session layer —
/// neither exists yet, so today's callers are tests and whatever wires
/// this up next).
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Unique per session — used to name the session's cgroup
    /// (`safeshell-<session_id>`) and must therefore be filesystem-path
    /// safe (no `/`).
    pub session_id: String,
    /// Directory to `pivot_root` into. SafeShell's own configuration
    /// (the base image / layer stack location), never user command input
    /// — same rule as `fs_abstraction::HostManagedPath`. Build order phase
    /// 3's layer model is what will populate this meaningfully; today it
    /// can be any real directory, including a plain temp dir in tests.
    pub root_path: PathBuf,
    pub cgroup_limits: CgroupLimits,
}

/// A live sandbox session: the worker child's pid (for cgroup membership
/// and teardown) and the host's end of the connected socket (for
/// `exec_in_sandbox`). Constructible only by `NamespaceSandboxBackend`.
#[derive(Debug)]
pub struct SandboxHandle {
    pub(crate) child_pid: nix::unistd::Pid,
    pub(crate) socket: UnixStream,
    pub(crate) cgroup_path: PathBuf,
}

/// Owns isolation: namespaces, mounts, `pivot_root`, seccomp, Landlock,
/// cgroups, and the sandbox worker process lifecycle. See
/// `docs/architecture.md` §14.4.
pub trait SandboxBackend {
    fn preflight(&self) -> CapabilityReport;
    fn create_session(&self, cfg: &SandboxConfig) -> Result<SandboxHandle, SandboxError>;
    fn exec_in_sandbox(
        &self,
        handle: &SandboxHandle,
        op: &SandboxOp,
    ) -> Result<OpResult, SandboxError>;
    fn teardown(&self, handle: SandboxHandle) -> Result<(), SandboxError>;
}

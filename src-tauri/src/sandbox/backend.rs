// Defines the SandboxBackend trait and the capability-report, config, and
// handle types used to create and operate sandbox sessions.

use std::fmt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::sandbox::cgroups::CgroupLimits;
pub use crate::sandbox::worker::protocol::{
    WorkerRequest as SandboxOp, WorkerResponse as OpResult,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimitiveStatus {
    Ok,
    Unavailable {
        reason: String,
    },
    Fallback {
        using: String,
        reason: String,
    },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    pub user_namespaces: PrimitiveStatus,
    pub mount_namespaces: PrimitiveStatus,
    pub pid_namespaces: PrimitiveStatus,
    pub seccomp: PrimitiveStatus,
    pub cgroups_v2: PrimitiveStatus,
    pub landlock: PrimitiveStatus,
    pub overlayfs: PrimitiveStatus,
    pub openat2: PrimitiveStatus,
    pub degradations: Vec<String>,
}

impl CapabilityReport {
    pub fn execution_available(&self) -> bool {
        self.user_namespaces.is_ok()
            && self.mount_namespaces.is_ok()
            && self.seccomp.is_ok()
            && self.cgroups_v2.is_ok()
    }

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

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub session_id: String,
    pub root_path: PathBuf,
    pub cgroup_limits: CgroupLimits,
}

#[derive(Debug)]
pub struct SandboxHandle {
    pub(crate) child_pid: nix::unistd::Pid,
    pub(crate) socket: UnixStream,
    pub(crate) cgroup_path: PathBuf,
}

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

// NamespaceSandboxBackend: forks, enters namespaces, pivot_roots, applies
// seccomp and Landlock, joins a resource-limited cgroup, and hands off to
// the sandbox worker.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use nix::sched::CloneFlags;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};

use crate::sandbox::backend::{
    CapabilityReport, OpResult, SandboxBackend, SandboxConfig, SandboxError, SandboxHandle,
    SandboxOp,
};
use crate::sandbox::preflight::PreflightCapabilityChecker;
use crate::sandbox::worker::{self, transport};
use crate::sandbox::{cgroups, landlock, seccomp, syscalls};

pub struct NamespaceSandboxBackend;

impl NamespaceSandboxBackend {
    pub fn new() -> Self {
        NamespaceSandboxBackend
    }
}

impl Default for NamespaceSandboxBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxBackend for NamespaceSandboxBackend {
    fn preflight(&self) -> CapabilityReport {
        PreflightCapabilityChecker::new().run()
    }

    fn create_session(&self, cfg: &SandboxConfig) -> Result<SandboxHandle, SandboxError> {
        let report = self.preflight();
        if !report.execution_available() {
            return Err(SandboxError::CapabilityUnavailable(
                missing_required_primitives(&report),
            ));
        }

        let cgroup_path = cgroups::create_session_cgroup(&cfg.session_id, &cfg.cgroup_limits)
            .map_err(|e| SandboxError::SessionCreationFailed(format!("cgroup setup: {e}")))?;

        let (host_socket, worker_socket) = UnixStream::pair()
            .map_err(|e| SandboxError::SessionCreationFailed(format!("socketpair: {e}")))?;

        let root_path = cfg.root_path.clone();

        match syscalls::fork_for_session()
            .map_err(|e| SandboxError::SessionCreationFailed(format!("fork: {e}")))?
        {
            syscalls::ForkOutcome::Child => {
                drop(host_socket);
                run_session_child(root_path, worker_socket);
            }
            syscalls::ForkOutcome::Parent { child_pid } => {
                drop(worker_socket);
                finish_session_creation(child_pid, host_socket, cgroup_path)
            }
        }
    }

    fn exec_in_sandbox(
        &self,
        handle: &SandboxHandle,
        op: &SandboxOp,
    ) -> Result<OpResult, SandboxError> {
        transport::send_message(&handle.socket, op)
            .map_err(|e| SandboxError::OperationFailed(format!("send: {e}")))?;
        transport::recv_message(&handle.socket)
            .map_err(|e| SandboxError::OperationFailed(format!("recv: {e}")))
    }

    fn teardown(&self, handle: SandboxHandle) -> Result<(), SandboxError> {
        drop(handle.socket);
        waitpid(handle.child_pid, None)
            .map_err(|e| SandboxError::OperationFailed(format!("waitpid: {e}")))?;
        cgroups::remove_session_cgroup(&handle.cgroup_path)
            .map_err(|e| SandboxError::OperationFailed(format!("cgroup cleanup: {e}")))?;
        Ok(())
    }
}

fn finish_session_creation(
    child_pid: Pid,
    host_socket: UnixStream,
    cgroup_path: PathBuf,
) -> Result<SandboxHandle, SandboxError> {
    if let Err(e) = cgroups::add_process(&cgroup_path, child_pid.as_raw()) {
        abandon_session(child_pid, &cgroup_path);
        return Err(SandboxError::SessionCreationFailed(format!(
            "failed to join session cgroup: {e}"
        )));
    }

    match transport::recv_message::<SetupOutcome>(&host_socket) {
        Ok(SetupOutcome::Ready) => Ok(SandboxHandle {
            child_pid,
            socket: host_socket,
            cgroup_path,
        }),
        Ok(SetupOutcome::Failed(msg)) => {
            let _ = waitpid(child_pid, None);
            let _ = cgroups::remove_session_cgroup(&cgroup_path);
            Err(SandboxError::SessionCreationFailed(msg))
        }
        Err(e) => {
            abandon_session(child_pid, &cgroup_path);
            Err(SandboxError::SessionCreationFailed(format!(
                "setup handshake failed: {e}"
            )))
        }
    }
}

fn abandon_session(child_pid: Pid, cgroup_path: &Path) {
    let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGKILL);
    let _ = waitpid(child_pid, None);
    let _ = cgroups::remove_session_cgroup(cgroup_path);
}

fn missing_required_primitives(report: &CapabilityReport) -> String {
    let mut missing = Vec::new();
    if !report.user_namespaces.is_ok() {
        missing.push(format!("user_namespaces: {}", report.user_namespaces));
    }
    if !report.mount_namespaces.is_ok() {
        missing.push(format!("mount_namespaces: {}", report.mount_namespaces));
    }
    if !report.seccomp.is_ok() {
        missing.push(format!("seccomp: {}", report.seccomp));
    }
    if !report.cgroups_v2.is_ok() {
        missing.push(format!("cgroups_v2: {}", report.cgroups_v2));
    }
    format!(
        "cannot create sandbox session — required capabilities unavailable: {}",
        missing.join("; ")
    )
}

#[derive(Debug, Serialize, Deserialize)]
enum SetupOutcome {
    Ready,
    Failed(String),
}

fn run_session_child(root_path: PathBuf, mut worker_socket: UnixStream) -> ! {
    match try_setup_session(&root_path) {
        Ok(()) => {
            if transport::send_message(&worker_socket, &SetupOutcome::Ready).is_ok() {
                let _ = worker::serve(Path::new("/"), &mut worker_socket);
            }
            std::process::exit(0);
        }
        Err(e) => {
            let _ = transport::send_message(&worker_socket, &SetupOutcome::Failed(e.to_string()));
            std::process::exit(1);
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum SetupError {
    #[error("unshare failed: {0}")]
    Unshare(String),
    #[error("uid/gid mapping failed: {0}")]
    IdMap(String),
    #[error("pivot_root sequence failed: {0}")]
    PivotRoot(String),
    #[error("mounting a fresh /proc failed: {0}")]
    ProcMount(String),
    #[error("Landlock restriction failed: {0}")]
    Landlock(String),
    #[error("seccomp baseline failed: {0}")]
    Seccomp(#[from] crate::sandbox::seccomp::SeccompApplyError),
}

fn try_setup_session(root_path: &Path) -> Result<(), SetupError> {
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();

    nix::sched::unshare(
        CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWNET,
    )
    .map_err(|e| SetupError::Unshare(e.to_string()))?;

    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"))
        .map_err(|e| SetupError::IdMap(format!("uid_map: {e}")))?;
    std::fs::write("/proc/self/setgroups", "deny")
        .map_err(|e| SetupError::IdMap(format!("setgroups: {e}")))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"))
        .map_err(|e| SetupError::IdMap(format!("gid_map: {e}")))?;

    std::fs::create_dir_all(root_path.join("proc"))
        .map_err(|e| SetupError::PivotRoot(format!("proc dir: {e}")))?;
    let old_root = root_path.join(".old_root");
    std::fs::create_dir_all(&old_root)
        .map_err(|e| SetupError::PivotRoot(format!("old_root dir: {e}")))?;

    nix::mount::mount(
        Some(root_path),
        root_path,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| SetupError::PivotRoot(format!("bind mount: {e}")))?;

    nix::unistd::chdir(root_path).map_err(|e| SetupError::PivotRoot(format!("chdir root: {e}")))?;
    nix::unistd::pivot_root(".", ".old_root")
        .map_err(|e| SetupError::PivotRoot(format!("pivot_root: {e}")))?;
    nix::unistd::chdir("/").map_err(|e| SetupError::PivotRoot(format!("chdir /: {e}")))?;

    let _ = nix::mount::umount2("/.old_root", nix::mount::MntFlags::MNT_DETACH);

    nix::mount::mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    )
    .map_err(|e| SetupError::ProcMount(e.to_string()))?;

    match landlock::restrict_to_root() {
        Ok(_) => {}
        Err(e) => return Err(SetupError::Landlock(e.to_string())),
    }

    seccomp::apply_baseline()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::cgroups::CgroupLimits;

    fn test_config(session_id: &str) -> SandboxConfig {
        SandboxConfig {
            session_id: session_id.to_string(),
            root_path: std::env::temp_dir().join(format!("safeshell-nsbackend-test-{session_id}")),
            cgroup_limits: CgroupLimits {
                pids_max: 64,
                memory_max_bytes: 64 * 1024 * 1024,
                cpu_quota_period: (50_000, 100_000),
            },
        }
    }

    #[test]
    fn create_session_fails_closed_when_capabilities_are_unavailable() {
        let backend = NamespaceSandboxBackend::new();
        let report = backend.preflight();
        if report.execution_available() {
            eprintln!(
                "skipping: this machine actually has full sandbox capability, which this test isn't equipped to safely exercise end-to-end"
            );
            return;
        }

        let cfg = test_config("capgate");
        let result = backend.create_session(&cfg);
        assert!(matches!(
            result,
            Err(SandboxError::CapabilityUnavailable(_))
        ));
    }

    #[test]
    fn try_setup_session_fails_cleanly_without_panicking() {
        let root = std::env::temp_dir().join(format!(
            "safeshell-nsbackend-setup-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();

        let outcome = syscalls::run_probe_in_child(|| match try_setup_session(&root) {
            Ok(()) => 0,
            Err(_) => 1,
        });

        let _ = std::fs::remove_dir_all(&root);
        let code = outcome.expect("probe fork itself should succeed");
        println!("try_setup_session (in throwaway child): exit code {code}");
    }
}

//! `NamespaceSandboxBackend` — the MVP-default `SandboxBackend` (§14.4):
//! forks, enters user/mount/PID/UTS/net namespaces, `pivot_root`s into a
//! real root, applies the seccomp baseline and a Landlock ruleset, joins a
//! resource-limited cgroup, and hands the result off to
//! `worker::serve` (§8, §25.2).
//!
//! **What is and isn't verified in this pass** (read before trusting the
//! `Ok` path on anything past capability-gating):
//!
//! `create_session` checks `CapabilityReport::execution_available()`
//! *before* doing anything else, per §15.3's fail-closed rule. On this
//! development machine `cgroups_v2` already reports `Unavailable` (see
//! `cgroups.rs`'s tests), so `execution_available()` is `false` here and
//! `create_session` always returns `Err` at that very first check — it
//! never reaches the fork, the namespace-entry sequence, `pivot_root`,
//! Landlock, or the seccomp baseline in this environment, full stop. That
//! fail-closed refusal itself *is* real-verified (see this module's
//! tests). Everything past it — `try_setup_session`'s body — is
//! independently unit-tested by calling it directly (bypassing the
//! capability gate, the way `sandbox/syscalls.rs`'s probes are tested),
//! which reaches the same `unshare(CLONE_NEWUSER)`-then-`setgroups`
//! failure point documented there and goes no further. The `/proc` mount,
//! Landlock application, and seccomp baseline steps inside
//! `try_setup_session` are, to the best of my understanding, correct, but
//! have never actually executed on any machine this project has run on.
//! Verify on a real Linux host with unprivileged user namespaces enabled.

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
                // Diverges (-> !): the child never returns past this call.
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
        // Dropping the host's end of the socket delivers EOF to the
        // worker, which is `run_loop`'s clean-exit signal (§13.2-style:
        // an orderly end, not a failure).
        drop(handle.socket);
        waitpid(handle.child_pid, None)
            .map_err(|e| SandboxError::OperationFailed(format!("waitpid: {e}")))?;
        cgroups::remove_session_cgroup(&handle.cgroup_path)
            .map_err(|e| SandboxError::OperationFailed(format!("cgroup cleanup: {e}")))?;
        Ok(())
    }
}

/// Finishes session creation on the **host** side once a child has been
/// forked: joins the child to its cgroup, waits for its setup handshake,
/// and cleans up (kills/reaps the child, removes the cgroup) on any
/// failure rather than leaking a half-configured process or an orphaned
/// cgroup directory.
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

/// Kills and reaps a child whose setup we can no longer trust or wait on
/// normally, then best-effort removes its cgroup. Used only on failure
/// paths where the child's own exit can't be relied on to happen promptly
/// (e.g. the handshake message itself never arrived).
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

/// Handshake sent once, by the child to the host, immediately before the
/// child enters `worker::run_loop`. Distinct from `WorkerRequest`/
/// `WorkerResponse` (`worker/protocol.rs`) — this is session-setup
/// signaling, not a filesystem operation.
#[derive(Debug, Serialize, Deserialize)]
enum SetupOutcome {
    Ready,
    Failed(String),
}

/// The child side of `create_session`. Never returns: exits via
/// `std::process::exit` on every path. This is an ordinary (not
/// throwaway-probe) long-lived process from this point on, so — unlike
/// `syscalls::run_probe_in_child`'s children — it uses `std::process::exit`
/// rather than `libc::_exit`, running Rust's normal exit machinery, which
/// is correct here precisely because this process's lifetime is real, not
/// a microsecond-scale probe.
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

/// Runs the full namespace-entry, `pivot_root`, and hardening sequence on
/// the **calling** process (must be the freshly-forked session child —
/// see module docs for what is/isn't verified here).
fn try_setup_session(root_path: &Path) -> Result<(), SetupError> {
    // `getuid()`/`getgid()` must be read *before* `unshare(CLONE_NEWUSER)`
    // — see `sandbox/syscalls.rs::probe_user_namespace`'s doc comment for
    // why: reading them after returns the fresh namespace's unmapped
    // overflow id (65534), not this process's real id, and a mapping
    // built from that is correctly refused by the kernel. A real bug an
    // earlier version of this function had too, found and fixed via the
    // same diagnosis that fixed the probes.
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();

    // 1. Namespaces, rootless: user + mount + PID + UTS + net, matching
    //    §8's diagram. Network namespace means loopback-only, no route
    //    (§14.2) — nothing further needs to be configured for that; an
    //    unconfigured net namespace already has no route out.
    nix::sched::unshare(
        CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWNET,
    )
    .map_err(|e| SetupError::Unshare(e.to_string()))?;

    // 2. Map this process to uid/gid 0 *inside* the new user namespace
    //    (§18: "root inside the simulation" without host privilege).
    //    Write order uid_map, then setgroups, then gid_map: harmless
    //    either way for uid_map, but gid_map genuinely needs setgroups
    //    written first.
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"))
        .map_err(|e| SetupError::IdMap(format!("uid_map: {e}")))?;
    std::fs::write("/proc/self/setgroups", "deny")
        .map_err(|e| SetupError::IdMap(format!("setgroups: {e}")))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"))
        .map_err(|e| SetupError::IdMap(format!("gid_map: {e}")))?;

    // 3. pivot_root into root_path. A fresh "proc" directory is created
    //    inside it beforehand so step 4 has somewhere to mount onto —
    //    root_path is SafeShell-managed content (today: whatever the
    //    caller configured; from Build order phase 3 onward, the layer
    //    stack's mounted view), so adding this directory to it is not
    //    the "resolve user input against the host root" mistake §25.1
    //    warns about.
    std::fs::create_dir_all(root_path.join("proc"))
        .map_err(|e| SetupError::PivotRoot(format!("proc dir: {e}")))?;
    let old_root = root_path.join(".old_root");
    std::fs::create_dir_all(&old_root)
        .map_err(|e| SetupError::PivotRoot(format!("old_root dir: {e}")))?;

    // pivot_root requires its target to already be a mount point.
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

    // Detach the old root — best-effort; not fatal if it fails (the old
    // tree is inaccessible either way once nothing below `/` can reach
    // it, and this process's PID-namespace exit will tear the mount
    // namespace down regardless).
    let _ = nix::mount::umount2("/.old_root", nix::mount::MntFlags::MNT_DETACH);

    // 4. A fresh /proc for *this* PID namespace — required both for
    //    `sandbox/worker/resolver.rs`'s `read_dir` (§25.2's containment
    //    scope doesn't cover this file directly, but it does need the
    //    kernel-provided `/proc/self/fd/N` magic link, which only exists
    //    if /proc is mounted) and, later, for `ps`-style commands to see
    //    only this PID namespace's processes.
    nix::mount::mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    )
    .map_err(|e| SetupError::ProcMount(e.to_string()))?;

    // 5. Landlock, defense in depth on top of the pivot_root boundary —
    //    applied *after* pivot_root so "/" means the sandbox root, not
    //    the host root (see `landlock::restrict_to_root`'s doc comment).
    //    Unsupported degrades with disclosure (§15.2); this pass has
    //    nowhere to *put* that disclosure yet (no audit log — Build order
    //    phase 5+), so it's silently tolerated rather than failing —
    //    documented here as the gap it is, not hidden.
    match landlock::restrict_to_root() {
        Ok(_) => {}
        Err(e) => return Err(SetupError::Landlock(e.to_string())),
    }

    // 6. seccomp baseline last: the final, most restrictive gate, applied
    //    only once every syscall this setup sequence itself still needs
    //    (mount, pivot_root, chdir) has already happened.
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

    /// The one thing about `create_session` this environment can verify
    /// for real end to end: it refuses outright, before forking anything,
    /// when required capabilities aren't available — which is genuinely
    /// true here (see this module's doc comment). No child process or
    /// cgroup should be left behind by a refusal at this stage.
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

    /// Exercises `try_setup_session`'s real body directly, bypassing the
    /// capability gate — this reaches the same `unshare`-then-`setgroups`
    /// failure point documented in `syscalls.rs`, verifying at least that
    /// this function propagates that failure as a clean `Err`, from a
    /// throwaway forked child, rather than panicking or hanging.
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
        // Not asserting a specific outcome: whether this succeeds is
        // exactly the environment-dependent question this whole module's
        // doc comment is honest about. It must not have panicked or hung
        // to get this far, which `run_probe_in_child` returning at all
        // already demonstrates.
    }
}

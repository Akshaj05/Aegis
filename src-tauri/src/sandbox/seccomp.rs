//! seccomp-bpf, via the `seccompiler` crate's safe API — no `unsafe` needed
//! in this module itself (docs/CLAUDE.md: `unsafe` is confined to
//! `sandbox/syscalls.rs`). See `docs/architecture.md` §15.2, §18.
//!
//! Two things live here: the preflight self-test ("install a trivial
//! filter in a probe child and verify a denied syscall is blocked",
//! §15.2), and [`apply_baseline`], the real profile applied to the
//! sandbox worker.
//!
//! **Build order phase 12 ("seccomp tightening"): default-deny, not
//! default-allow.** An earlier pass here built [`apply_baseline`] as a
//! denylist — a fixed set of dangerous syscalls (`mount`, `reboot`,
//! `ptrace`, …) blocked, everything else implicitly allowed
//! (`mismatch_action = Allow`, i.e. "anything not explicitly matched
//! passes through"). That is a real security control (it still stops the
//! syscalls §18 names), but it is not what "hardening" should mean for a
//! process whose entire post-setup job is a small, fixed set of file
//! operations dispatched from a typed protocol
//! (`sandbox/worker/dispatch.rs`) — a syscall this worker has no reason
//! to ever call (e.g. `execve`, `socket`, `bpf`, `keyctl`) was reachable
//! by anything that could get code running in that process (a bug in a
//! dependency, a future handler with a mistake in it), purely because
//! nobody had thought to deny it by name yet. [`apply_baseline`] now
//! flips the model: [`ALLOWED_SYSCALLS`] is the only thing the worker can
//! call after this filter installs; everything else gets `Errno(EPERM)`,
//! not a process-killing action — a syscall this list is missing makes
//! *that one operation* fail with a plain I/O error (which
//! `sandbox/worker/dispatch.rs` already turns into a `WorkerResponse::Error`
//! for the specific request that needed it, per its own fail-safe
//! design), not a crash, so an incomplete allowlist degrades gracefully
//! rather than catastrophically. [`ALLOWED_SYSCALLS`] itself was built
//! from a real `strace -c` capture of every syscall this worker's actual
//! request/response loop makes (open root, `touch`/`mkdir`/`read`/`stat`/
//! `read_dir`, and the socket transport), not guessed — see
//! `apply_baseline_allows_a_real_request_response_session_end_to_end`
//! below, which applies this exact filter in a throwaway forked child and
//! then runs a real session through it, proving the allowlist is
//! sufficient rather than just installable.
//!
//! `mount`/`umount2`/`pivot_root`/`socket`/`ptrace`/`reboot`/`kexec_load`/
//! `init_module`/`swapon`/etc. are consequently denied by *absence*
//! now, not by an explicit entry — the old `DENIED_SYSCALLS` list doesn't
//! need to exist any more; not being on [`ALLOWED_SYSCALLS`] already
//! denies all of them, which is strictly stricter than enumerating them
//! (docs/CLAUDE.md's tie-break rule: "default to... stricter enforcement
//! at the boundary"). This worker never needs to mount anything itself
//! after its own initial `pivot_root` setup runs (which happens *before*
//! this filter is installed), and MVP's command grammar has no operation
//! that legitimately calls `socket()`/`ptrace()` at all.

use std::collections::BTreeMap;

use seccompiler::{SeccompAction, SeccompFilter};

use crate::sandbox::backend::PrimitiveStatus;
use crate::sandbox::syscalls::{query_personality_flags, run_probe_in_child};

/// §15.2: installs a filter denying one harmless syscall
/// (`personality(2)`, chosen because a probe child has no other reason to
/// call it) and verifies the denial actually takes effect.
pub fn self_test() -> PrimitiveStatus {
    let outcome = run_probe_in_child(|| {
        let mut rules = BTreeMap::new();
        rules.insert(libc::SYS_personality, vec![]);

        let target_arch = match std::env::consts::ARCH.try_into() {
            Ok(arch) => arch,
            Err(_) => return 1,
        };

        let filter = match SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            target_arch,
        ) {
            Ok(f) => f,
            Err(_) => return 2,
        };

        let program: seccompiler::BpfProgram = match filter.try_into() {
            Ok(p) => p,
            Err(_) => return 3,
        };

        if seccompiler::apply_filter(&program).is_err() {
            return 4;
        }

        // Trigger the syscall we just denied. `personality` is a harmless
        // choice — this probe child needs it for nothing else, so denying
        // it can't break anything the probe itself depends on.
        match query_personality_flags() {
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => 0,
            _ => 5,
        }
    });

    match outcome {
        Ok(0) => PrimitiveStatus::Ok,
        Ok(code) => PrimitiveStatus::Unavailable {
            reason: format!(
                "seccomp self-test failed at step {code} (1=arch lookup, 2=filter build, \
                 3=BPF compile, 4=apply_filter, 5=denied syscall was not actually blocked)"
            ),
        },
        Err(e) => PrimitiveStatus::Unavailable {
            reason: format!("probe fork failed: {e}"),
        },
    }
}

/// The only syscalls [`apply_baseline`] permits after it installs. Built
/// from a real `strace -c` capture of a scratch binary exercising
/// `sandbox/worker`'s actual request/response loop (touch, mkdir, read,
/// stat, read_dir, and the socket transport) — not guessed — then pruned
/// of pure process-startup/dynamic-linker noise (that trace's own
/// `execve`/`clone3`/`readlinkat`/etc., none of which happen after this
/// filter installs in the real flow, since it's applied deep inside an
/// already-running forked child, never around `exec`). Grouped below by
/// what each group is for, not left as one flat, unexplained list, and
/// verified sufficient — not just plausible — by
/// `apply_baseline_allows_a_real_request_response_session_end_to_end`
/// below, which runs that exact workload through this exact filter in a
/// real forked child.
const ALLOWED_SYSCALLS: &[i64] = &[
    // Socket transport (`worker/transport.rs`, a `UnixStream`) — reads
    // and writes on a connected stream socket surface as either the
    // plain file-descriptor syscalls or their socket-specific
    // equivalents depending on libc/kernel version, so both families are
    // allowed rather than gambling on which one this build produces.
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    // Real path resolution and file operations (`sandbox/syscalls.rs`'s
    // `openat2_raw`/`mkdirat_raw`, `RootResolver::open`'s `File::open`,
    // `RootResolver::read_dir`'s `/proc/self/fd/N` walk).
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_mkdirat,
    libc::SYS_close,
    libc::SYS_fstat,
    libc::SYS_statx,
    libc::SYS_getdents64,
    libc::SYS_lseek,
    // Allocator/heap growth for request/response buffers (file contents,
    // path strings) — Rust's own process-startup runtime init (signal
    // handlers, guard pages) already ran long before this filter
    // installs, so this is deliberately not a full process-startup
    // syscall set, just what plain heap growth during request handling
    // can still trigger.
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_brk,
    libc::SYS_madvise,
    libc::SYS_futex,
    // `HashMap`'s per-process random seed (first use, lazily), read once
    // and cached — a real observed call, not a hypothetical one.
    libc::SYS_getrandom,
    // Signal return (only reached if a signal is actually delivered and
    // handled — harmless to allow, and denying it would make ordinary
    // signal delivery hang rather than degrade gracefully) and process
    // exit.
    libc::SYS_rt_sigreturn,
    libc::SYS_exit,
    libc::SYS_exit_group,
];

#[derive(Debug, thiserror::Error)]
pub enum SeccompApplyError {
    #[error("unrecognized target architecture for seccomp filter: {0}")]
    UnknownArch(String),
    #[error("failed to build seccomp filter: {0}")]
    FilterBuild(String),
    #[error("failed to compile seccomp BPF program: {0}")]
    BpfCompile(String),
    #[error("failed to install seccomp filter: {0}")]
    Install(String),
}

/// Installs the real baseline profile on the **calling** process/thread —
/// callers apply this from inside the sandbox worker child, after
/// `pivot_root` (§18: "`pivot_root` is called once by the sandbox setup
/// code itself and denied thereafter" — `pivot_root` is not on
/// [`ALLOWED_SYSCALLS`], so it must go on *after* the setup code's own
/// `pivot_root` call, never before, or setup itself would break).
///
/// Unlike [`self_test`], this does not fork — it's meant to be called by
/// the session child as the last hardening step before it starts serving
/// requests, restricting that same process going forward, not a
/// disposable copy of it. Default-deny: every syscall not on
/// [`ALLOWED_SYSCALLS`] gets `Errno(EPERM)`, never a process-killing
/// action — see this module's doc comment for why that matters for a
/// possibly-incomplete allowlist's failure mode.
pub fn apply_baseline() -> Result<(), SeccompApplyError> {
    let mut rules = std::collections::BTreeMap::new();
    for &syscall in ALLOWED_SYSCALLS {
        rules.insert(syscall, vec![]);
    }

    let target_arch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| SeccompApplyError::UnknownArch(std::env::consts::ARCH.to_string()))?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        target_arch,
    )
    .map_err(|e| SeccompApplyError::FilterBuild(e.to_string()))?;

    let program: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| SeccompApplyError::BpfCompile(e.to_string()))?;

    seccompiler::apply_filter(&program).map_err(|e| SeccompApplyError::Install(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_test_runs_to_completion() {
        let status = self_test();
        println!("seccomp::self_test: {status}");
        assert!(matches!(
            status,
            PrimitiveStatus::Ok | PrimitiveStatus::Unavailable { .. }
        ));
    }

    /// `apply_baseline` restricts the *calling* thread for the rest of its
    /// life, and that restriction is inherited by anything it execs — if
    /// this test called it directly in the test process, it could
    /// permanently restrict whichever OS thread the test harness happens
    /// to run it on, breaking unrelated later tests that reuse that
    /// thread. Running it inside a disposable forked child (like
    /// `self_test` does) verifies it builds and installs without ever
    /// touching the real test process.
    #[test]
    fn apply_baseline_builds_and_installs_in_a_throwaway_child() {
        let outcome = run_probe_in_child(|| match apply_baseline() {
            Ok(()) => 0,
            Err(_) => 1,
        });
        let code = outcome.expect("probe fork itself should succeed");
        println!("seccomp::apply_baseline (in throwaway child): exit code {code}");
        assert_eq!(
            code, 0,
            "apply_baseline should build and install cleanly on this kernel"
        );
    }

    /// The real proof [`ALLOWED_SYSCALLS`] is *sufficient*, not just
    /// buildable: forks a genuine long-lived session-style child (via
    /// `syscalls::fork_for_session`, the same primitive
    /// `namespace_backend.rs` uses for the real worker), applies the
    /// tightened filter in it, and then runs an actual
    /// `sandbox::worker::serve` request/response session through it —
    /// touch, mkdir, read, read_dir, stat, over the real socket transport
    /// — exactly the workload `ALLOWED_SYSCALLS`'s doc comment says it was
    /// built from. No namespaces are needed for this (unlike the real
    /// worker, this child never calls `pivot_root`), which is exactly
    /// what makes it something this dev environment — which cannot get
    /// past `unshare(CLONE_NEWUSER)`'s follow-up `setgroups` write (see
    /// `syscalls.rs`'s "Honesty note") — can still verify for real.
    #[test]
    fn apply_baseline_allows_a_real_request_response_session_end_to_end() {
        use std::os::unix::net::UnixStream;

        use nix::sys::wait::{waitpid, WaitStatus};

        use crate::sandbox::syscalls::{fork_for_session, ForkOutcome};
        use crate::sandbox::worker::protocol::{FileKind, StatInfo, WorkerRequest, WorkerResponse};
        use crate::sandbox::worker::{serve, transport};

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("existing.txt"), b"hello").unwrap();
        let root = tmp.path().to_path_buf();

        let (client, mut server) = UnixStream::pair().unwrap();

        match fork_for_session().expect("fork_for_session itself should succeed") {
            ForkOutcome::Child => {
                drop(client);
                let code = match apply_baseline() {
                    Ok(()) => match serve(&root, &mut server) {
                        Ok(()) => 0,
                        Err(_) => 1,
                    },
                    Err(_) => 2,
                };
                // `unsafe` stays confined to `sandbox/syscalls.rs`
                // (docs/CLAUDE.md) — `exit_immediately` is that module's
                // safe wrapper around `_exit`, used here for the same
                // reason `run_probe_in_child` uses it internally: this is
                // a throwaway forked child with nothing left to do.
                crate::sandbox::syscalls::exit_immediately(code);
            }
            ForkOutcome::Parent { child_pid } => {
                drop(server);

                transport::send_message(
                    &client,
                    &WorkerRequest::Touch {
                        rel_path: "touched.txt".into(),
                    },
                )
                .unwrap();
                let resp: WorkerResponse = transport::recv_message(&client).unwrap();
                assert_eq!(resp, WorkerResponse::Ok, "touch under the tightened filter");

                transport::send_message(
                    &client,
                    &WorkerRequest::Mkdir {
                        parent_rel: "".into(),
                        name: "project".into(),
                    },
                )
                .unwrap();
                let resp: WorkerResponse = transport::recv_message(&client).unwrap();
                assert_eq!(resp, WorkerResponse::Ok, "mkdir under the tightened filter");

                transport::send_message(
                    &client,
                    &WorkerRequest::ReadFile {
                        rel_path: "existing.txt".into(),
                    },
                )
                .unwrap();
                let resp: WorkerResponse = transport::recv_message(&client).unwrap();
                assert_eq!(
                    resp,
                    WorkerResponse::FileContents(b"hello".to_vec()),
                    "read_file under the tightened filter"
                );

                transport::send_message(
                    &client,
                    &WorkerRequest::ReadDir {
                        rel_path: "".into(),
                    },
                )
                .unwrap();
                let resp: WorkerResponse = transport::recv_message(&client).unwrap();
                match resp {
                    WorkerResponse::DirEntries(names) => {
                        assert!(names.contains(&"project".to_string()));
                        assert!(names.contains(&"touched.txt".to_string()));
                    }
                    other => {
                        panic!("expected DirEntries under the tightened filter, got {other:?}")
                    }
                }

                transport::send_message(
                    &client,
                    &WorkerRequest::Stat {
                        rel_path: "project".into(),
                    },
                )
                .unwrap();
                let resp: WorkerResponse = transport::recv_message(&client).unwrap();
                match resp {
                    WorkerResponse::Stat(StatInfo {
                        kind: FileKind::Directory,
                        ..
                    }) => {}
                    other => panic!(
                        "expected a directory Stat under the tightened filter, got {other:?}"
                    ),
                }

                drop(client);
                match waitpid(child_pid, None).unwrap() {
                    WaitStatus::Exited(_, 0) => {}
                    other => panic!(
                        "worker child under the tightened seccomp filter did not exit cleanly: {other:?}"
                    ),
                }
            }
        }
    }

    /// The other half of "default-deny": a syscall genuinely absent from
    /// [`ALLOWED_SYSCALLS`] — `socket(2)`, which the worker never
    /// legitimately needs (its one connection is inherited from the
    /// parent, never self-created) — must still be refused with `EPERM`
    /// after the filter installs, proving denial-by-absence actually
    /// takes effect and isn't just "everything happens to be on the
    /// list."
    #[test]
    fn a_syscall_absent_from_the_allowlist_is_denied_after_apply_baseline() {
        let outcome = run_probe_in_child(|| {
            if apply_baseline().is_err() {
                return 1;
            }
            match crate::sandbox::syscalls::probe_raw_socket() {
                Ok(()) => 2, // unexpected success — the filter didn't take effect
                Err(e) if e.raw_os_error() == Some(libc::EPERM) => 0,
                Err(_) => 3, // some other error — inconclusive, not the expected denial
            }
        });
        assert_eq!(
            outcome,
            Ok(0),
            "socket(2) is absent from ALLOWED_SYSCALLS and must be denied with EPERM \
             (1=apply_baseline failed, 2=socket unexpectedly succeeded, 3=wrong errno)"
        );
    }
}

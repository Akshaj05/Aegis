// seccomp-bpf preflight self-test and the default-deny syscall allowlist
// filter applied to the sandbox worker process.

use std::collections::BTreeMap;

use seccompiler::{SeccompAction, SeccompFilter};

use crate::sandbox::backend::PrimitiveStatus;
use crate::sandbox::syscalls::{query_personality_flags, run_probe_in_child};

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

const ALLOWED_SYSCALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_mkdirat,
    libc::SYS_close,
    libc::SYS_fstat,
    libc::SYS_statx,
    libc::SYS_getdents64,
    libc::SYS_lseek,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_brk,
    libc::SYS_madvise,
    libc::SYS_futex,
    libc::SYS_getrandom,
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

    #[test]
    fn a_syscall_absent_from_the_allowlist_is_denied_after_apply_baseline() {
        let outcome = run_probe_in_child(|| {
            if apply_baseline().is_err() {
                return 1;
            }
            match crate::sandbox::syscalls::probe_raw_socket() {
                Ok(()) => 2,
                Err(e) if e.raw_os_error() == Some(libc::EPERM) => 0,
                Err(_) => 3,
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

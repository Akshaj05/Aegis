// Raw syscall wrappers and unsafe fork/exit primitives used by the sandbox
// preflight probes, the namespace backend, and the worker's path
// resolution.

use nix::sched::CloneFlags;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::ForkResult;

use crate::sandbox::backend::PrimitiveStatus;

pub(crate) fn run_probe_in_child<F>(probe: F) -> Result<u8, nix::Error>
where
    F: FnOnce() -> u8,
{
    let fork_result = unsafe { nix::unistd::fork() }?;
    match fork_result {
        ForkResult::Child => {
            let code = probe();
            unsafe { libc::_exit(code as i32) };
        }
        ForkResult::Parent { child } => match waitpid(child, None)? {
            WaitStatus::Exited(_, code) => Ok(code as u8),
            _ => Ok(255),
        },
    }
}

pub enum ForkOutcome {
    Parent { child_pid: nix::unistd::Pid },
    Child,
}

pub fn fork_for_session() -> Result<ForkOutcome, nix::Error> {
    let fork_result = unsafe { nix::unistd::fork() }?;
    Ok(match fork_result {
        ForkResult::Parent { child } => ForkOutcome::Parent { child_pid: child },
        ForkResult::Child => ForkOutcome::Child,
    })
}

pub fn probe_user_namespace() -> PrimitiveStatus {
    let outcome = run_probe_in_child(|| {
        let uid = nix::unistd::getuid();
        if nix::sched::unshare(CloneFlags::CLONE_NEWUSER).is_err() {
            return 1;
        }
        if std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_err() {
            return 2;
        }
        if std::fs::write("/proc/self/setgroups", "deny").is_err() {
            return 3;
        }
        0
    });

    match outcome {
        Ok(0) => PrimitiveStatus::Ok,
        Ok(code) => PrimitiveStatus::Unavailable {
            reason: format!(
                "probe failed at step {code} of 3 (1=unshare(CLONE_NEWUSER), \
                 2=write /proc/self/uid_map, 3=write /proc/self/setgroups) — re-run with \
                 RUST_LOG or attach strace to a probe child for the specific errno"
            ),
        },
        Err(e) => PrimitiveStatus::Unavailable {
            reason: format!("probe fork failed: {e}"),
        },
    }
}

pub fn probe_mount_namespace_and_pivot_root() -> PrimitiveStatus {
    probe_mount_namespace_and_pivot_root_at(fresh_probe_root())
}

pub(crate) fn fresh_probe_root() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "safeshell-preflight-mountns-{}-{}",
        std::process::id(),
        ulid::Ulid::new()
    ))
}

pub(crate) fn probe_mount_namespace_and_pivot_root_at(
    probe_root: std::path::PathBuf,
) -> PrimitiveStatus {
    let probe_root_for_child = probe_root.clone();

    let outcome = run_probe_in_child(move || {
        let uid = nix::unistd::getuid();
        let gid = nix::unistd::getgid();
        if nix::sched::unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS).is_err() {
            return 1;
        }

        if std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_err() {
            return 2;
        }
        if std::fs::write("/proc/self/setgroups", "deny").is_err() {
            return 3;
        }
        if std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).is_err() {
            return 4;
        }

        let new_root = probe_root_for_child.as_path();
        let old_root = new_root.join(".old_root");
        if std::fs::create_dir_all(&old_root).is_err() {
            return 5;
        }

        if nix::mount::mount(
            Some(new_root),
            new_root,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .is_err()
        {
            return 6;
        }

        if nix::unistd::chdir(new_root).is_err() {
            return 7;
        }
        if nix::unistd::pivot_root(".", ".old_root").is_err() {
            return 8;
        }
        if nix::unistd::chdir("/").is_err() {
            return 9;
        }

        0
    });

    let _ = std::fs::remove_dir_all(&probe_root);

    match outcome {
        Ok(0) => PrimitiveStatus::Ok,
        Ok(code) => PrimitiveStatus::Unavailable {
            reason: format!(
                "probe failed at step {code} (1=unshare, 2-4=uid/gid map, 5=temp root setup, \
                 6=bind mount, 7-9=pivot_root sequence)"
            ),
        },
        Err(e) => PrimitiveStatus::Unavailable {
            reason: format!("probe fork failed: {e}"),
        },
    }
}

pub fn probe_pid_namespace() -> PrimitiveStatus {
    let outcome = run_probe_in_child(|| {
        let uid = nix::unistd::getuid();
        let gid = nix::unistd::getgid();
        if nix::sched::unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID).is_err() {
            return 1;
        }

        if std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_err() {
            return 2;
        }
        if std::fs::write("/proc/self/setgroups", "deny").is_err() {
            return 3;
        }
        if std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).is_err() {
            return 4;
        }

        let grandchild_fork = unsafe { nix::unistd::fork() };
        match grandchild_fork {
            Ok(ForkResult::Child) => {
                let is_pid_1 = nix::unistd::getpid().as_raw() == 1;
                unsafe { libc::_exit(if is_pid_1 { 0 } else { 20 }) };
            }
            Ok(ForkResult::Parent { child: grandchild }) => match waitpid(grandchild, None) {
                Ok(WaitStatus::Exited(_, 0)) => 0,
                Ok(WaitStatus::Exited(_, code)) => code as u8,
                _ => 21,
            },
            Err(_) => 22,
        }
    });

    match outcome {
        Ok(0) => PrimitiveStatus::Ok,
        Ok(code) => PrimitiveStatus::Unavailable {
            reason: format!(
                "probe failed at step {code} (1=unshare, 2-4=uid/gid map, 20=grandchild did not \
                 observe PID 1, 21=grandchild wait failed, 22=grandchild fork failed)"
            ),
        },
        Err(e) => PrimitiveStatus::Unavailable {
            reason: format!("probe fork failed: {e}"),
        },
    }
}

pub fn openat2_raw(
    dirfd: std::os::fd::RawFd,
    path: &std::ffi::CStr,
    flags: i32,
    resolve: u64,
    mode: u64,
) -> std::io::Result<std::os::fd::OwnedFd> {
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags as u64;
    how.mode = mode;
    how.resolve = resolve;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };

    if ret >= 0 {
        Ok(unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(ret as i32) })
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub fn mkdirat_raw(
    dirfd: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    mode: u32,
) -> std::io::Result<()> {
    let ret = unsafe { libc::mkdirat(dirfd, name.as_ptr(), mode) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub fn unlinkat_raw(
    dirfd: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    is_dir: bool,
) -> std::io::Result<()> {
    let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    let ret = unsafe { libc::unlinkat(dirfd, name.as_ptr(), flags) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub fn probe_openat2() -> PrimitiveStatus {
    let path = match std::ffi::CString::new(".") {
        Ok(p) => p,
        Err(e) => {
            return PrimitiveStatus::Unavailable {
                reason: format!("probe path error: {e}"),
            }
        }
    };

    match openat2_raw(libc::AT_FDCWD, &path, libc::O_RDONLY, 0, 0) {
        Ok(_owned_fd) => PrimitiveStatus::Ok,
        Err(errno) => {
            if errno.raw_os_error() == Some(libc::ENOSYS) {
                PrimitiveStatus::Fallback {
                    using: "component-walk openat with O_NOFOLLOW".into(),
                    reason: "openat2 syscall not available (pre-5.6 kernel, or blocked)".into(),
                }
            } else {
                PrimitiveStatus::Unavailable {
                    reason: format!("openat2 probe failed: {errno}"),
                }
            }
        }
    }
}

pub(super) fn query_personality_flags() -> Result<(), std::io::Error> {
    let ret = unsafe { libc::personality(0xffffffff) };
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn exit_immediately(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

#[cfg(test)]
pub(super) fn probe_raw_socket() -> Result<(), std::io::Error> {
    let ret = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if ret >= 0 {
        unsafe {
            libc::close(ret);
        }
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_probe_in_child_reports_child_exit_code() {
        let code = run_probe_in_child(|| 42).unwrap();
        assert_eq!(code, 42);
    }

    #[test]
    fn run_probe_in_child_reports_zero_on_success() {
        let code = run_probe_in_child(|| 0).unwrap();
        assert_eq!(code, 0);
    }

    fn open_dirfd(path: &std::path::Path) -> std::os::fd::OwnedFd {
        use std::os::fd::AsFd;
        std::fs::File::open(path)
            .unwrap()
            .as_fd()
            .try_clone_to_owned()
            .unwrap()
    }

    #[test]
    fn openat2_raw_opens_an_existing_file_relative_to_a_dirfd() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"hi").unwrap();
        let dirfd = open_dirfd(tmp.path());

        let name = std::ffi::CString::new("a.txt").unwrap();
        use std::os::fd::AsRawFd;
        let fd = openat2_raw(
            dirfd.as_raw_fd(),
            &name,
            libc::O_RDONLY,
            libc::RESOLVE_BENEATH,
            0,
        )
        .expect("openat2 should open an existing in-bounds file");

        let mut file = std::fs::File::from(fd);
        let mut contents = String::new();
        std::io::Read::read_to_string(&mut file, &mut contents).unwrap();
        assert_eq!(contents, "hi");
    }

    #[test]
    fn openat2_raw_with_resolve_beneath_refuses_a_dotdot_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let confined = tmp.path().join("confined");
        std::fs::create_dir(&confined).unwrap();
        std::fs::write(tmp.path().join("secret.txt"), b"top secret").unwrap();

        let dirfd = open_dirfd(&confined);
        let escape_attempt = std::ffi::CString::new("../secret.txt").unwrap();
        use std::os::fd::AsRawFd;
        let result = openat2_raw(
            dirfd.as_raw_fd(),
            &escape_attempt,
            libc::O_RDONLY,
            libc::RESOLVE_BENEATH,
            0,
        );

        assert!(
            result.is_err(),
            "RESOLVE_BENEATH should have refused a `..` escape attempt"
        );
    }

    #[test]
    fn openat2_raw_with_resolve_beneath_refuses_an_absolute_path() {
        let tmp = tempfile::tempdir().unwrap();
        let dirfd = open_dirfd(tmp.path());
        let absolute = std::ffi::CString::new("/etc/passwd").unwrap();
        use std::os::fd::AsRawFd;
        let result = openat2_raw(
            dirfd.as_raw_fd(),
            &absolute,
            libc::O_RDONLY,
            libc::RESOLVE_BENEATH,
            0,
        );
        assert!(
            result.is_err(),
            "RESOLVE_BENEATH should have refused an absolute path"
        );
    }

    #[test]
    fn mkdirat_raw_creates_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dirfd = open_dirfd(tmp.path());
        let name = std::ffi::CString::new("new_dir").unwrap();
        use std::os::fd::AsRawFd;
        mkdirat_raw(dirfd.as_raw_fd(), &name, 0o755).unwrap();
        assert!(tmp.path().join("new_dir").is_dir());
    }

    #[test]
    fn unlinkat_raw_removes_a_file() {
        use std::os::fd::AsRawFd;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"gone soon").unwrap();
        let dirfd = open_dirfd(tmp.path());
        let name = std::ffi::CString::new("a.txt").unwrap();
        unlinkat_raw(dirfd.as_raw_fd(), &name, false).unwrap();
        assert!(!tmp.path().join("a.txt").exists());
    }

    #[test]
    fn unlinkat_raw_removes_an_empty_directory() {
        use std::os::fd::AsRawFd;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("empty_dir")).unwrap();
        let dirfd = open_dirfd(tmp.path());
        let name = std::ffi::CString::new("empty_dir").unwrap();
        unlinkat_raw(dirfd.as_raw_fd(), &name, true).unwrap();
        assert!(!tmp.path().join("empty_dir").exists());
    }

    #[test]
    fn unlinkat_raw_refuses_a_nonempty_directory_without_at_removedir_matching_reality() {
        use std::os::fd::AsRawFd;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("has_stuff")).unwrap();
        std::fs::write(tmp.path().join("has_stuff/inner.txt"), b"x").unwrap();
        let dirfd = open_dirfd(tmp.path());
        let name = std::ffi::CString::new("has_stuff").unwrap();
        let result = unlinkat_raw(dirfd.as_raw_fd(), &name, true);
        assert!(
            result.is_err(),
            "AT_REMOVEDIR must refuse a non-empty directory, matching real rmdir(2) semantics"
        );
        assert!(tmp.path().join("has_stuff").exists());
    }

    #[test]
    fn probe_user_namespace_runs_to_completion() {
        let status = probe_user_namespace();
        println!("probe_user_namespace: {status}");
        assert!(matches!(
            status,
            PrimitiveStatus::Ok | PrimitiveStatus::Unavailable { .. }
        ));
    }

    #[test]
    fn probe_mount_namespace_and_pivot_root_runs_to_completion() {
        let status = probe_mount_namespace_and_pivot_root();
        println!("probe_mount_namespace_and_pivot_root: {status}");
        assert!(matches!(
            status,
            PrimitiveStatus::Ok | PrimitiveStatus::Unavailable { .. }
        ));
    }

    #[test]
    fn probe_mount_namespace_cleans_up_its_temp_directory() {
        let probe_root = fresh_probe_root();
        let _ = probe_mount_namespace_and_pivot_root_at(probe_root.clone());
        assert!(
            !probe_root.exists(),
            "probe left its own temp directory behind: {}",
            probe_root.display()
        );
    }

    #[test]
    fn probe_pid_namespace_runs_to_completion() {
        let status = probe_pid_namespace();
        println!("probe_pid_namespace: {status}");
        assert!(matches!(
            status,
            PrimitiveStatus::Ok | PrimitiveStatus::Unavailable { .. }
        ));
    }

    #[test]
    fn probe_openat2_runs_to_completion() {
        let status = probe_openat2();
        println!("probe_openat2: {status}");
        assert!(matches!(
            status,
            PrimitiveStatus::Ok
                | PrimitiveStatus::Unavailable { .. }
                | PrimitiveStatus::Fallback { .. }
        ));
    }
}

//! The only module in this crate permitted to contain `unsafe`
//! (docs/CLAUDE.md code conventions). Every `unsafe` block below carries a
//! comment stating the invariant it relies on, per that same rule.
//!
//! This pass implements the active self-tests from `docs/architecture.md`
//! §15.2 for the primitives that need raw syscalls: user/mount/PID
//! namespace creation (via `fork()` + `unshare()` + `pivot_root()`), and
//! `openat2` availability (§25.2). seccomp and Landlock have their own
//! modules because they go through safe wrapper crates (`seccompiler`,
//! `landlock`) and need no `unsafe` of their own.
//!
//! **Honesty note for whoever reads this next**: `probe_user_namespace`,
//! `probe_mount_namespace_and_pivot_root`, and `probe_pid_namespace` all
//! now genuinely reach `PrimitiveStatus::Ok` on a real machine — verified
//! after finding and fixing a real bug, not by adjusting the probes to
//! pass. Two issues stacked on that machine, diagnosed in order:
//!
//! 1. `kernel.apparmor_restrict_unprivileged_userns` (a Ubuntu 24.04+
//!    systemwide sysctl) blocked the `/proc/self/setgroups`/`uid_map`
//!    writes outright; setting it to `0` got past that.
//! 2. Even with that relaxed, these probes still failed — because
//!    `getuid()`/`getgid()` were being read *after* `unshare(CLONE_NEWUSER)`
//!    instead of before. Per `user_namespaces(7)`, until `uid_map` is
//!    written, a process's own id *as seen from inside its own fresh,
//!    unmapped namespace* reads back as the overflow id (`65534`), not
//!    its real id — so the mapping being written was `"0 65534 1"`, which
//!    the kernel correctly refuses (the unprivileged single-id exception
//!    only covers mapping your *own* real id). Confirmed by instrumenting
//!    the probe and printing the raw error and the misread uid directly.
//!    Moving the `getuid()`/`getgid()` calls before `unshare()` fixed it.
//!
//! `cgroups_v2` delegation (a separate, systemd-level `Delegate=` gap) is
//! the remaining blocker for `execution_available()` on that same
//! machine as of this note — namespace creation itself is no longer the
//! open question this note used to describe.
//!
//! `openat2_raw`/`mkdirat_raw` below and the resolver built on them
//! (`sandbox/worker/resolver.rs`) don't depend on namespace creation at
//! all and were independently verified against a plain directory from
//! the start.

use nix::sched::CloneFlags;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::ForkResult;

use crate::sandbox::backend::PrimitiveStatus;

/// Forks a throwaway child to run `probe` in isolation from the parent
/// process's state, and returns the child's exit code (0-255). Used by
/// every namespace-related preflight probe: `unshare()`/`pivot_root()`
/// affect only the calling process, so testing them for real (rather than
/// guessing from a kernel version string) means doing them in a process we
/// intend to throw away regardless of outcome.
///
/// SAFETY invariant this relies on: SafeShell's preflight check runs
/// single-threaded, early at startup (before any other threads exist).
/// `fork()` is unsafe in general because a multithreaded parent can leave
/// the child with a half-locked allocator or other thread-owned state; a
/// single-threaded caller has no other threads whose locks could be held
/// at fork time, so that hazard doesn't apply here. The child calls
/// `probe` (ordinary safe Rust) and then unconditionally exits via
/// `libc::_exit` — it never returns through the rest of the parent's call
/// stack, never unwinds, and never runs Rust's normal `exit` machinery
/// (atexit handlers, stdio flush) meant for the *parent* process.
pub(crate) fn run_probe_in_child<F>(probe: F) -> Result<u8, nix::Error>
where
    F: FnOnce() -> u8,
{
    // SAFETY: see function doc comment above.
    let fork_result = unsafe { nix::unistd::fork() }?;
    match fork_result {
        ForkResult::Child => {
            let code = probe();
            // SAFETY: throwaway probe child exiting immediately after
            // `probe` returns; using `_exit` (not `std::process::exit` or
            // a normal return) deliberately skips destructors and
            // parent-process cleanup machinery that should not run twice.
            unsafe { libc::_exit(code as i32) };
        }
        ForkResult::Parent { child } => match waitpid(child, None)? {
            WaitStatus::Exited(_, code) => Ok(code as u8),
            // Any other outcome (killed by signal, stopped, ...) is
            // itself evidence the probe environment is unusual; callers
            // treat this as "probe inconclusive / failed" rather than
            // panicking, since a preflight check must never crash the
            // application it's checking on behalf of.
            _ => Ok(255),
        },
    }
}

/// Which side of a [`fork_for_session`] call this is.
pub enum ForkOutcome {
    /// The original (host) process. Carries the new child's pid so the
    /// caller can manage its lifecycle explicitly (join it into a cgroup,
    /// wait for it at teardown) — unlike [`run_probe_in_child`], this
    /// function does not wait for the child itself, because the child is
    /// expected to run indefinitely (the sandbox worker loop), not exit
    /// immediately.
    Parent { child_pid: nix::unistd::Pid },
    /// The new child process.
    Child,
}

/// Forks for a real, long-lived sandbox session child — as opposed to
/// [`run_probe_in_child`]'s throwaway, immediately-exiting probe children.
/// The caller in the `Child` case is responsible for eventually calling
/// `std::process::exit` (a normal, safe exit — this child is not a
/// microsecond-lived probe, so there's no reason to skip Rust's ordinary
/// exit machinery the way `run_probe_in_child` deliberately does) and must
/// never let control flow return past the fork call site in that branch,
/// or both processes will continue executing the caller's remaining code.
///
/// SAFETY invariant this relies on: identical to [`run_probe_in_child`] —
/// SafeShell forks only from a single-threaded context (session creation
/// happens before any worker threads exist for that session).
pub fn fork_for_session() -> Result<ForkOutcome, nix::Error> {
    // SAFETY: see function doc comment above.
    let fork_result = unsafe { nix::unistd::fork() }?;
    Ok(match fork_result {
        ForkResult::Parent { child } => ForkOutcome::Parent { child_pid: child },
        ForkResult::Child => ForkOutcome::Child,
    })
}

/// §15.2 row: "User namespaces (`CLONE_NEWUSER`, unprivileged) — Attempt
/// `unshare(CLONE_NEWUSER)` in a probe child; verify uid/gid map write."
///
/// **`getuid()`/`getgid()` must be read *before* `unshare(CLONE_NEWUSER)`,
/// never after.** This was a real bug, not a guess: an earlier version of
/// this probe called `unshare()` first and read `getuid()` afterward —
/// but per `user_namespaces(7)`, until `uid_map` is written, a process's
/// own uid *as seen from inside its own fresh, unmapped namespace* reads
/// back as the overflow id (`65534`, "nobody"), not its real uid. That
/// bug then tried to write `"0 65534 1"` to `uid_map` — mapping a uid the
/// process doesn't actually own — which the kernel correctly refuses with
/// `EPERM` (the unprivileged single-id exception only covers mapping your
/// *own* real uid). Confirmed by instrumenting this exact probe on a real
/// machine and printing the raw error: `getuid()` really did read back
/// `65534` after `unshare()`, and moving the `getuid()`/`getgid()` calls
/// before it is what actually fixed `execution_available` going from
/// `false` to `true` there — not the write-order change history briefly
/// (and wrongly) attributed this to.
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
            // Deliberately factual, not speculative about *why* the step
            // failed: the underlying `io::Error`/`nix::Error` doesn't
            // survive the fork boundary in this implementation (the child
            // only returns a `u8` exit code), so this names which
            // operation failed without guessing at a specific root cause
            // that may not match the actual one.
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

/// §15.2 row: "Mount namespaces (`CLONE_NEWNS`) + `pivot_root` — Probe
/// child performs `pivot_root` into a temporary tree." Run together with
/// `CLONE_NEWUSER` because that's how SafeShell actually uses it —
/// rootless, never with real host privilege.
///
/// `getuid()`/`getgid()` are read *before* `unshare()` — see
/// [`probe_user_namespace`]'s doc comment for why (reading them after
/// returns the unmapped-namespace overflow id, not the real one, and a
/// mapping built from that is correctly refused). Write order `uid_map`
/// → `setgroups` → `gid_map`: harmless either way for `uid_map` (no
/// prerequisite), but `gid_map` genuinely does need `setgroups` written
/// first, so it stays last.
pub fn probe_mount_namespace_and_pivot_root() -> PrimitiveStatus {
    probe_mount_namespace_and_pivot_root_at(fresh_probe_root())
}

/// Keyed by pid *and* a fresh ULID, not pid alone: every test in one
/// `cargo test` binary shares the same process id, so two tests calling
/// [`probe_mount_namespace_and_pivot_root`] concurrently (the ordinary
/// case — this function has more than one caller in `tests` below) would
/// otherwise race on the exact same directory. Invisible as long as this
/// probe failed before ever touching the filesystem; a real, reproducible
/// collision once it started succeeding for real.
pub(crate) fn fresh_probe_root() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "safeshell-preflight-mountns-{}-{}",
        std::process::id(),
        ulid::Ulid::new()
    ))
}

/// Split out from [`probe_mount_namespace_and_pivot_root`] so its own
/// tests can supply a `probe_root` they generated themselves and assert
/// on that *exact* path's cleanup afterward, instead of scanning the
/// whole temp directory for anything matching the shared name prefix —
/// which is racy against any *other* concurrently-running call to this
/// same function (each with its own, now-unique, `fresh_probe_root()`
/// path) and was a real, reproducible test flake once this probe started
/// succeeding for real, not just a theoretical one.
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

        // pivot_root requires its target to already be a mount point, so
        // bind-mount the probe root onto itself first.
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

    // The probe root is a real host directory created before the child's
    // mount namespace diverges; it survives the child's exit (the mount
    // namespace and its bind mount don't) and must be cleaned up by the
    // parent, unconditionally, regardless of probe outcome.
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

/// §15.2 row: "PID namespace (`CLONE_NEWPID`) — Probe child verifies it
/// observes itself as PID 1." Per `pid_namespaces(7)`, the process that
/// calls `unshare(CLONE_NEWPID)` does **not** itself move into the new
/// namespace — only its next child does — so this probe forks twice.
///
/// `getuid()`/`getgid()` are read *before* `unshare()` — see
/// [`probe_user_namespace`]'s doc comment for why.
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

        // SAFETY: same invariant as `run_probe_in_child` above — this is
        // already inside a throwaway, single-threaded probe child.
        // Forking again here is the only way to actually observe
        // PID-namespace behavior, per the architecture's specified check.
        let grandchild_fork = unsafe { nix::unistd::fork() };
        match grandchild_fork {
            Ok(ForkResult::Child) => {
                let is_pid_1 = nix::unistd::getpid().as_raw() == 1;
                // SAFETY: throwaway grandchild, same reasoning as
                // `run_probe_in_child`'s child branch.
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

/// Raw `openat2(2)` wrapper: resolves `path` relative to `dirfd` with the
/// given `flags`/`resolve` mask/`mode`, returning an owned fd. This is the
/// **only** place in the crate that calls `openat2` directly — both the
/// preflight probe ([`probe_openat2`]) and the worker's real path
/// resolution (`sandbox/worker/resolver.rs`) go through this function, so
/// there's exactly one syscall call site to audit for the ABI details
/// (§25.2).
///
/// `dirfd` is typically `libc::AT_FDCWD` (probing) or a retained root
/// directory fd (the worker's real resolution, always paired with
/// `RESOLVE_BENEATH` there). This function itself applies no policy about
/// which `resolve` flags are "safe" — callers choose those; see
/// `resolver.rs` for the containment-relevant choice.
pub fn openat2_raw(
    dirfd: std::os::fd::RawFd,
    path: &std::ffi::CStr,
    flags: i32,
    resolve: u64,
    mode: u64,
) -> std::io::Result<std::os::fd::OwnedFd> {
    // `libc::open_how` is `#[non_exhaustive]` (no struct-literal
    // construction from outside the crate) and derives no `Default`. It's
    // a plain three-`u64`-field `#[repr(C)]`/`Copy` type with no padding
    // or pointer fields, so zero-initializing is a valid value and then
    // assigning fields individually is fine — field assignment on an
    // already-constructed value isn't restricted by `#[non_exhaustive]`,
    // only struct-literal/functional-update syntax is.
    //
    // SAFETY: `open_how` has no invalid bit patterns (three plain `u64`s),
    // so zero-initializing it via `mem::zeroed()` cannot produce undefined
    // behavior the way it could for a type with padding, references, or
    // niches.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags as u64;
    how.mode = mode;
    how.resolve = resolve;

    // SAFETY: `path` is a valid, NUL-terminated, live `CStr` for the
    // duration of this call. `how` is a plain `#[repr(C)]` value with a
    // layout `libc` defines to match the kernel's `struct open_how` ABI
    // (verified: `size_of::<libc::open_how>() == 24`, the documented
    // size). `dirfd` is caller-supplied and used exactly as the kernel API
    // requires (a valid fd or the `AT_FDCWD` sentinel) — this function
    // does not itself validate `dirfd` ownership because it doesn't take
    // ownership of it; only the returned fd is owned by the caller.
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
        // SAFETY: `ret` is a valid, freshly-opened fd returned by the
        // syscall immediately above, exclusively owned by this call site
        // (nothing else has a handle to it yet) — wrapping it in `OwnedFd`
        // is exactly what transfers that ownership into a safe type that
        // closes it on drop.
        Ok(unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(ret as i32) })
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Raw `mkdirat(2)` wrapper. `name` **must** be a single path component
/// (no `/`, not `.`/`..`) — see `sandbox/worker/protocol.rs`'s doc comment
/// for why: `mkdirat` has no `RESOLVE_BENEATH`-equivalent, so a multi-
/// component `name` would be resolved relative to `dirfd` with no
/// containment check at all. This function trusts the caller to have
/// already enforced that (`resolver.rs` does); it is not itself the
/// containment control.
pub fn mkdirat_raw(
    dirfd: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    mode: u32,
) -> std::io::Result<()> {
    // SAFETY: `dirfd` is caller-supplied and used exactly as the kernel
    // API requires; `name` is a valid, NUL-terminated, live `CStr` for the
    // duration of this call. `mkdirat` has no other memory-safety hazard —
    // its only side effect is the directory creation itself.
    let ret = unsafe { libc::mkdirat(dirfd, name.as_ptr(), mode) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Raw `unlinkat(2)` wrapper — the removal counterpart to
/// [`mkdirat_raw`], added for `rm`'s handler
/// (`sandbox/worker/resolver.rs::RootResolver::remove_file`/
/// `remove_dir_empty`). `is_dir` selects `AT_REMOVEDIR` (only valid on an
/// already-empty directory, per `unlinkat(2)`) versus plain file removal;
/// same trust boundary as `mkdirat_raw` — this function does not itself
/// enforce containment, `resolver.rs`'s callers already resolved `dirfd`
/// via `RESOLVE_BENEATH` beforehand.
pub fn unlinkat_raw(
    dirfd: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    is_dir: bool,
) -> std::io::Result<()> {
    let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: `dirfd` is caller-supplied and used exactly as the kernel
    // API requires; `name` is a valid, NUL-terminated, live `CStr` for the
    // duration of this call. `unlinkat`'s only side effect is the removal
    // itself — no memory-safety hazard beyond the two argument contracts
    // already stated.
    let ret = unsafe { libc::unlinkat(dirfd, name.as_ptr(), flags) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// `openat2` availability (§25.2: falls back to a component-walk `openat`
/// with `O_NOFOLLOW` on pre-5.6 kernels or where the syscall is blocked).
/// No `fork()` needed — `openat2` on `.` is a harmless, self-contained
/// probe that doesn't mutate any process-global state worth isolating.
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
        // The returned OwnedFd closes itself on drop — no manual close
        // needed, unlike the pre-refactor version of this probe.
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

/// Queries the current process's personality flags (a read-only,
/// side-effect-free operation) purely to give `sandbox::seccomp::self_test`
/// something harmless to call that it can also legitimately deny via a
/// seccomp filter. Returns `Ok(())` if the call succeeded, or the `errno`
/// if it didn't (which is the expected outcome once a filter denies it).
///
/// SAFETY: `personality(0xffffffff)` is a documented query-only invocation
/// — the sentinel value asks the kernel to report the current flags
/// without changing them, so this has no effect on process state beyond
/// its return value.
pub(super) fn query_personality_flags() -> Result<(), std::io::Error> {
    let ret = unsafe { libc::personality(0xffffffff) };
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Exits the calling process immediately, skipping destructors and
/// parent-process cleanup machinery — for callers elsewhere in
/// `sandbox/` (e.g. `seccomp`'s own tests) that fork a throwaway child
/// and must exit it the same way [`run_probe_in_child`] does internally,
/// without needing an `unsafe` block of their own (docs/CLAUDE.md:
/// `unsafe` confined to this module).
///
/// SAFETY: identical reasoning to [`run_probe_in_child`]'s child branch —
/// callers use this only in a throwaway or disposable forked child that
/// has nothing left to do, so skipping normal exit machinery is correct,
/// not merely convenient.
///
/// `#[cfg(test)]`: its only caller today is `seccomp`'s own test module —
/// gated the same way so it doesn't sit unused (and dead-code-linted) in
/// a non-test build.
#[cfg(test)]
pub(super) fn exit_immediately(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

/// A bare `socket(AF_INET, SOCK_STREAM, 0)` attempt, for
/// `sandbox::seccomp`'s own tests to prove a syscall genuinely absent
/// from `seccomp::ALLOWED_SYSCALLS` (Build order phase 12's tightened,
/// default-deny baseline) is actually refused once that filter installs
/// — not merely documented as refused. The sandbox worker never creates
/// its own socket (its one connection is inherited from the parent at
/// fork time), so denying this outright costs the worker nothing.
///
/// SAFETY: `socket(2)` with a fixed, valid, harmless argument set; on an
/// (unexpected, filter-bypassing) success the returned fd is closed
/// immediately — this function exists only to observe the call's
/// outcome, never to keep a socket open.
///
/// `#[cfg(test)]`: its only caller today is `seccomp`'s own test module —
/// gated the same way so it doesn't sit unused (and dead-code-linted) in
/// a non-test build.
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

        // `File: From<OwnedFd>` is a safe std conversion — no unsafe
        // needed to turn the fd we got back into something we can read.
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
        // A file *outside* `confined`, which `..` would reach if
        // RESOLVE_BENEATH weren't enforced.
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

    // The namespace/openat2 probes are exercised for real (not mocked) —
    // see the module-level "Honesty note". These tests assert the probes
    // run to completion and produce a well-formed status, not a specific
    // Ok/Unavailable outcome, since that outcome is genuinely
    // environment-dependent and the whole point of a preflight check is to
    // reflect the real environment rather than an assumption about it.

    #[test]
    fn probe_user_namespace_runs_to_completion() {
        let status = probe_user_namespace();
        // Print so `cargo test -- --nocapture` shows what this machine
        // actually reported, for whoever verifies this on a real host.
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
        // Checks this call's *own* `probe_root` specifically
        // (`probe_mount_namespace_and_pivot_root_at`, `fresh_probe_root`)
        // rather than scanning the whole temp directory for anything
        // matching the shared name prefix — that scan is racy against
        // any other concurrently-running call to the same probe (each
        // with its own generated path), which is the ordinary case in
        // this same test module, and was a real, reproducible flake once
        // this probe started succeeding for real instead of always
        // failing before touching the filesystem.
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

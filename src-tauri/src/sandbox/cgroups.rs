// cgroups v2 delegated-subtree preflight check, and creation/limiting/
// teardown of per-session cgroups.

use std::path::{Path, PathBuf};

use crate::sandbox::backend::PrimitiveStatus;

const REQUIRED_CONTROLLERS: [&str; 3] = ["pids.max", "memory.max", "cpu.max"];

pub fn delegated_subtree_status() -> PrimitiveStatus {
    let cgroup_root = Path::new("/sys/fs/cgroup");

    if !cgroup_root.is_dir() {
        return PrimitiveStatus::Unavailable {
            reason: "no /sys/fs/cgroup mount found".into(),
        };
    }

    if !cgroup_root.join("cgroup.controllers").is_file() {
        return PrimitiveStatus::Unavailable {
            reason: "/sys/fs/cgroup has no cgroup.controllers file — not a cgroup v2 (unified) hierarchy".into(),
        };
    }

    let own_cgroup_relative = match current_process_cgroup_path() {
        Ok(p) => p,
        Err(e) => {
            return PrimitiveStatus::Unavailable {
                reason: format!("could not read own cgroup: {e}"),
            };
        }
    };

    let mut candidate = cgroup_root.join(own_cgroup_relative.trim_start_matches('/'));

    loop {
        let probe_dir = candidate.join(format!("safeshell-preflight-probe-{}", std::process::id()));

        if std::fs::create_dir(&probe_dir).is_ok() {
            let missing = missing_writable_controllers(&probe_dir);
            let _ = std::fs::remove_dir(&probe_dir);

            if missing.is_empty() {
                return PrimitiveStatus::Ok;
            }
        }

        if candidate == cgroup_root {
            break;
        }

        if !candidate.pop() {
            break;
        }
    }

    PrimitiveStatus::Unavailable {
        reason:
            "no writable delegated cgroup subtree with pids.max, memory.max and cpu.max was found"
                .into(),
    }
}

fn find_delegated_subtree() -> std::io::Result<PathBuf> {
    let cgroup_root = Path::new("/sys/fs/cgroup");

    let own_relative = current_process_cgroup_path()?;

    let mut candidate = cgroup_root.join(own_relative.trim_start_matches('/'));

    loop {
        let probe_dir = candidate.join(format!("safeshell-probe-{}", std::process::id()));

        if std::fs::create_dir(&probe_dir).is_ok() {
            let missing = missing_writable_controllers(&probe_dir);
            let _ = std::fs::remove_dir(&probe_dir);

            if missing.is_empty() {
                return Ok(candidate);
            }
        }

        if candidate == cgroup_root {
            break;
        }

        if !candidate.pop() {
            break;
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "no writable delegated cgroup subtree found",
    ))
}

fn missing_writable_controllers(probe_dir: &Path) -> Vec<&'static str> {
    REQUIRED_CONTROLLERS
        .into_iter()
        .filter(|controller| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(probe_dir.join(controller))
                .is_err()
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
pub struct CgroupLimits {
    pub pids_max: u64,
    pub memory_max_bytes: u64,
    pub cpu_quota_period: (u64, u64),
}

pub fn create_session_cgroup(session_id: &str, limits: &CgroupLimits) -> std::io::Result<PathBuf> {
    let delegated = find_delegated_subtree()?;

    let session_dir = delegated.join(format!("safeshell-{session_id}"));

    std::fs::create_dir(&session_dir)?;
    std::fs::write(session_dir.join("pids.max"), limits.pids_max.to_string())?;
    std::fs::write(
        session_dir.join("memory.max"),
        limits.memory_max_bytes.to_string(),
    )?;
    let (quota, period) = limits.cpu_quota_period;
    std::fs::write(session_dir.join("cpu.max"), format!("{quota} {period}"))?;

    Ok(session_dir)
}

pub fn add_process(cgroup_path: &Path, pid: i32) -> std::io::Result<()> {
    std::fs::write(cgroup_path.join("cgroup.procs"), pid.to_string())
}

pub fn remove_session_cgroup(cgroup_path: &Path) -> std::io::Result<()> {
    std::fs::remove_dir(cgroup_path)
}

fn current_process_cgroup_path() -> std::io::Result<String> {
    let contents = std::fs::read_to_string("/proc/self/cgroup")?;
    contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_string)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no cgroup v2 (0::) line in /proc/self/cgroup",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegated_subtree_status_runs_to_completion() {
        let status = delegated_subtree_status();
        println!("cgroups::delegated_subtree_status: {status}");
        assert!(matches!(
            status,
            PrimitiveStatus::Ok | PrimitiveStatus::Unavailable { .. }
        ));
    }

    #[test]
    fn current_process_cgroup_path_is_readable_on_this_kernel() {
        let result = current_process_cgroup_path();
        println!("current_process_cgroup_path: {result:?}");
    }

    fn test_limits() -> CgroupLimits {
        CgroupLimits {
            pids_max: 512,
            memory_max_bytes: 512 * 1024 * 1024,
            cpu_quota_period: (100_000, 100_000),
        }
    }

    #[test]
    fn create_session_cgroup_runs_to_completion() {
        let session_id = format!("test-{}", std::process::id());
        let result = create_session_cgroup(&session_id, &test_limits());
        println!("create_session_cgroup: {result:?}");
        if let Ok(path) = &result {
            let _ = remove_session_cgroup(path);
        }
    }

    #[test]
    fn add_process_to_a_nonexistent_cgroup_fails_cleanly() {
        let fake_path = Path::new("/sys/fs/cgroup/safeshell-this-does-not-exist");
        let result = add_process(fake_path, std::process::id() as i32);
        assert!(result.is_err());
    }
}

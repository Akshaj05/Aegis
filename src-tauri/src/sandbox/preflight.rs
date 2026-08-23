//! Preflight Capability Checker: runs every active self-test from
//! `docs/architecture.md` §15.2 and aggregates them into one
//! `CapabilityReport`. See §11 (component table) and §15.3 (fail-closed
//! rule — this module reports status; it does not itself decide policy.
//! `CapabilityReport::execution_available()`/`process_commands_available()`
//! in `backend.rs` are what downstream code checks before offering
//! sandboxed execution).

use crate::sandbox::backend::{CapabilityReport, PrimitiveStatus};
use crate::sandbox::{cgroups, landlock, seccomp, syscalls};

pub struct PreflightCapabilityChecker;

impl PreflightCapabilityChecker {
    pub fn new() -> Self {
        PreflightCapabilityChecker
    }

    /// Runs every probe and aggregates the result. Each probe is
    /// independent — one probe's failure does not skip the others, so the
    /// report is always complete, matching §15.2's "aggregate report" row.
    pub fn run(&self) -> CapabilityReport {
        let user_namespaces = syscalls::probe_user_namespace();
        let mount_namespaces = syscalls::probe_mount_namespace_and_pivot_root();
        let pid_namespaces = syscalls::probe_pid_namespace();
        let seccomp_status = seccomp::self_test();
        let cgroups_v2 = cgroups::delegated_subtree_status();
        let landlock_status = landlock::probe();
        let openat2 = syscalls::probe_openat2();

        // Real multi-lowerdir OverlayFS self-testing (mount a probe
        // overlay, write, verify whiteout/opaque semantics survive
        // re-stacking, per §15.2's OverlayFS row) belongs with the layer
        // model, Build order phase 3 — this pass doesn't guess at it.
        let overlayfs = PrimitiveStatus::Unavailable {
            reason: "not yet probed — OverlayFS self-test lands with the layer model (Build order phase 3)".into(),
        };

        let mut degradations = Vec::new();
        if !landlock_status.is_ok() {
            degradations.push("landlock_unavailable".to_string());
        }
        if let PrimitiveStatus::Fallback { using, .. } = &openat2 {
            degradations.push(format!("openat2_fallback:{using}"));
        }
        if let PrimitiveStatus::Fallback { using, .. } = &overlayfs {
            degradations.push(format!("simulation_backend_fallback:{using}"));
        }

        CapabilityReport {
            user_namespaces,
            mount_namespaces,
            pid_namespaces,
            seccomp: seccomp_status,
            cgroups_v2,
            landlock: landlock_status,
            overlayfs,
            openat2,
            degradations,
        }
    }
}

impl Default for PreflightCapabilityChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_produces_a_complete_report_regardless_of_individual_probe_outcomes() {
        let report = PreflightCapabilityChecker::new().run();

        // "Complete" here means every field was actually assigned by a
        // real probe (not skipped) — not that every probe reported `Ok`,
        // which is genuinely environment-dependent (see the "Honesty
        // note" in sandbox/syscalls.rs for what this machine reports).
        println!("--- CapabilityReport (this machine) ---");
        println!("user_namespaces:   {}", report.user_namespaces);
        println!("mount_namespaces:  {}", report.mount_namespaces);
        println!("pid_namespaces:    {}", report.pid_namespaces);
        println!("seccomp:           {}", report.seccomp);
        println!("cgroups_v2:        {}", report.cgroups_v2);
        println!("landlock:          {}", report.landlock);
        println!("overlayfs:         {}", report.overlayfs);
        println!("openat2:           {}", report.openat2);
        println!("degradations:      {:?}", report.degradations);
        println!(
            "execution_available:        {}",
            report.execution_available()
        );
        println!(
            "process_commands_available: {}",
            report.process_commands_available()
        );

        // overlayfs is unconditionally "not yet probed" this pass (see
        // module docs) — assert that honestly rather than assuming any
        // particular real status for it.
        assert!(
            matches!(&report.overlayfs, PrimitiveStatus::Unavailable { reason } if reason.contains("Build order phase 3"))
        );
    }

    #[test]
    fn execution_available_is_false_when_any_required_primitive_is_unavailable() {
        let report = CapabilityReport {
            user_namespaces: PrimitiveStatus::Unavailable {
                reason: "test".into(),
            },
            mount_namespaces: PrimitiveStatus::Ok,
            pid_namespaces: PrimitiveStatus::Ok,
            seccomp: PrimitiveStatus::Ok,
            cgroups_v2: PrimitiveStatus::Ok,
            landlock: PrimitiveStatus::Ok,
            overlayfs: PrimitiveStatus::Ok,
            openat2: PrimitiveStatus::Ok,
            degradations: vec![],
        };
        assert!(!report.execution_available());
    }

    #[test]
    fn execution_available_true_does_not_require_pid_namespaces_or_landlock() {
        let report = CapabilityReport {
            user_namespaces: PrimitiveStatus::Ok,
            mount_namespaces: PrimitiveStatus::Ok,
            pid_namespaces: PrimitiveStatus::Unavailable {
                reason: "test".into(),
            },
            seccomp: PrimitiveStatus::Ok,
            cgroups_v2: PrimitiveStatus::Ok,
            landlock: PrimitiveStatus::Unavailable {
                reason: "test".into(),
            },
            overlayfs: PrimitiveStatus::Unavailable {
                reason: "test".into(),
            },
            openat2: PrimitiveStatus::Fallback {
                using: "openat".into(),
                reason: "test".into(),
            },
            degradations: vec!["landlock_unavailable".into()],
        };
        assert!(report.execution_available());
        assert!(!report.process_commands_available());
    }
}

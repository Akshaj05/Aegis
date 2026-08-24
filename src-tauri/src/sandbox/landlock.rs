// Landlock ABI preflight probe and the ruleset that restricts the sandbox
// worker to filesystem access beneath its own root.

use landlock::{
    path_beneath_rules, Access, AccessFs, LandlockStatus, Ruleset, RulesetAttr, RulesetCreatedAttr,
    ABI,
};

use crate::sandbox::backend::PrimitiveStatus;
use crate::sandbox::syscalls::run_probe_in_child;

pub fn probe() -> PrimitiveStatus {
    let outcome = run_probe_in_child(|| {
        let result = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V1))
            .and_then(|r| r.create())
            .and_then(|r| r.restrict_self());

        match result {
            Ok(status) => match status.landlock {
                LandlockStatus::Available { .. } => 0,
                LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => 1,
            },
            Err(_) => 2,
        }
    });

    match outcome {
        Ok(0) => PrimitiveStatus::Ok,
        Ok(1) => PrimitiveStatus::Unavailable {
            reason: "kernel does not support Landlock (pre-5.13, or disabled at build time)".into(),
        },
        Ok(_) => PrimitiveStatus::Unavailable {
            reason: "Landlock probe ruleset failed to build or apply".into(),
        },
        Err(e) => PrimitiveStatus::Unavailable {
            reason: format!("probe fork failed: {e}"),
        },
    }
}

pub enum LandlockOutcome {
    Enforced,
    Unsupported {
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
#[error("failed to build or apply Landlock ruleset: {0}")]
pub struct LandlockApplyError(String);

pub fn restrict_to_root() -> Result<LandlockOutcome, LandlockApplyError> {
    let access = AccessFs::from_all(ABI::V1);
    let result = Ruleset::default()
        .handle_access(access)
        .and_then(|r| r.create())
        .and_then(|r| r.add_rules(path_beneath_rules(["/"], access)))
        .and_then(|r| r.restrict_self())
        .map_err(|e| LandlockApplyError(e.to_string()))?;

    match result.landlock {
        LandlockStatus::Available { .. } => Ok(LandlockOutcome::Enforced),
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => {
            Ok(LandlockOutcome::Unsupported {
                reason: "kernel does not support Landlock (pre-5.13, or disabled at build time)"
                    .into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::syscalls::run_probe_in_child;

    #[test]
    fn probe_runs_to_completion() {
        let status = probe();
        println!("landlock::probe: {status}");
        assert!(matches!(
            status,
            PrimitiveStatus::Ok | PrimitiveStatus::Unavailable { .. }
        ));
    }

    #[test]
    fn restrict_to_root_builds_and_applies_in_a_throwaway_child() {
        let outcome = run_probe_in_child(|| match restrict_to_root() {
            Ok(LandlockOutcome::Enforced) => 0,
            Ok(LandlockOutcome::Unsupported { .. }) => 1,
            Err(_) => 2,
        });
        let code = outcome.expect("probe fork itself should succeed");
        println!("landlock::restrict_to_root (in throwaway child): exit code {code}");
        assert!(
            code == 0 || code == 1,
            "restrict_to_root should not error outright on this kernel"
        );
    }
}

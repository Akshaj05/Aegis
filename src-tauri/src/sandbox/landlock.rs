//! Landlock ABI probing, via the `landlock` crate's safe API — no
//! `unsafe` needed in this module itself (docs/CLAUDE.md: `unsafe`
//! confined to `sandbox/syscalls.rs`). See `docs/architecture.md` §15.2.
//!
//! The crate deliberately keeps its raw "what ABI does this kernel
//! support" query private ("discouraged to compare the system's provided
//! Landlock ABI version directly" — its own docs) and instead wants
//! callers to build the ruleset they actually want and read back whether
//! it was enforced. So this probe does exactly that with a minimal
//! filesystem-access ruleset, in a throwaway forked child (`run_probe_in_child`,
//! from `syscalls.rs`) — actually restricting the *current* process would
//! be a real, unwanted side effect for a mere capability check.
//!
//! [`restrict_to_root`] applies a real ruleset — but a permissive one:
//! it grants every filesystem access right beneath `/` back to the
//! calling process, which (once the sandbox worker calls this after its
//! own `pivot_root`, not before — see that function's doc comment) is the
//! entire visible sandboxed tree. That makes it functionally a no-op
//! beyond what `pivot_root` already confines, for now. There's no
//! sub-path policy to encode yet (the layer model and Policy Engine that
//! would motivate one don't exist until Build order phases 3-4), so this
//! establishes the real plumbing — ruleset construction, `restrict_self`,
//! degrade-not-fail-closed on `Unsupported` — without inventing a
//! restriction policy nothing asked for. Per §15.2, an unavailable
//! Landlock is a **degrade-with-disclosure** case, not fail-closed:
//! mount-namespace isolation is the primary control, Landlock is defense
//! in depth.

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
    /// Not a failure — §15.2's "continue with disclosure" case. The
    /// caller records this as a degradation and proceeds.
    Unsupported {
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
#[error("failed to build or apply Landlock ruleset: {0}")]
pub struct LandlockApplyError(String);

/// Restricts the **calling** process to full access beneath `/` — see
/// module docs for why that's permissive rather than a real policy right
/// now. Must be called from inside the sandbox worker child **after** its
/// own `pivot_root`, never before: `/` means whatever the calling
/// process's mount namespace currently resolves it to, so calling this
/// before `pivot_root` would restrict access relative to the *host* root
/// instead of the intended sandbox root — the opposite of what this is
/// for.
///
/// Like [`apply_baseline`](crate::sandbox::seccomp::apply_baseline), this
/// permanently affects the calling process/thread going forward — it must
/// never be called from the main test process directly (see this file's
/// own test for how to call it safely: inside a disposable forked child).
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

    /// See `restrict_to_root`'s doc comment: it permanently restricts the
    /// calling process, so — like the seccomp baseline test — this must
    /// run inside a disposable forked child, never the real test process.
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

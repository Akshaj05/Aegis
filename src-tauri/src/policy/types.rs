//! Core policy vocabulary: `Category`, `Verdict`, `RiskLevel`,
//! `SupportTier`, `ReasonCode`, `PolicyDecision`. See `docs/architecture.md`
//! §4.1, §19.1, §20, §42.

use std::fmt;

use serde::{Deserialize, Serialize};

/// §4.1's three categories every parsed command resolves into — but see
/// [`Verdict::RejectUnsupported`] for why a command can also resolve into
/// neither, when it isn't implemented at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Safe,
    DangerousContainable,
    UnsafeToContain,
}

/// Added in Build order phase 9, alongside `SupportTier`'s: both were
/// computed by `record_policy_decision` but never actually persisted to
/// the `transactions.category`/`transactions.support_tier` columns —
/// `db::transaction_queries::update_transaction_policy_fields` existed
/// since phase 5 and was simply never called. Closed while wiring the
/// equivalent, adjacent `update_transaction_ai_fields` gap for real AI
/// data (see `transaction::manager`'s doc comment).
impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Category::Safe => "safe",
            Category::DangerousContainable => "dangerous_containable",
            Category::UnsafeToContain => "unsafe_to_contain",
        };
        write!(f, "{s}")
    }
}

/// §42's illustrative sketch shows three variants (`Allow`,
/// `RequireApproval`, `Deny`). This adds a fourth,
/// [`Verdict::RejectUnsupported`], because docs/CLAUDE.md invariant #3 is
/// explicit that UNSUPPORTED and DENIED must be "different enum
/// variants" — not two names for the same outcome, and not folded into
/// `Deny` — and §20.1 step 2 (support-tier resolution) is its own
/// short-circuit before containment rules or risk classification ever
/// run. Same kind of deliberate, documented deviation from illustrative
/// Rust as `snapshot/backend.rs`'s `LayerStack` parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    RequireApproval,
    Deny,
    /// "Not implemented in SafeShell" — never audited or rendered as a
    /// security denial (§19.1). Distinct from `Deny` at the type level so
    /// no downstream code can accidentally treat the two the same way.
    RejectUnsupported,
}

/// `Serialize`/`Deserialize` (`snake_case`, e.g. `"high"`) were added in
/// Build order phase 9: `ai::schema::AiPlan` reuses this type directly
/// for its own `risk_level` field rather than defining a second, parallel
/// enum (see that module's doc comment) — serde's derived enum
/// deserialization already rejects any string outside the four variants
/// here, which is exactly §21.7's "enum-constrained fields... rejected,
/// never coerced" requirement, with no hand-written validation needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// One step up, per §20.5's scope-escalation rule ("escalates one
    /// level... can never move it to Deny, and can never de-escalate").
    /// Saturates at `Critical` rather than erroring — there is no level
    /// above it to escalate to.
    pub fn escalate_one_level(self) -> Self {
        match self {
            RiskLevel::Low => RiskLevel::Medium,
            RiskLevel::Medium => RiskLevel::High,
            RiskLevel::High | RiskLevel::Critical => RiskLevel::Critical,
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

/// §19.1's four support tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportTier {
    Supported,
    PartiallySupported,
    Unsupported,
    /// The command *name itself* always names a containment-boundary
    /// operation (e.g. invoking a shell) — distinct from a per-invocation
    /// `Deny` computed by containment rules for an otherwise-supported
    /// command used in a boundary-violating way (§19's own distinction).
    Denied,
}

impl fmt::Display for SupportTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SupportTier::Supported => "supported",
            SupportTier::PartiallySupported => "partially_supported",
            SupportTier::Unsupported => "unsupported",
            SupportTier::Denied => "denied",
        };
        write!(f, "{s}")
    }
}

/// §20.3's exhaustive reason-code list. Adding a variant is a deliberate
/// architectural change (docs/CLAUDE.md: "Adding a new DENY reason is an
/// architectural change; do not add one to make a test pass"), not a
/// routine edit — this enum is exactly the nine codes the architecture
/// names, no more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    DenyHostPathAccess,
    DenySandboxEscapeAttempt,
    DenyHostProcessManipulation,
    DenySandboxWeakening,
    DenyRequiresHostPrivilege,
    DenyUnsimulatable,
    DenyNoRecoveryGuarantee,
    DenyCapabilityUnavailable,
    DenyShellInvocation,
}

impl ReasonCode {
    /// Canonical, deterministic human-readable text — "derived from the
    /// code, never the source of truth" (docs/CLAUDE.md code
    /// conventions). This is what's shown in the UI *before* any AI
    /// rendering, and always shown alongside it (§21.5) — an AI failure
    /// must never leave a DENY unexplained.
    pub fn canonical_text(self) -> &'static str {
        match self {
            ReasonCode::DenyHostPathAccess => "This operation names or would resolve to a path outside the SafeShell environment.",
            ReasonCode::DenySandboxEscapeAttempt => "This operation attempts to escape the SafeShell environment's namespace or mount boundary.",
            ReasonCode::DenyHostProcessManipulation => "This operation targets a process outside the SafeShell environment's process namespace.",
            ReasonCode::DenySandboxWeakening => "This operation would modify or disable a security control that SafeShell's containment guarantee depends on.",
            ReasonCode::DenyRequiresHostPrivilege => "This operation requires a host capability SafeShell cannot safely provide.",
            ReasonCode::DenyUnsimulatable => "This operation is outside SafeShell's supported execution model and cannot be safely simulated or contained.",
            ReasonCode::DenyNoRecoveryGuarantee => "SafeShell cannot provide the required isolation or recovery guarantee for this operation in the current configuration.",
            ReasonCode::DenyCapabilityUnavailable => "A required security capability is unavailable in this session.",
            ReasonCode::DenyShellInvocation => "This operation attempts to invoke a general-purpose shell or interpreter, which SafeShell does not provide.",
        }
    }

    /// Inverse of [`Display`](fmt::Display): recovers the enum from the
    /// exact string `transaction::manager::record_policy_decision`
    /// persists into `transactions.policy_reason_codes` (a JSON array of
    /// `Display` strings, since `db/` takes primitives, never `policy/`
    /// types — see `db/transaction_queries.rs`'s module doc). Added in
    /// Build order phase 10 so the IPC detail/DENY-panel assembly can
    /// recover `canonical_text()` for a persisted reason code without
    /// `db/` needing to import `policy/` types to store something richer.
    pub fn from_code_str(s: &str) -> Option<Self> {
        match s {
            "DENY_HOST_PATH_ACCESS" => Some(ReasonCode::DenyHostPathAccess),
            "DENY_SANDBOX_ESCAPE_ATTEMPT" => Some(ReasonCode::DenySandboxEscapeAttempt),
            "DENY_HOST_PROCESS_MANIPULATION" => Some(ReasonCode::DenyHostProcessManipulation),
            "DENY_SANDBOX_WEAKENING" => Some(ReasonCode::DenySandboxWeakening),
            "DENY_REQUIRES_HOST_PRIVILEGE" => Some(ReasonCode::DenyRequiresHostPrivilege),
            "DENY_UNSIMULATABLE" => Some(ReasonCode::DenyUnsimulatable),
            "DENY_NO_RECOVERY_GUARANTEE" => Some(ReasonCode::DenyNoRecoveryGuarantee),
            "DENY_CAPABILITY_UNAVAILABLE" => Some(ReasonCode::DenyCapabilityUnavailable),
            "DENY_SHELL_INVOCATION" => Some(ReasonCode::DenyShellInvocation),
            _ => None,
        }
    }
}

#[cfg(test)]
mod reason_code_round_trip_tests {
    use super::*;

    #[test]
    fn every_reason_code_round_trips_through_its_display_string() {
        let all = [
            ReasonCode::DenyHostPathAccess,
            ReasonCode::DenySandboxEscapeAttempt,
            ReasonCode::DenyHostProcessManipulation,
            ReasonCode::DenySandboxWeakening,
            ReasonCode::DenyRequiresHostPrivilege,
            ReasonCode::DenyUnsimulatable,
            ReasonCode::DenyNoRecoveryGuarantee,
            ReasonCode::DenyCapabilityUnavailable,
            ReasonCode::DenyShellInvocation,
        ];
        for code in all {
            assert_eq!(ReasonCode::from_code_str(&code.to_string()), Some(code));
        }
        assert_eq!(ReasonCode::from_code_str("NOT_A_REAL_CODE"), None);
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ReasonCode::DenyHostPathAccess => "DENY_HOST_PATH_ACCESS",
            ReasonCode::DenySandboxEscapeAttempt => "DENY_SANDBOX_ESCAPE_ATTEMPT",
            ReasonCode::DenyHostProcessManipulation => "DENY_HOST_PROCESS_MANIPULATION",
            ReasonCode::DenySandboxWeakening => "DENY_SANDBOX_WEAKENING",
            ReasonCode::DenyRequiresHostPrivilege => "DENY_REQUIRES_HOST_PRIVILEGE",
            ReasonCode::DenyUnsimulatable => "DENY_UNSIMULATABLE",
            ReasonCode::DenyNoRecoveryGuarantee => "DENY_NO_RECOVERY_GUARANTEE",
            ReasonCode::DenyCapabilityUnavailable => "DENY_CAPABILITY_UNAVAILABLE",
            ReasonCode::DenyShellInvocation => "DENY_SHELL_INVOCATION",
        };
        write!(f, "{s}")
    }
}

/// The Policy Engine's output for one parsed command. See
/// `docs/architecture.md` §20 (opening code block) — `category` and
/// `risk_level` are `Option` here (a deviation from that illustrative
/// sketch, same justification as `Verdict::RejectUnsupported`): both are
/// meaningless when `verdict == RejectUnsupported`, since the command
/// never reached categorization or risk classification at all (§20.1 step
/// 2 short-circuits before either runs). `None` makes that structurally
/// impossible to read past by accident, rather than documenting "ignore
/// this field sometimes."
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub support_tier: SupportTier,
    pub verdict: Verdict,
    pub category: Option<Category>,
    pub risk_level: Option<RiskLevel>,
    pub reason_codes: Vec<ReasonCode>,
    pub reasons: Vec<String>,
}

impl PolicyDecision {
    /// Whether this decision requires an explicit user approval pause
    /// before proceeding (§12: `DIFF_READY -> WAITING_FOR_APPROVAL`).
    pub fn requires_approval(&self) -> bool {
        self.verdict == Verdict::RequireApproval
    }
}

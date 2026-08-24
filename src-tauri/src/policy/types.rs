// Core policy vocabulary types: Category, Verdict, RiskLevel, SupportTier,
// ReasonCode, and PolicyDecision.

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Safe,
    DangerousContainable,
    UnsafeToContain,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    RequireApproval,
    Deny,

    RejectUnsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportTier {
    Supported,
    PartiallySupported,
    Unsupported,

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

    pub fn requires_approval(&self) -> bool {
        self.verdict == Verdict::RequireApproval
    }
}

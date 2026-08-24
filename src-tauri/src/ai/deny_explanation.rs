// Renders grounded DENY explanations that always pair a deterministic
// reason code's canonical text with an optional AI-generated gloss,
// validating any AI rendering before it can be attached.

use crate::policy::ReasonCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundedDenyExplanation {
    pub reason_code: ReasonCode,
    pub canonical_text: &'static str,
    pub ai_rendering: Option<String>,
}

impl GroundedDenyExplanation {
    pub fn canonical_only(reason_code: ReasonCode) -> Self {
        GroundedDenyExplanation {
            reason_code,
            canonical_text: reason_code.canonical_text(),
            ai_rendering: None,
        }
    }

    pub fn with_validated_ai_rendering(reason_code: ReasonCode, ai_rendering: String) -> Self {
        GroundedDenyExplanation {
            reason_code,
            canonical_text: reason_code.canonical_text(),
            ai_rendering: Some(ai_rendering),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DenyExplanationError {
    #[error("AI rendering is empty")]
    Empty,
    #[error("AI rendering exceeds the maximum length for a DENY gloss")]
    TooLong,
}

pub fn validate_ai_rendering(raw: &str) -> Result<String, DenyExplanationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DenyExplanationError::Empty);
    }
    const MAX_LEN: usize = 2000;
    if trimmed.len() > MAX_LEN {
        return Err(DenyExplanationError::TooLong);
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_only_never_has_an_ai_rendering() {
        let explanation = GroundedDenyExplanation::canonical_only(ReasonCode::DenyShellInvocation);
        assert!(explanation.ai_rendering.is_none());
        assert_eq!(
            explanation.canonical_text,
            ReasonCode::DenyShellInvocation.canonical_text()
        );
    }

    #[test]
    fn validated_ai_rendering_still_carries_the_canonical_text_alongside() {
        let rendered = validate_ai_rendering("This blocks shell invocation.").unwrap();
        let explanation = GroundedDenyExplanation::with_validated_ai_rendering(
            ReasonCode::DenyShellInvocation,
            rendered,
        );
        assert!(explanation.ai_rendering.is_some());
        assert_eq!(
            explanation.canonical_text,
            ReasonCode::DenyShellInvocation.canonical_text(),
            "the canonical text must never be displaced by an AI rendering"
        );
    }

    #[test]
    fn empty_ai_rendering_is_rejected() {
        assert_eq!(
            validate_ai_rendering("   "),
            Err(DenyExplanationError::Empty)
        );
    }

    #[test]
    fn an_overlong_ai_rendering_is_rejected() {
        let too_long = "x".repeat(2001);
        assert_eq!(
            validate_ai_rendering(&too_long),
            Err(DenyExplanationError::TooLong)
        );
    }

    #[test]
    fn every_reason_code_has_nonempty_canonical_text() {
        for code in [
            ReasonCode::DenyHostPathAccess,
            ReasonCode::DenySandboxEscapeAttempt,
            ReasonCode::DenyHostProcessManipulation,
            ReasonCode::DenySandboxWeakening,
            ReasonCode::DenyRequiresHostPrivilege,
            ReasonCode::DenyUnsimulatable,
            ReasonCode::DenyNoRecoveryGuarantee,
            ReasonCode::DenyCapabilityUnavailable,
            ReasonCode::DenyShellInvocation,
        ] {
            let explanation = GroundedDenyExplanation::canonical_only(code);
            assert!(!explanation.canonical_text.is_empty());
        }
    }
}

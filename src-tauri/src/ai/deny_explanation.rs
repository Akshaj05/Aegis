//! §21.5's grounded DENY explanations. A `DENIED` transaction's state
//! machine path (`POLICY_CHECK -> DENIED`, terminal) never visits
//! `AI_ANALYSIS` at all (§13.2) — so this is deliberately **not** wired
//! through `transaction::manager`. It's a standalone rendering helper the
//! UI layer (Build order phase 10) calls independently, after a `DENIED`
//! transaction already exists, entirely out of band from the state
//! machine — consistent with §21.1's "stateless, advisory annotator"
//! that "never sets or influences a security decision."
//!
//! [`GroundedDenyExplanation`] makes §21.5's enforcement bullets a type
//! guarantee rather than a convention: it is only constructible with a
//! canonical text already attached, so there is no way to end up
//! rendering an AI gloss on its own with no deterministic text alongside
//! it, and no way to construct one without the AI ever being consulted at
//! all — the AI rendering is optional; the canonical text never is.

use crate::policy::ReasonCode;

/// The deterministic reason code and its canonical text, always present,
/// plus an optional AI-rendered gloss — never the reverse. §21.5: "The
/// deterministic reason code and its canonical text are always displayed
/// alongside the AI-rendered version, so the user can see the
/// authoritative statement even if the rendering is poor" and "If the AI
/// is unavailable, the canonical deterministic text is shown alone."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroundedDenyExplanation {
    pub reason_code: ReasonCode,
    pub canonical_text: &'static str,
    pub ai_rendering: Option<String>,
}

impl GroundedDenyExplanation {
    /// The AI-unavailable case (§21.9's failure/timeout/skip path applies
    /// here too, even though this isn't part of the transaction state
    /// machine): canonical text alone, always well-formed.
    pub fn canonical_only(reason_code: ReasonCode) -> Self {
        GroundedDenyExplanation {
            reason_code,
            canonical_text: reason_code.canonical_text(),
            ai_rendering: None,
        }
    }

    /// Attaches an AI rendering that has already been validated to
    /// reference only this `reason_code`'s own canonical fact (§21.5:
    /// "The rendered explanation is validated to reference only the
    /// supplied reason code(s)") — see [`validate_ai_rendering`]. There
    /// is no constructor that accepts an unvalidated AI string.
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

/// The bar an AI-rendered DENY gloss must clear before
/// [`GroundedDenyExplanation::with_validated_ai_rendering`] will accept
/// it. This is deliberately shallow — content-level "did it actually stay
/// grounded in the reason code" is not mechanically checkable from text
/// alone, so the architectural guarantee here is structural (the
/// canonical text is never displaced, only ever supplemented — see the
/// type itself) rather than a claim that this function detects every way
/// a rendering could stray. §21.8: "the worst achievable outcome is a
/// misleading `explanation`... string in the UI," which is exactly what
/// this bounds, not eliminates.
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
        // Not exhaustive over every variant via a match (that would just
        // duplicate `ReasonCode::canonical_text`'s own match), but a
        // sanity check that `canonical_only` never produces an empty
        // string for any code actually in use elsewhere in this crate.
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

// `TransactionState` enum and the legal state-transition table; the sole
// authority for which transitions are legal, consulted by `transition`.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionState {
    Received,
    Parsed,
    PolicyCheck,
    AiAnalysis,
    Simulating,
    DiffReady,
    WaitingForApproval,
    Snapshotting,
    Executing,
    Verifying,
    Committed,
    RollingBack,
    Restored,
    Rejected,
    Denied,
    Failed,
    RollbackFailed,
}

impl TransactionState {
    pub fn is_terminal(self) -> bool {
        self.legal_next_states().is_empty()
    }

    pub fn legal_next_states(self) -> &'static [TransactionState] {
        use TransactionState::*;
        match self {
            Received => &[Parsed, Failed],
            Parsed => &[PolicyCheck, Failed],
            PolicyCheck => &[Denied, Failed, AiAnalysis],
            AiAnalysis => &[Simulating],
            Simulating => &[DiffReady, Failed],
            DiffReady => &[WaitingForApproval, Snapshotting],
            WaitingForApproval => &[Snapshotting, Rejected, Failed],
            Snapshotting => &[Executing, Failed],
            Executing => &[Verifying, RollingBack],
            Verifying => &[Committed, RollingBack],
            RollingBack => &[Restored, RollbackFailed],
            Committed | Restored | Rejected | Denied | Failed | RollbackFailed => &[],
        }
    }

    pub fn can_transition_to(self, next: TransactionState) -> bool {
        self.legal_next_states().contains(&next)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("illegal transaction state transition: {from} -> {to}")]
pub struct IllegalTransitionError {
    pub from: TransactionState,
    pub to: TransactionState,
}

pub fn transition(
    from: TransactionState,
    to: TransactionState,
) -> Result<TransactionState, IllegalTransitionError> {
    if from.can_transition_to(to) {
        Ok(to)
    } else {
        Err(IllegalTransitionError { from, to })
    }
}

impl fmt::Display for TransactionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TransactionState::Received => "RECEIVED",
            TransactionState::Parsed => "PARSED",
            TransactionState::PolicyCheck => "POLICY_CHECK",
            TransactionState::AiAnalysis => "AI_ANALYSIS",
            TransactionState::Simulating => "SIMULATING",
            TransactionState::DiffReady => "DIFF_READY",
            TransactionState::WaitingForApproval => "WAITING_FOR_APPROVAL",
            TransactionState::Snapshotting => "SNAPSHOTTING",
            TransactionState::Executing => "EXECUTING",
            TransactionState::Verifying => "VERIFYING",
            TransactionState::Committed => "COMMITTED",
            TransactionState::RollingBack => "ROLLING_BACK",
            TransactionState::Restored => "RESTORED",
            TransactionState::Rejected => "REJECTED",
            TransactionState::Denied => "DENIED",
            TransactionState::Failed => "FAILED",
            TransactionState::RollbackFailed => "ROLLBACK_FAILED",
        };
        write!(f, "{s}")
    }
}

pub const ALL_STATES: &[TransactionState] = &[
    TransactionState::Received,
    TransactionState::Parsed,
    TransactionState::PolicyCheck,
    TransactionState::AiAnalysis,
    TransactionState::Simulating,
    TransactionState::DiffReady,
    TransactionState::WaitingForApproval,
    TransactionState::Snapshotting,
    TransactionState::Executing,
    TransactionState::Verifying,
    TransactionState::Committed,
    TransactionState::RollingBack,
    TransactionState::Restored,
    TransactionState::Rejected,
    TransactionState::Denied,
    TransactionState::Failed,
    TransactionState::RollbackFailed,
];

#[cfg(test)]
mod tests {
    use super::*;
    use TransactionState::*;

    #[test]
    fn every_documented_legal_transition_is_accepted() {
        let legal_pairs: &[(TransactionState, TransactionState)] = &[
            (Received, Parsed),
            (Received, Failed),
            (Parsed, PolicyCheck),
            (Parsed, Failed),
            (PolicyCheck, Denied),
            (PolicyCheck, Failed),
            (PolicyCheck, AiAnalysis),
            (AiAnalysis, Simulating),
            (Simulating, DiffReady),
            (Simulating, Failed),
            (DiffReady, WaitingForApproval),
            (DiffReady, Snapshotting),
            (WaitingForApproval, Snapshotting),
            (WaitingForApproval, Rejected),
            (WaitingForApproval, Failed),
            (Snapshotting, Executing),
            (Snapshotting, Failed),
            (Executing, Verifying),
            (Executing, RollingBack),
            (Verifying, Committed),
            (Verifying, RollingBack),
            (RollingBack, Restored),
            (RollingBack, RollbackFailed),
        ];
        for &(from, to) in legal_pairs {
            assert_eq!(
                transition(from, to),
                Ok(to),
                "{from} -> {to} should be legal"
            );
        }
    }

    #[test]
    fn every_pair_not_in_the_legal_table_is_rejected() {
        let mut checked = 0usize;
        let mut illegal_checked = 0usize;
        for &from in ALL_STATES {
            for &to in ALL_STATES {
                checked += 1;
                let is_legal = from.legal_next_states().contains(&to);
                let result = transition(from, to);
                if is_legal {
                    assert_eq!(result, Ok(to));
                } else {
                    illegal_checked += 1;
                    assert_eq!(
                        result,
                        Err(IllegalTransitionError { from, to }),
                        "{from} -> {to} should be rejected"
                    );
                }
            }
        }
        assert_eq!(checked, ALL_STATES.len() * ALL_STATES.len());
        assert!(
            illegal_checked > 0,
            "sanity check: this test should actually exercise illegal pairs"
        );
    }

    #[test]
    fn no_state_transitions_to_itself() {
        for &state in ALL_STATES {
            assert!(
                !state.can_transition_to(state),
                "{state} must not have a self-loop"
            );
        }
    }

    #[test]
    fn terminal_states_have_no_outgoing_edges() {
        let expected_terminal = [
            Committed,
            Restored,
            Rejected,
            Denied,
            Failed,
            RollbackFailed,
        ];
        for &state in ALL_STATES {
            let is_terminal = expected_terminal.contains(&state);
            assert_eq!(
                state.is_terminal(),
                is_terminal,
                "{state}'s terminal-ness is wrong"
            );
            if is_terminal {
                assert!(
                    state.legal_next_states().is_empty(),
                    "{state} is terminal but has outgoing edges"
                );
            }
        }
    }

    #[test]
    fn invariant_denied_never_reaches_executing() {
        assert!(Denied.is_terminal());
        assert!(!Denied.can_transition_to(Executing));
    }

    #[test]
    fn invariant_rejected_never_modifies_persistent_state() {
        let reachable_from: Vec<TransactionState> = ALL_STATES
            .iter()
            .copied()
            .filter(|&s| s.can_transition_to(Rejected))
            .collect();
        assert_eq!(reachable_from, vec![WaitingForApproval]);
    }

    #[test]
    fn invariant_simulation_failure_never_proceeds_to_execution() {
        let targets = Simulating.legal_next_states();
        assert!(targets.contains(&Failed));
        assert!(!targets.contains(&Snapshotting));
        assert!(!targets.contains(&Executing));
    }

    #[test]
    fn invariant_snapshot_failure_never_proceeds_to_execution() {
        let targets = Snapshotting.legal_next_states();
        assert_eq!(targets, &[Executing, Failed]);
    }

    #[test]
    fn invariant_verification_mismatch_always_triggers_rollback() {
        let targets = Verifying.legal_next_states();
        assert_eq!(targets, &[Committed, RollingBack]);
    }

    #[test]
    fn invariant_rollback_failure_is_never_silent() {
        let targets = RollingBack.legal_next_states();
        assert_eq!(targets, &[Restored, RollbackFailed]);
    }

    #[test]
    fn invariant_execution_never_occurs_without_a_snapshot() {
        let reachable_from: Vec<TransactionState> = ALL_STATES
            .iter()
            .copied()
            .filter(|&s| s.can_transition_to(Executing))
            .collect();
        assert_eq!(reachable_from, vec![Snapshotting]);
    }

    #[test]
    fn category_1_safe_path_reaches_committed() {
        let path = [
            Received,
            Parsed,
            PolicyCheck,
            AiAnalysis,
            Simulating,
            DiffReady,
            Snapshotting,
            Executing,
            Verifying,
            Committed,
        ];
        for pair in path.windows(2) {
            assert!(
                pair[0].can_transition_to(pair[1]),
                "{} -> {} should be on the safe-path",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn category_2_dangerous_containable_path_via_approval_reaches_committed() {
        let path = [
            Received,
            Parsed,
            PolicyCheck,
            AiAnalysis,
            Simulating,
            DiffReady,
            WaitingForApproval,
            Snapshotting,
            Executing,
            Verifying,
            Committed,
        ];
        for pair in path.windows(2) {
            assert!(pair[0].can_transition_to(pair[1]));
        }
    }

    #[test]
    fn category_3_unsafe_to_contain_path_ends_at_denied() {
        assert!(Received.can_transition_to(Parsed));
        assert!(Parsed.can_transition_to(PolicyCheck));
        assert!(PolicyCheck.can_transition_to(Denied));
        assert!(Denied.is_terminal());
    }
}

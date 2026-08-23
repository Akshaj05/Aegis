//! `ApprovedExecutionToken` — the type that makes §13.3's "`DENIED` never
//! reaches `EXECUTING`" and "execution never occurs without a snapshot"
//! invariants structural rather than a convention someone could
//! accidentally violate.
//!
//! Per §24 and docs/CLAUDE.md invariant #11: this type is constructible
//! **only** inside `transaction/`, on the `SNAPSHOTTING -> EXECUTING`
//! edge. No public constructor, no `Default`, no test helper that
//! bypasses this — enforced here by giving the constructor `pub(super)`
//! visibility (callable only from `transaction/`, i.e. `manager.rs`) while
//! the type and its read accessors are `pub` (so `executor/`, once it
//! exists in Build order phase 6-7, can accept one as a parameter and read
//! it, but never build one itself).

use crate::snapshot::backend::CheckpointId;
use crate::transaction::manager::TransactionId;

#[derive(Debug, Clone, Copy)]
pub struct ApprovedExecutionToken {
    transaction_id: TransactionId,
    checkpoint_id: CheckpointId,
}

impl ApprovedExecutionToken {
    /// `pub(super)`: only `transaction/`'s own modules (concretely,
    /// `manager.rs`'s `SNAPSHOTTING -> EXECUTING` transition method) can
    /// call this. Everything outside `transaction/` — including
    /// `executor/`, `policy/`, and `ai/` — can only ever *receive* a
    /// token that already exists, never mint one.
    pub(super) fn new(transaction_id: TransactionId, checkpoint_id: CheckpointId) -> Self {
        ApprovedExecutionToken {
            transaction_id,
            checkpoint_id,
        }
    }

    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    pub fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::manager::TransactionId;
    use ulid::Ulid;

    #[test]
    fn token_carries_the_transaction_and_checkpoint_it_was_built_from() {
        // This test lives inside `transaction/` itself, so it can call
        // the pub(super) constructor — that's expected and fine. The
        // invariant this type exists to enforce is that code *outside*
        // `transaction/` cannot do the same; there is no test that can
        // positively demonstrate "this fails to compile" from within a
        // passing test suite, so that half of the guarantee rests on
        // `pub(super)` itself, checked by `cargo check` on every future
        // change to `executor/`, not by a runtime assertion here.
        let txn_id = TransactionId::new();
        let checkpoint_id = CheckpointId(Ulid::new());
        let token = ApprovedExecutionToken::new(txn_id, checkpoint_id);
        assert_eq!(token.transaction_id(), txn_id);
        assert_eq!(token.checkpoint_id(), checkpoint_id);
    }
}

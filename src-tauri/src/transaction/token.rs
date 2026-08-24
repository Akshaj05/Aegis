// `ApprovedExecutionToken` — proof that a transaction legally reached
// EXECUTING via a sealed snapshot; constructible only within `transaction/`.

use crate::snapshot::backend::CheckpointId;
use crate::transaction::manager::TransactionId;

#[derive(Debug, Clone, Copy)]
pub struct ApprovedExecutionToken {
    transaction_id: TransactionId,
    checkpoint_id: CheckpointId,
}

impl ApprovedExecutionToken {
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
        let txn_id = TransactionId::new();
        let checkpoint_id = CheckpointId(Ulid::new());
        let token = ApprovedExecutionToken::new(txn_id, checkpoint_id);
        assert_eq!(token.transaction_id(), txn_id);
        assert_eq!(token.checkpoint_id(), checkpoint_id);
    }
}

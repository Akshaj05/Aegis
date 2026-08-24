// Transaction module root: the transaction state machine, its event types,
// the transaction manager, and the approved-execution token.

pub mod events;
pub mod manager;
pub mod state;
pub mod token;

pub use events::{EventSink, EventStatus, TransactionEvent};
pub use manager::{Transaction, TransactionError, TransactionId};
pub use state::TransactionState;
pub use token::ApprovedExecutionToken;

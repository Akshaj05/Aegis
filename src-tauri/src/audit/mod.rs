//! Append-only, hash-chained audit log. See `docs/architecture.md` §35.
//!
//! Implemented alongside the Transaction Manager (Build order phase 5): every
//! security-relevant decision writes an audit row, and if the write fails the
//! transaction does not advance (docs/CLAUDE.md invariant list).

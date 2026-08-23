//! `SimulationBackend` trait (OverlayFS / fuse-overlayfs / copy-up) and
//! layer-stack lifecycle management. See `docs/architecture.md` §14.4,
//! §23.
//!
//! Build order phase 3 ("layer model"), scoped to stack lifecycle
//! (create/seal/discard/restore/size) across all three backends — see
//! `backend.rs`'s module doc for what's deliberately deferred to later
//! phases (a merged read/write API, retention policy, dependency-aware
//! GC).
//!
//! Only `copyup.rs` is fully real-tested in this project's development
//! environment: it's pure directory operations, needing no kernel or FUSE
//! support. `overlayfs.rs` and `fuse_overlay.rs` are honestly
//! unverified past "the self-test correctly detects unavailability" —
//! `overlay` isn't a registered filesystem here and `fuse-overlayfs` isn't
//! installed. See each module's own doc comment for specifics.
//!
//! `retention.rs` — real retention policy and dependency-aware GC
//! (§23.3-§23.4), including the squash-merge algorithm flagged all the way
//! back at the initial repo scaffold as algorithmically delicate. See that
//! module's doc comment for why it's tractable now and what changes once
//! deletion handlers exist.
//!
//! `backend.rs`'s `SimulationBackend::restore_to` now takes
//! `Option<CheckpointId>` rather than the bare `CheckpointId` earlier
//! phases shipped — `rollback/`'s "Undo Last Transaction" needs to express
//! "no checkpoint remains," which the old signature couldn't say. See that
//! trait method's own doc comment.

pub mod backend;
pub mod copyup;
pub mod fuse_overlay;
pub mod overlayfs;
pub mod retention;

//! The real end-to-end command pipeline: parse → policy → AI (advisory) →
//! simulate → diff → approve → snapshot → execute → verify →
//! commit | rollback (§12). Not named in `docs/architecture.md` §40's
//! repository structure — that document's `ipc/` doc comment ("Thin,
//! typed Tauri command handlers; delegate immediately, no logic of their
//! own") implies *something* holds the logic they delegate to, without
//! naming it. Every other candidate module is scoped to one pipeline
//! stage (`policy/`, `simulation/`, `executor/`, `verification/`,
//! `rollback/`, `transaction/` itself only encodes the state machine, not
//! what produces each stage's input) — driving a real command through all
//! of them, and holding the live, per-session runtime state
//! (`TerminalSession`, `LayerStack`, a selected `SimulationBackend`, a
//! paused approval waiting to be resumed) that no single stage module
//! owns, is genuinely Build order phase 10's own work, not a gap in an
//! earlier phase. `tests/verification_tolerance_tests/harness.rs`
//! (Build order phase 8) is this module's direct ancestor: same real
//! pipeline, driven by hand in one test file rather than exposed as a
//! reusable, resumable API two IPC commands (`submit_command` and
//! `approve_transaction`/`reject_transaction`) can share.
//!
//! **Why "resumable" is the hard part**: §13.2 has `DIFF_READY ->
//! WAITING_FOR_APPROVAL`, and the *next* legal edge
//! (`WAITING_FOR_APPROVAL -> SNAPSHOTTING`) only fires once a human calls
//! `approve_transaction` — arbitrarily far in wall-clock time later, via a
//! *separate* Tauri IPC call with no arguments but a transaction id. So
//! [`submit_command`] cannot simply run the pipeline to completion in one
//! call the way `harness.rs`'s `run_pipeline` does: when a decision
//! requires approval, it must suspend with enough state to resume —
//! [`PendingApproval`], parked on the session that submitted it — and
//! return early. [`run_to_completion`] is the shared tail
//! (snapshot → execute → verify → commit/rollback) both the
//! no-approval-needed fast path and `approve_transaction`'s resume call
//! into, so the two paths can never drift into different pipelines.
//!
//! **MVP scope limits, stated plainly rather than silently assumed**:
//! only the first `;`/`&&`-separated segment of a parsed command line is
//! ever run — `handlers::dispatch` itself only executes one
//! `ParsedCommand` at a time (see its module doc), and no code anywhere
//! in this crate, including this module, sequences multiple segments yet.
//! `interrupt_command` cannot cancel a command genuinely mid-execution —
//! every handler in `handlers/` runs synchronously to completion before
//! any IPC call could reach this module again, so the only state this
//! crate can actually interrupt is a paused `WAITING_FOR_APPROVAL`, which
//! is what it does.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde_json::json;
use ulid::Ulid;

use crate::ai::backend::AiBackend;
use crate::ai::schema::AiRequest;
use crate::db::session_queries::{NewSession, SessionRow};
use crate::db::transaction_queries::{
    ExecutionResultRow, TransactionEventRow, TransactionSummaryRow,
};
use crate::db::Database;
use crate::executor;
use crate::parser::{self, ParsedCommand};
use crate::policy::risk::SimulationDiffStats;
use crate::policy::{self, Category, PolicyEngine, ReasonCode, Verdict};
use crate::rollback::{self, RollbackOutcome};
use crate::sandbox::backend::CapabilityReport;
use crate::sandbox::preflight::PreflightCapabilityChecker;
use crate::session::{SessionId, TerminalSession};
use crate::simulation::diff::SimulationDiff;
use crate::simulation::manager as sim_manager;
use crate::snapshot::backend::{CheckpointId, LayerId, LayerStack, SimulationBackend};
use crate::snapshot::copyup::CopyUpSimulationBackend;
use crate::snapshot::retention::RetentionPolicy;
use crate::snapshot::{fuse_overlay, overlayfs};
use crate::transaction::events::EventSink;
use crate::transaction::manager::{Transaction, TransactionError};
use crate::transaction::state::TransactionState;
use crate::verification::{self, tolerance::NondeterminismAllowlist, Mismatch};

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("unknown session: {0}")]
    UnknownSession(String),
    #[error("unknown transaction: {0}")]
    UnknownTransaction(String),
    #[error("unknown or no-longer-retained checkpoint: {0}")]
    UnknownCheckpoint(String),
    #[error("transaction {0} is not currently awaiting approval")]
    NotAwaitingApproval(String),
    #[error("no recoverable checkpoint")]
    NoRecoverableCheckpoint,
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("simulation/layer error: {0}")]
    Simulation(#[from] crate::snapshot::backend::SimulationError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// §29.2's `transaction://event` payload is what `TransactionEvent::to_json`
/// already produces; this is the second, separate channel §29.2 names
/// (`terminal://output`) for the command's actual stdout/stderr/exit code
/// once execution has really happened. Kept as its own trait — not folded
/// into [`EventSink`] — because it carries different data at a different
/// point in the pipeline (only after a real `executor::execute`, never
/// after `simulation::manager::simulate`, which the terminal must never
/// display as if it were real output).
#[derive(Debug, Clone)]
pub struct TerminalOutputEvent {
    pub session_id: String,
    pub transaction_id: String,
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

pub trait TerminalOutputSink {
    fn emit(&mut self, event: &TerminalOutputEvent);
}

pub struct NullTerminalOutputSink;

impl TerminalOutputSink for NullTerminalOutputSink {
    fn emit(&mut self, _event: &TerminalOutputEvent) {}
}

#[derive(Default)]
pub struct CollectingTerminalOutputSink {
    pub events: Vec<TerminalOutputEvent>,
}

impl TerminalOutputSink for CollectingTerminalOutputSink {
    fn emit(&mut self, event: &TerminalOutputEvent) {
        self.events.push(event.clone());
    }
}

/// Everything a `WAITING_FOR_APPROVAL` transaction needs to resume once
/// `approve_transaction` arrives — parked on the session that produced it
/// rather than in some separate global table, since only one session can
/// ever own a given in-memory `TerminalSession`/`LayerStack` pair.
struct PendingApproval {
    txn: Transaction,
    parsed: ParsedCommand,
    predicted_diff: SimulationDiff,
    predicted_exit_code: i32,
}

pub struct SessionRuntime {
    pub terminal: TerminalSession,
    pub backend: Arc<dyn SimulationBackend + Send + Sync>,
    pub simulation_backend_name: &'static str,
    pub stack: LayerStack,
    pending: Option<PendingApproval>,
}

/// Shared, `Send + Sync` application state — what `main.rs` hands Tauri's
/// `.manage(...)` and every `ipc/` command reads through `tauri::State`.
pub struct AppState {
    pub db: Mutex<Database>,
    pub capability_report: CapabilityReport,
    pub policy_engine: PolicyEngine,
    pub ai_backend: Box<dyn AiBackend + Send + Sync>,
    pub sessions: Mutex<HashMap<String, SessionRuntime>>,
    pub data_dir: PathBuf,
    /// §23.3's two bounds — used both to report `get_storage_status` and,
    /// as of Build order phase 12 ("hardening... fail-closed path
    /// tests"), to actually refuse a snapshot per §24/invariant #24
    /// ("Storage ceiling reached with the minimum checkpoint set → fail
    /// closed on transactions needing a snapshot") — see
    /// `run_to_completion`'s pre-seal check. Plain data, not behind a
    /// `Mutex`: nothing in this crate reconfigures it after startup.
    pub retention_policy: RetentionPolicy,
    /// `simulated-root-image/`'s directory content (`etc/`, `home/`,
    /// `opt/`, `project/`, `tmp/`, `usr/`, `var/`) — [`create_session`]
    /// seeds each new session's `LayerStack::base` from this, per
    /// Build order phase 13 ("seed environment"). Top-level *files*
    /// alongside those directories (`nondeterministic-paths.toml`,
    /// `mock-users.json`, `mock-package-db.json`) are SafeShell's own
    /// configuration about the base image, not simulated filesystem
    /// content, and are deliberately never copied into a session's root
    /// — see [`seed_base_from_image`].
    pub base_image_path: PathBuf,
    /// §26.3's declared nondeterminism allowlist, loaded once from
    /// `base_image_path`'s `nondeterministic-paths.toml` at startup and
    /// used by every session's [`run_to_completion`] — Build order phase
    /// 13 closes a gap phase 8/10 left disclosed: `verification::verify`
    /// was always called with `NondeterminismAllowlist::empty()`, never
    /// the real base image manifest.
    pub nondeterminism_allowlist: NondeterminismAllowlist,
    /// `base_image_path`'s `mock-package-db.json`, loaded once at startup
    /// — [`create_session`] clones this into every new session's
    /// `TerminalSession::packages` (`handlers::pkg`'s `safeshell-pkg`
    /// state). See `mock_packages`'s module doc for why this file was
    /// real seed data sitting unread until now.
    pub mock_packages: Vec<crate::mock_packages::MockPackage>,
}

impl AppState {
    pub fn new(
        data_dir: PathBuf,
        policies_path: &Path,
        base_image_path: &Path,
        ai_backend: Box<dyn AiBackend + Send + Sync>,
    ) -> Result<Self, OrchestratorError> {
        let capability_report = PreflightCapabilityChecker::new().run();
        Self::new_with_capability_report(
            data_dir,
            policies_path,
            base_image_path,
            ai_backend,
            capability_report,
        )
    }

    /// Split out from [`Self::new`] so tests can supply a synthetic
    /// all-capabilities-available report instead of the real preflight
    /// probe's result. This is not a workaround for a bug: this project's
    /// own development sandbox genuinely lacks user namespaces and a
    /// delegated cgroups v2 subtree (see `sandbox/preflight.rs`'s own
    /// tests, which honestly report that), so
    /// `CapabilityReport::execution_available()` is really `false` here —
    /// correctly fail-closed per docs/CLAUDE.md invariant #19. Real
    /// end-to-end pipeline tests (does `submit_command` correctly route
    /// through simulate/approve/execute/verify) need to exercise the
    /// pipeline past `POLICY_CHECK`'s capability gate to mean anything, so
    /// they supply a fixture report the same way `policy::containment`'s
    /// own unit tests already do (`report_with(...)`), rather than either
    /// silently skipping capability gating or asserting on this
    /// environment's specific unavailability every time.
    fn new_with_capability_report(
        data_dir: PathBuf,
        policies_path: &Path,
        base_image_path: &Path,
        ai_backend: Box<dyn AiBackend + Send + Sync>,
        capability_report: CapabilityReport,
    ) -> Result<Self, OrchestratorError> {
        std::fs::create_dir_all(&data_dir)?;
        let db =
            Database::open(&data_dir.join("safeshell.db")).map_err(OrchestratorError::Database)?;
        let policy_engine = PolicyEngine::load(policies_path)
            .map_err(|e| OrchestratorError::Io(std::io::Error::other(e.to_string())))?;
        let nondeterminism_allowlist =
            NondeterminismAllowlist::load(&base_image_path.join("nondeterministic-paths.toml"))
                .map_err(|e| OrchestratorError::Io(std::io::Error::other(e.to_string())))?;
        let mock_packages =
            crate::mock_packages::load(&base_image_path.join("mock-package-db.json"))
                .map_err(|e| OrchestratorError::Io(std::io::Error::other(e.to_string())))?;

        Ok(AppState {
            db: Mutex::new(db),
            capability_report,
            policy_engine,
            ai_backend,
            sessions: Mutex::new(HashMap::new()),
            data_dir,
            retention_policy: RetentionPolicy::default(),
            mock_packages,
            base_image_path: base_image_path.to_path_buf(),
            nondeterminism_allowlist,
        })
    }

    #[cfg(test)]
    fn for_tests(ai_backend: Box<dyn AiBackend + Send + Sync>) -> (Self, tempfile::TempDir) {
        use crate::sandbox::backend::PrimitiveStatus;

        let tmp = tempfile::tempdir().unwrap();
        let policies_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../policies/supported_commands.toml"
        );
        let base_image_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../simulated-root-image");
        let all_ok = CapabilityReport {
            user_namespaces: PrimitiveStatus::Ok,
            mount_namespaces: PrimitiveStatus::Ok,
            pid_namespaces: PrimitiveStatus::Ok,
            seccomp: PrimitiveStatus::Ok,
            cgroups_v2: PrimitiveStatus::Ok,
            landlock: PrimitiveStatus::Ok,
            overlayfs: PrimitiveStatus::Ok,
            openat2: PrimitiveStatus::Ok,
            degradations: vec![],
        };
        let state = AppState::new_with_capability_report(
            tmp.path().join("data"),
            Path::new(policies_path),
            Path::new(base_image_path),
            ai_backend,
            all_ok,
        )
        .unwrap();
        (state, tmp)
    }
}

/// Build order phase 13 ("seed environment"): seeds a fresh session's
/// `LayerStack::base` from `simulated-root-image/`'s real content, so
/// every new session starts from the same populated base image instead
/// of an empty directory. Only *directories* directly under
/// `base_image_path` are copied — `nondeterministic-paths.toml`,
/// `mock-users.json`, and `mock-package-db.json` sit alongside them as
/// SafeShell's own configuration about the image, not simulated
/// filesystem content, and must never appear inside a session's
/// simulated root.
fn seed_base_from_image(base_image_path: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(base_image_path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &dst_path)?;
        }
        // Symlinks in the base image are skipped: no handler in this
        // crate creates or follows one yet (`handlers/mod.rs`'s own doc
        // comment), so there is nothing that could meaningfully consume
        // one here either.
    }
    Ok(())
}

/// §14.4/CLAUDE.md invariant #19: kernel OverlayFS, then fuse-overlayfs,
/// then copy-up — never a silent downgrade, always the mechanism that's
/// actually in effect, announced by name. `overlayfs::self_test`/
/// `fuse_overlay::self_test` perform a real probe every time a session is
/// created; neither backend is exercisable in this project's development
/// environment (see each module's own doc comment for why), so every
/// session created *in this environment* honestly falls through to
/// `copyup` — a real probe result, not an assumption.
fn select_simulation_backend(
    layers_root: &Path,
) -> std::io::Result<(Arc<dyn SimulationBackend + Send + Sync>, &'static str)> {
    if overlayfs::self_test().is_ok() {
        let backend = overlayfs::OverlayFsSimulationBackend::new(layers_root.to_path_buf())?;
        return Ok((Arc::new(backend), "overlayfs"));
    }
    if fuse_overlay::self_test().is_ok() {
        let backend = fuse_overlay::FuseOverlaySimulationBackend::new(layers_root.to_path_buf())?;
        return Ok((Arc::new(backend), "fuse-overlayfs"));
    }
    let backend = CopyUpSimulationBackend::new(layers_root.to_path_buf())?;
    Ok((Arc::new(backend), "copyup"))
}

pub fn capability_report_to_json(report: &CapabilityReport) -> serde_json::Value {
    json!({
        "user_namespaces": report.user_namespaces.to_string(),
        "mount_namespaces": report.mount_namespaces.to_string(),
        "pid_namespaces": report.pid_namespaces.to_string(),
        "seccomp": report.seccomp.to_string(),
        "cgroups_v2": report.cgroups_v2.to_string(),
        "landlock": report.landlock.to_string(),
        "overlayfs": report.overlayfs.to_string(),
        "openat2": report.openat2.to_string(),
        "execution_available": report.execution_available(),
        "degradations": report.degradations,
    })
}

fn category_static_str(c: Category) -> &'static str {
    match c {
        Category::Safe => "safe",
        Category::DangerousContainable => "dangerous_containable",
        Category::UnsafeToContain => "unsafe_to_contain",
    }
}

fn diff_to_json(diff: &SimulationDiff) -> serde_json::Value {
    json!({
        "files_created": diff.files_created,
        "files_modified": diff.files_modified,
        "directories_created": diff.directories_created,
        "files_deleted": diff.files_deleted,
        "directories_deleted": diff.directories_deleted,
        "bytes_affected": diff.bytes_affected,
        "bytes_deleted": diff.bytes_deleted,
    })
}

fn mismatch_kind_str(m: &Mismatch) -> &'static str {
    match m {
        Mismatch::UnexpectedChange { .. } => "unexpected_change",
        Mismatch::PredictedChangeMissing { .. } => "predicted_change_missing",
        Mismatch::ContentHashDiffers { .. } => "content_hash_differs",
        Mismatch::ExitCodeClassDiffers { .. } => "exit_code_class_differs",
    }
}

fn deny_stderr_text(decision: &policy::PolicyDecision) -> String {
    let mut parts: Vec<String> = decision.reasons.clone();
    for code in &decision.reason_codes {
        parts.push(code.canonical_text().to_string());
    }
    if parts.is_empty() {
        "denied: this operation would breach SafeShell's containment boundary".to_string()
    } else {
        parts.join(" ")
    }
}

fn parse_checkpoint_id(s: &str) -> Option<CheckpointId> {
    s.strip_prefix("ckpt_")
        .and_then(|rest| rest.parse::<Ulid>().ok())
        .map(CheckpointId)
}

// --- Session lifecycle ---

pub fn create_session(state: &AppState) -> Result<String, OrchestratorError> {
    let session_id = SessionId::new().to_string();
    let session_dir = state.data_dir.join("sessions").join(&session_id);
    let layers_root = session_dir.join("layers");
    let base = session_dir.join("base");
    let active_write = session_dir.join("write");
    seed_base_from_image(&state.base_image_path, &base)?;
    std::fs::create_dir_all(&active_write)?;

    let (backend, backend_name) = select_simulation_backend(&layers_root)?;

    {
        let db = state.db.lock().unwrap();
        db.insert_session(&NewSession {
            id: session_id.clone(),
            created_at: Utc::now().to_rfc3339(),
            layer_root_path: Some(layers_root.to_string_lossy().to_string()),
            sandbox_backend: None,
            simulation_backend: Some(backend_name.to_string()),
            capability_report_json: serde_json::to_string(&capability_report_to_json(
                &state.capability_report,
            ))
            .ok(),
            status: "active".to_string(),
        })?;
    }

    let stack = LayerStack {
        base,
        checkpoints: Vec::new(),
        active_write,
    };
    let mut terminal = TerminalSession::new();
    terminal.packages = state.mock_packages.clone();
    state.sessions.lock().unwrap().insert(
        session_id.clone(),
        SessionRuntime {
            terminal,
            backend,
            simulation_backend_name: backend_name,
            stack,
            pending: None,
        },
    );
    Ok(session_id)
}

pub fn close_session(state: &AppState, session_id: &str) -> Result<(), OrchestratorError> {
    state
        .sessions
        .lock()
        .unwrap()
        .remove(session_id)
        .ok_or_else(|| OrchestratorError::UnknownSession(session_id.to_string()))?;
    state
        .db
        .lock()
        .unwrap()
        .update_session_status(session_id, "closed")?;
    Ok(())
}

pub fn list_sessions(state: &AppState) -> Result<Vec<SessionRow>, OrchestratorError> {
    Ok(state.db.lock().unwrap().list_sessions()?)
}

// --- Command submission and the resumable pipeline ---

pub fn submit_command(
    state: &AppState,
    session_id: &str,
    line: &str,
    sink: &mut dyn EventSink,
    output: &mut dyn TerminalOutputSink,
) -> Result<String, OrchestratorError> {
    let mut db = state.db.lock().unwrap();
    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| OrchestratorError::UnknownSession(session_id.to_string()))?;

    let command_id = format!("cmd_{}", Ulid::new());
    let now = Utc::now().to_rfc3339();
    db.insert_command(&command_id, session_id, line, None, &now)?;
    db.insert_terminal_history(session_id, line, &now)?;
    session.terminal.record_history(line.to_string());

    let mut txn = Transaction::begin(&db, sink, session_id, &command_id, line)?;
    let txn_id = txn.id.to_string();

    let parsed = match parser::parse_line(line, session.terminal.env()) {
        Ok(cmd_line) => cmd_line.segments.into_iter().next().unwrap().0,
        Err(e) => {
            txn.record_parse_failure(&db, sink, &e.to_string())?;
            output.emit(&TerminalOutputEvent {
                session_id: session_id.to_string(),
                transaction_id: txn_id.clone(),
                command: line.to_string(),
                stdout: String::new(),
                stderr: e.to_string(),
                exit_code: 2,
            });
            return Ok(txn_id);
        }
    };
    txn.record_parsed(&db, sink, &parsed)?;

    let decision = state
        .policy_engine
        .evaluate_pipeline(&parsed, &state.capability_report);
    txn.record_policy_decision(&db, sink, &decision)?;

    if txn.state() == TransactionState::Denied {
        output.emit(&TerminalOutputEvent {
            session_id: session_id.to_string(),
            transaction_id: txn_id.clone(),
            command: line.to_string(),
            stdout: String::new(),
            stderr: deny_stderr_text(&decision),
            exit_code: -1,
        });
        return Ok(txn_id);
    }
    if txn.state() == TransactionState::Failed {
        // Verdict::RejectUnsupported — see transaction::manager's module
        // doc for why this lands on FAILED rather than a dedicated state.
        output.emit(&TerminalOutputEvent {
            session_id: session_id.to_string(),
            transaction_id: txn_id.clone(),
            command: line.to_string(),
            stdout: String::new(),
            stderr: decision.reasons.join("; "),
            exit_code: 127,
        });
        return Ok(txn_id);
    }

    // `allow_or_require_approval` (policy/engine.rs) only ever produces
    // `Verdict::Allow` paired with `Category::Safe`/`RiskLevel::Low` — it's
    // the sole place `Verdict::Allow` is constructed for a
    // Supported/PartiallySupported command. AI output is advisory-only
    // (§21: never able to widen a decision, lower a risk level, or approve
    // a Deny) and `ai_outcome` is never read back into policy/verdict logic
    // anywhere in this pipeline — see `record_ai_analysis_and_enter_simulation`,
    // which only persists it for display. So a command the deterministic
    // policy engine has already decided needs no approval gains nothing
    // from waiting on the real AI call, and skipping it here cannot change
    // any routing outcome: post-simulation escalation (`apply_post_simulation_escalation`,
    // called after this regardless) is the only thing that can still move
    // this transaction to RequireApproval, and it runs identically whether
    // AI analysis happened or was skipped.
    let ai_outcome = if decision.verdict == Verdict::Allow {
        crate::ai::backend::AiOutcome::Skipped {
            reason: "command structurally cannot require approval (policy: Allow/Safe)".to_string(),
        }
    } else {
        let ai_request = AiRequest {
            command_text: line.to_string(),
            category: decision.category.map(category_static_str),
            risk_level: decision.risk_level,
            policy_reasons: decision.reasons.clone(),
        };
        // `analyze` is a blocking network round trip (`OllamaBackend`'s
        // default timeout is 30s; real local generation has been measured
        // at 9-16s) that touches neither the database nor any session
        // state. Holding `state.db`'s lock across it — as this used to —
        // stalls every *other* IPC command that needs the database
        // (`list_sessions`, `get_transaction_history`,
        // `get_transaction_detail`, `create_session`, ...) for the AI
        // call's full duration, for every session in the app, not just
        // this one's. Dropping it here and re-acquiring right after means
        // only this session's own pipeline waits on the AI response.
        drop(db);
        let outcome = state.ai_backend.analyze(&ai_request);
        db = state.db.lock().unwrap();
        outcome
    };
    txn.record_ai_analysis_and_enter_simulation(&db, sink, &ai_outcome)?;

    // A real bug, found via a live session: `sim_manager::simulate` used
    // to take `&mut session.terminal` directly — the *real* session, not
    // a disposable copy. `cd`'s effect is a mutation of
    // `TerminalSession.cwd`, not a filesystem write, so it's invisible to
    // the diff/verification machinery and was silently applying for real
    // during simulation, before approval/execution ever happened
    // (violating invariant #12: simulation must never have an effect
    // beyond its disposable transient layer). `executor::execute` then
    // ran the same `cd` a second time relative to the already-changed
    // cwd, producing a wrong, doubled path. Simulating against a clone
    // and discarding it after prediction is the fix — the real session's
    // cwd/env only ever change once, for real, in `executor::execute`.
    let mut sim_session = session.terminal.clone();
    let predicted =
        match sim_manager::simulate(&*session.backend, &session.stack, &mut sim_session, &parsed) {
            Ok(outcome) => outcome,
            Err(e) => {
                txn.record_simulation_failure(&db, sink, &e.to_string())?;
                output.emit(&TerminalOutputEvent {
                    session_id: session_id.to_string(),
                    transaction_id: txn_id.clone(),
                    command: line.to_string(),
                    stdout: String::new(),
                    stderr: e.to_string(),
                    exit_code: 1,
                });
                return Ok(txn_id);
            }
        };
    // §31.3's approval panel needs the predicted diff *before* execution
    // has happened at all — nothing in `db/` persists a "predicted diff"
    // row (only `verification_results`, written after execution, does),
    // so this event's `metrics` payload (§29.2: exactly what per-stage
    // free-form data is for) is the one place it travels to the frontend,
    // live via `transaction://event` and, for a page that missed the live
    // event, durably via this same row inside `get_transaction_detail`'s
    // `events` list (`transaction_events.metrics_json`).
    txn.record_simulation_complete(
        &db,
        sink,
        json!({
            "predicted_diff": diff_to_json(&predicted.diff),
            "predicted_exit_code": predicted.command_result.exit_code,
        }),
    )?;

    // §20.5's post-simulation re-evaluation: escalate risk against the
    // real diff's scale, then re-persist policy fields if it actually
    // moved anything (a silently-unwired gap otherwise — see
    // `policy::apply_post_simulation_escalation`'s own doc comment; this
    // orchestrator is the first caller that ever reaches it with a real
    // `SimulationDiffStats`).
    let stats = SimulationDiffStats {
        files_affected: predicted.diff.files_affected(),
        directories_affected: (predicted.diff.directories_created.len()
            + predicted.diff.directories_deleted.len()) as u64,
        bytes_deleted: predicted.diff.bytes_deleted,
        permission_changes: 0,
    };
    let escalated = policy::apply_post_simulation_escalation(decision.clone(), &stats);
    if escalated.risk_level != decision.risk_level || escalated.verdict != decision.verdict {
        let reason_codes: Vec<String> = escalated
            .reason_codes
            .iter()
            .map(|r| r.to_string())
            .collect();
        let reason_codes_json =
            serde_json::to_string(&reason_codes).unwrap_or_else(|_| "[]".to_string());
        db.update_transaction_policy_fields(
            &txn_id,
            escalated.category.map(|c| c.to_string()).as_deref(),
            &escalated.support_tier.to_string(),
            escalated.risk_level.map(|r| r.to_string()).as_deref(),
            &reason_codes_json,
            escalated.requires_approval(),
        )?;
        db.insert_audit_row(
            Some(&txn_id),
            Some(session_id),
            "post_simulation_escalation",
            &json!({
                "from_risk_level": decision.risk_level.map(|r| r.to_string()),
                "to_risk_level": escalated.risk_level.map(|r| r.to_string()),
            })
            .to_string(),
            &Utc::now().to_rfc3339(),
        )?;
    }
    let requires_approval = escalated.requires_approval();

    txn.record_diff_ready(&db, sink, requires_approval)?;

    if requires_approval {
        session.pending = Some(PendingApproval {
            txn,
            parsed,
            predicted_diff: predicted.diff,
            predicted_exit_code: predicted.command_result.exit_code,
        });
        return Ok(txn_id);
    }

    run_to_completion(
        &db,
        session,
        session_id,
        &mut txn,
        &parsed,
        &predicted.diff,
        predicted.command_result.exit_code,
        state.retention_policy,
        &state.nondeterminism_allowlist,
        sink,
        output,
    )?;
    Ok(txn_id)
}

pub fn approve_transaction(
    state: &AppState,
    transaction_id: &str,
    sink: &mut dyn EventSink,
    output: &mut dyn TerminalOutputSink,
) -> Result<(), OrchestratorError> {
    let db = state.db.lock().unwrap();
    let mut sessions = state.sessions.lock().unwrap();
    let (session_id, session) = find_session_with_pending(&mut sessions, transaction_id)
        .ok_or_else(|| OrchestratorError::UnknownTransaction(transaction_id.to_string()))?;
    let mut pending = session
        .pending
        .take()
        .ok_or_else(|| OrchestratorError::NotAwaitingApproval(transaction_id.to_string()))?;

    pending.txn.approve(&db, sink)?;
    run_to_completion(
        &db,
        session,
        &session_id,
        &mut pending.txn,
        &pending.parsed,
        &pending.predicted_diff,
        pending.predicted_exit_code,
        state.retention_policy,
        &state.nondeterminism_allowlist,
        sink,
        output,
    )?;
    Ok(())
}

pub fn reject_transaction(
    state: &AppState,
    transaction_id: &str,
    sink: &mut dyn EventSink,
) -> Result<(), OrchestratorError> {
    let db = state.db.lock().unwrap();
    let mut sessions = state.sessions.lock().unwrap();
    let (_, session) = find_session_with_pending(&mut sessions, transaction_id)
        .ok_or_else(|| OrchestratorError::UnknownTransaction(transaction_id.to_string()))?;
    let mut pending = session
        .pending
        .take()
        .ok_or_else(|| OrchestratorError::NotAwaitingApproval(transaction_id.to_string()))?;
    pending.txn.reject(&db, sink)?;
    Ok(())
}

/// See this module's doc comment for why this is the only thing this
/// crate can actually interrupt right now.
pub fn interrupt_command(
    state: &AppState,
    session_id: &str,
    sink: &mut dyn EventSink,
) -> Result<(), OrchestratorError> {
    let db = state.db.lock().unwrap();
    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| OrchestratorError::UnknownSession(session_id.to_string()))?;
    if let Some(mut pending) = session.pending.take() {
        pending.txn.record_approval_timeout(&db, sink)?;
    }
    Ok(())
}

fn find_session_with_pending<'a>(
    sessions: &'a mut HashMap<String, SessionRuntime>,
    transaction_id: &str,
) -> Option<(String, &'a mut SessionRuntime)> {
    for (id, session) in sessions.iter_mut() {
        if let Some(pending) = &session.pending {
            if pending.txn.id.to_string() == transaction_id {
                return Some((id.clone(), session));
            }
        }
    }
    None
}

/// The shared tail of the pipeline: snapshot → execute → verify →
/// commit | automatic rollback. Called from [`submit_command`]'s
/// no-approval-needed fast path and from [`approve_transaction`]'s
/// resume — see this module's doc comment for why both must call the
/// exact same function rather than two similar copies.
#[allow(clippy::too_many_arguments)]
fn run_to_completion(
    db: &Database,
    session: &mut SessionRuntime,
    session_id: &str,
    txn: &mut Transaction,
    parsed: &ParsedCommand,
    predicted_diff: &SimulationDiff,
    predicted_exit_code: i32,
    retention_policy: RetentionPolicy,
    allowlist: &NondeterminismAllowlist,
    sink: &mut dyn EventSink,
    output: &mut dyn TerminalOutputSink,
) -> Result<(), OrchestratorError> {
    let txn_id = txn.id.to_string();
    let backend = Arc::clone(&session.backend);

    // docs/CLAUDE.md invariant #24 / §24: "Storage ceiling reached with
    // the minimum checkpoint set → fail closed on transactions needing a
    // snapshot. Never execute without a snapshot to save disk." Checked
    // here, before `seal_active_layer` does anything persistent — a
    // refusal at this point costs nothing already committed. "Minimum
    // checkpoint set" is approximated as "already at the retained-count
    // ceiling" since automatic GC (`snapshot::retention::run_gc`) isn't
    // invoked anywhere in this pipeline yet (a disclosed, honest gap, not
    // a silent one) — there is no smaller checkpoint set this session
    // could actually be squashed down to right now, so "at the count
    // ceiling and still over the byte ceiling" is the real floor.
    if session.stack.checkpoints.len() >= retention_policy.max_checkpoints {
        let bytes_used: u64 = session
            .stack
            .checkpoints
            .iter()
            .filter_map(|(id, _)| backend.layer_size_bytes(LayerId::Checkpoint(*id)).ok())
            .sum();
        if bytes_used >= retention_policy.storage_ceiling_bytes {
            txn.record_snapshot_failure(
                db,
                sink,
                "storage ceiling reached with the maximum retained checkpoint set — refusing to \
                 execute without a snapshot rather than saving disk at the cost of reversibility",
            )?;
            return Ok(());
        }
    }

    let checkpoint_id = backend.seal_active_layer(&mut session.stack)?;
    let layer_path = session
        .stack
        .checkpoints
        .last()
        .expect("seal_active_layer just pushed a checkpoint")
        .1
        .to_string_lossy()
        .to_string();
    let layer_ordinal = session.stack.checkpoints.len() as i64;
    let size_bytes = backend
        .layer_size_bytes(LayerId::Checkpoint(checkpoint_id))
        .ok()
        .map(|v| v as i64);

    let token = txn.record_snapshot_sealed(
        db,
        sink,
        checkpoint_id,
        &layer_path,
        layer_ordinal,
        size_bytes,
    )?;

    let actual = match executor::execute(
        &*backend,
        &session.stack,
        &mut session.terminal,
        parsed,
        &token,
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            txn.record_execution_failure(db, sink, &e.to_string())?;
            let rollback_outcome = rollback::automatic_rollback(&*backend, &mut session.stack);
            persist_and_record_rollback(db, txn, sink, &rollback_outcome, "execution_failure")?;
            output.emit(&TerminalOutputEvent {
                session_id: session_id.to_string(),
                transaction_id: txn_id.clone(),
                command: parsed.name.clone(),
                stdout: String::new(),
                stderr: e.to_string(),
                exit_code: 1,
            });
            return Ok(());
        }
    };

    txn.record_execution_complete(
        db,
        sink,
        json!({"files_affected": actual.diff.files_affected()}),
    )?;
    db.insert_execution_result(
        &txn_id,
        actual.command_result.exit_code,
        &actual.command_result.stdout,
        &actual.command_result.stderr,
        actual.diff.files_created.len() as i64,
        actual.diff.files_modified.len() as i64,
        0,
        actual.diff.bytes_affected as i64,
        &Utc::now().to_rfc3339(),
    )?;

    let result = verification::verify(
        predicted_diff,
        predicted_exit_code,
        &actual.diff,
        actual.command_result.exit_code,
        allowlist,
    );

    db.insert_verification_result(
        &txn_id,
        &diff_to_json(predicted_diff).to_string(),
        &diff_to_json(&actual.diff).to_string(),
        result.matched,
        result.mismatches.first().map(mismatch_kind_str),
        result.detail().as_deref(),
    )?;
    txn.record_verification_result(db, sink, result.matched, result.detail().as_deref())?;

    output.emit(&TerminalOutputEvent {
        session_id: session_id.to_string(),
        transaction_id: txn_id.clone(),
        command: parsed.name.clone(),
        stdout: actual.command_result.stdout.clone(),
        stderr: actual.command_result.stderr.clone(),
        exit_code: actual.command_result.exit_code,
    });

    if !result.matched {
        let rollback_outcome = rollback::automatic_rollback(&*backend, &mut session.stack);
        persist_and_record_rollback(db, txn, sink, &rollback_outcome, "verification_mismatch")?;
    }

    Ok(())
}

fn persist_and_record_rollback(
    db: &Database,
    txn: &mut Transaction,
    sink: &mut dyn EventSink,
    outcome: &RollbackOutcome,
    reason: &str,
) -> Result<(), OrchestratorError> {
    db.insert_rollback_event(
        &format!("rb_{}", Ulid::new()),
        &txn.id.to_string(),
        reason,
        outcome
            .restored_checkpoint_id
            .map(|c| c.to_string())
            .as_deref(),
        outcome.success,
        outcome.failure_detail.as_deref(),
        &Utc::now().to_rfc3339(),
    )?;
    txn.record_rollback_result(db, sink, outcome.success, outcome.failure_detail.as_deref())?;
    Ok(())
}

// --- Recovery actions (§27.4, §30) ---

pub fn undo_last_transaction(
    state: &AppState,
    session_id: &str,
) -> Result<RollbackOutcome, OrchestratorError> {
    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| OrchestratorError::UnknownSession(session_id.to_string()))?;
    let outcome = rollback::undo_last_transaction(&*session.backend, &mut session.stack)
        .map_err(|_| OrchestratorError::NoRecoverableCheckpoint)?;
    state.db.lock().unwrap().insert_audit_row(
        None,
        Some(session_id),
        "undo_last_transaction",
        &json!({
            "success": outcome.success,
            "restored_checkpoint_id": outcome.restored_checkpoint_id.map(|c| c.to_string()),
        })
        .to_string(),
        &Utc::now().to_rfc3339(),
    )?;
    Ok(outcome)
}

/// §27.4's two named quarantine recovery actions. Both, unlike
/// [`undo_last_transaction`]/[`restore_to_checkpoint`], also lift the
/// session's `quarantined` status (`transaction::manager`'s own doc
/// comment on `record_rollback_result` names this as the missing half of
/// quarantine handling: "something calls `Database::update_session_status`
/// back to a non-quarantined value" — this is that something) so
/// `Transaction::begin` accepts new commands on this session again.
fn quarantine_recover(
    state: &AppState,
    session_id: &str,
    reset_to_base: bool,
) -> Result<RollbackOutcome, OrchestratorError> {
    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| OrchestratorError::UnknownSession(session_id.to_string()))?;
    let outcome = if reset_to_base {
        rollback::quarantine_recovery_reset_to_base(&*session.backend, &mut session.stack)
    } else {
        rollback::quarantine_recovery_restore_to_newest(&*session.backend, &mut session.stack)
    };
    drop(sessions);

    let db = state.db.lock().unwrap();
    if outcome.success {
        db.update_session_status(session_id, "active")?;
    }
    db.insert_audit_row(
        None,
        Some(session_id),
        if reset_to_base {
            "quarantine_recovery_reset_to_base"
        } else {
            "quarantine_recovery_restore_to_newest"
        },
        &json!({"success": outcome.success}).to_string(),
        &Utc::now().to_rfc3339(),
    )?;
    Ok(outcome)
}

pub fn quarantine_recovery_restore_to_newest(
    state: &AppState,
    session_id: &str,
) -> Result<RollbackOutcome, OrchestratorError> {
    quarantine_recover(state, session_id, false)
}

pub fn quarantine_recovery_reset_to_base(
    state: &AppState,
    session_id: &str,
) -> Result<RollbackOutcome, OrchestratorError> {
    quarantine_recover(state, session_id, true)
}

pub fn restore_to_checkpoint(
    state: &AppState,
    session_id: &str,
    checkpoint_id: &str,
) -> Result<RollbackOutcome, OrchestratorError> {
    let target = parse_checkpoint_id(checkpoint_id)
        .ok_or_else(|| OrchestratorError::UnknownCheckpoint(checkpoint_id.to_string()))?;
    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| OrchestratorError::UnknownSession(session_id.to_string()))?;
    if !session
        .stack
        .checkpoints
        .iter()
        .any(|(id, _)| *id == target)
    {
        return Err(OrchestratorError::UnknownCheckpoint(
            checkpoint_id.to_string(),
        ));
    }
    let outcome = rollback::restore_to_checkpoint(&*session.backend, &mut session.stack, target);
    state.db.lock().unwrap().insert_audit_row(
        None,
        Some(session_id),
        "restore_to_checkpoint",
        &json!({
            "requested_checkpoint_id": checkpoint_id,
            "success": outcome.success,
        })
        .to_string(),
        &Utc::now().to_rfc3339(),
    )?;
    Ok(outcome)
}

// --- Read-only query surface (§30, §41) ---

pub fn get_transaction_state(
    state: &AppState,
    transaction_id: &str,
) -> Result<Option<String>, OrchestratorError> {
    let events = state
        .db
        .lock()
        .unwrap()
        .get_transaction_events(transaction_id)?;
    Ok(events.last().map(|e| e.stage.clone()))
}

const HISTORY_PAGE_SIZE: i64 = 25;

pub fn get_transaction_history(
    state: &AppState,
    session_id: &str,
    page: i64,
) -> Result<Vec<TransactionSummaryRow>, OrchestratorError> {
    let offset = page.max(0) * HISTORY_PAGE_SIZE;
    Ok(state.db.lock().unwrap().get_transactions_for_session(
        session_id,
        HISTORY_PAGE_SIZE,
        offset,
    )?)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DenyReasonDetail {
    pub code: String,
    pub canonical_text: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AiPlanDetail {
    pub schema_version: Option<String>,
    pub intent: Option<String>,
    pub risk_level: Option<String>,
    pub confidence: Option<f64>,
    pub recovery_recommendation: Option<serde_json::Value>,
    pub explanation: Option<String>,
    pub divergence: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerificationDetail {
    pub matched: bool,
    pub mismatch_kind: Option<String>,
    pub mismatch_details: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TransactionDetail {
    pub transaction_id: String,
    pub command: String,
    pub final_state: Option<String>,
    pub category: Option<String>,
    pub support_tier: Option<String>,
    pub policy_risk_level: Option<String>,
    pub policy_reason_codes: Vec<DenyReasonDetail>,
    pub events: Vec<TransactionEventRow>,
    pub ai_plan: Option<AiPlanDetail>,
    pub ai_skipped: Option<bool>,
    pub ai_skipped_reason: Option<String>,
    pub requires_approval: Option<bool>,
    pub approved_by_user: Option<bool>,
    pub execution: Option<ExecutionResultRow>,
    pub verification: Option<VerificationDetail>,
    pub recoverable: bool,
    pub created_at: String,
    pub completed_at: Option<String>,
}

pub fn get_transaction_detail(
    state: &AppState,
    transaction_id: &str,
) -> Result<TransactionDetail, OrchestratorError> {
    let db = state.db.lock().unwrap();
    let row = db
        .get_transaction_row(transaction_id)?
        .ok_or_else(|| OrchestratorError::UnknownTransaction(transaction_id.to_string()))?;
    let events = db.get_transaction_events(transaction_id)?;
    let ai_plan_row = db.get_ai_plan(transaction_id)?;
    let execution = db.get_execution_result(transaction_id)?;
    let verification_row = db.get_verification_result(transaction_id)?;

    let reason_code_strings: Vec<String> = row
        .policy_reason_codes
        .as_deref()
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default();
    let policy_reason_codes = reason_code_strings
        .into_iter()
        .map(|code| {
            let canonical_text = ReasonCode::from_code_str(&code)
                .map(|r| r.canonical_text().to_string())
                .unwrap_or_else(|| "Unrecognized reason code.".to_string());
            DenyReasonDetail {
                code,
                canonical_text,
            }
        })
        .collect();

    let recoverable = match &row.pre_execution_checkpoint_id {
        Some(ckpt_id) => db.get_snapshot_recoverable(ckpt_id)?.unwrap_or(false),
        None => false,
    };

    Ok(TransactionDetail {
        transaction_id: row.id,
        command: row.raw_command,
        final_state: row.final_state,
        category: row.category,
        support_tier: row.support_tier,
        policy_risk_level: row.policy_risk_level,
        policy_reason_codes,
        events,
        ai_plan: ai_plan_row.map(|p| AiPlanDetail {
            schema_version: p.schema_version,
            intent: p.intent,
            risk_level: p.risk_level,
            confidence: p.confidence,
            recovery_recommendation: p
                .recovery_recommendation_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
            explanation: p.explanation,
            divergence: p
                .divergence_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
        }),
        ai_skipped: row.ai_skipped,
        ai_skipped_reason: row.ai_skipped_reason,
        requires_approval: row.requires_approval,
        approved_by_user: row.approved_by_user,
        execution,
        verification: verification_row.map(|v| VerificationDetail {
            matched: v.matched,
            mismatch_kind: v.mismatch_kind,
            mismatch_details: v.mismatch_details,
        }),
        recoverable,
        created_at: row.created_at,
        completed_at: row.completed_at,
    })
}

pub fn get_capability_report(state: &AppState) -> serde_json::Value {
    capability_report_to_json(&state.capability_report)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StorageStatus {
    pub checkpoints_retained: usize,
    pub max_checkpoints: usize,
    pub bytes_used: u64,
    pub ceiling_bytes: u64,
    pub oldest_recoverable_transaction_id: Option<String>,
}

pub fn get_storage_status(
    state: &AppState,
    session_id: &str,
) -> Result<StorageStatus, OrchestratorError> {
    let mut sessions = state.sessions.lock().unwrap();
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| OrchestratorError::UnknownSession(session_id.to_string()))?;
    let policy = state.retention_policy;

    let mut bytes_used = 0u64;
    for (id, _) in &session.stack.checkpoints {
        if let Ok(size) = session.backend.layer_size_bytes(LayerId::Checkpoint(*id)) {
            bytes_used += size;
        }
    }

    let oldest_checkpoint = session.stack.checkpoints.first().map(|(id, _)| *id);
    drop(sessions);

    let oldest_recoverable_transaction_id = match oldest_checkpoint {
        Some(id) => state
            .db
            .lock()
            .unwrap()
            .get_snapshot_transaction_id(&id.to_string())?,
        None => None,
    };

    let sessions = state.sessions.lock().unwrap();
    let session = sessions
        .get(session_id)
        .ok_or_else(|| OrchestratorError::UnknownSession(session_id.to_string()))?;

    Ok(StorageStatus {
        checkpoints_retained: session.stack.checkpoints.len(),
        max_checkpoints: policy.max_checkpoints,
        bytes_used,
        ceiling_bytes: policy.storage_ceiling_bytes,
        oldest_recoverable_transaction_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::backend::NullBackend;
    use crate::transaction::events::CollectingEventSink;

    fn test_state() -> (AppState, tempfile::TempDir) {
        AppState::for_tests(Box::new(NullBackend))
    }

    #[test]
    fn a_low_risk_command_runs_all_the_way_to_committed_with_no_approval_pause() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        let txn_id =
            submit_command(&state, &session_id, "mkdir newdir", &mut sink, &mut output).unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("COMMITTED"));
        assert_eq!(output.events.len(), 1);
        assert_eq!(output.events[0].exit_code, 0);
        assert!(
            state
                .sessions
                .lock()
                .unwrap()
                .get(&session_id)
                .unwrap()
                .stack
                .active_write
                .join("newdir")
                .exists(),
            "a committed transaction's write must persist to the active write layer"
        );
    }

    #[test]
    fn the_predicted_diff_travels_on_the_diff_ready_event_for_the_approval_panel() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        // `mkdir` is enough to prove the *diff* travels at all, without
        // getting into the approval-pause plumbing `rm`'s HIGH/CRITICAL
        // risk would trigger (covered separately below).
        let txn_id =
            submit_command(&state, &session_id, "mkdir newdir", &mut sink, &mut output).unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        let diff_ready_event = detail
            .events
            .iter()
            .find(|e| e.stage == "DIFF_READY")
            .expect("a DIFF_READY event must have been recorded");
        let metrics: serde_json::Value =
            serde_json::from_str(diff_ready_event.metrics_json.as_deref().unwrap()).unwrap();
        assert!(
            metrics["predicted_diff"]["directories_created"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("newdir")),
            "approval panel needs the predicted diff before the user decides: {metrics}"
        );
    }

    #[test]
    fn a_high_risk_command_pauses_for_approval_and_resumes_on_approve() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        let txn_id = submit_command(
            &state,
            &session_id,
            "rm -rf /project",
            &mut sink,
            &mut output,
        )
        .unwrap();

        let waiting = get_transaction_state(&state, &txn_id).unwrap();
        assert_eq!(waiting.as_deref(), Some("WAITING_FOR_APPROVAL"));
        assert!(output.events.is_empty(), "no output before approval");

        approve_transaction(&state, &txn_id, &mut sink, &mut output).unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert!(
            matches!(
                detail.final_state.as_deref(),
                Some("COMMITTED") | Some("RESTORED")
            ),
            "got {:?}",
            detail.final_state
        );
        assert_eq!(output.events.len(), 1);
    }

    #[test]
    fn a_verdict_allow_command_skips_the_real_ai_call_and_a_verdict_require_approval_command_does_not(
    ) {
        use crate::ai::backend::{AiBackend, AiOutcome};
        use crate::ai::schema::{
            AiPlan, AiRequest, Intent, PredictedEffects, RecoveryRecommendation, RecoveryStrategy,
        };
        use crate::policy::RiskLevel;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingBackend {
            calls: Arc<AtomicUsize>,
        }
        impl AiBackend for CountingBackend {
            fn name(&self) -> &'static str {
                "CountingBackend"
            }
            fn analyze(&self, request: &AiRequest) -> AiOutcome {
                self.calls.fetch_add(1, Ordering::SeqCst);
                AiOutcome::Analyzed(AiPlan {
                    schema_version: "1".to_string(),
                    command: request.command_text.clone(),
                    intent: Intent::RecursiveDelete,
                    risk_level: RiskLevel::High,
                    affected_resources: vec![],
                    predicted_effects: PredictedEffects {
                        files_deleted_estimate: 0,
                        directories_deleted_estimate: 0,
                        escapes_sandbox: false,
                    },
                    preconditions: vec![],
                    reversible_within_safeshell: true,
                    recovery_recommendation: RecoveryRecommendation {
                        strategy: RecoveryStrategy::RestorePreTransactionSnapshot,
                        description: "rollback".to_string(),
                    },
                    external_side_effects: false,
                    confidence: 0.9,
                    explanation: "test".to_string(),
                })
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let (state, _tmp) = AppState::for_tests(Box::new(CountingBackend {
            calls: calls.clone(),
        }));
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        // Verdict::Allow (Low risk by omission) — the real AI backend must
        // never be invoked; `submit_command` fabricates `AiOutcome::Skipped`
        // itself.
        let allow_txn =
            submit_command(&state, &session_id, "mkdir newdir", &mut sink, &mut output).unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a structurally-safe command must not wait on the real AI call"
        );
        let allow_detail = get_transaction_detail(&state, &allow_txn).unwrap();
        assert_eq!(allow_detail.ai_skipped, Some(true));
        assert_eq!(
            allow_detail.ai_skipped_reason.as_deref(),
            Some("command structurally cannot require approval (policy: Allow/Safe)")
        );
        assert_eq!(allow_detail.final_state.as_deref(), Some("COMMITTED"));

        // Verdict::RequireApproval (`rm -rf` is a HIGH/CRITICAL risk rule
        // match) — the real AI backend must still be consulted exactly as
        // before.
        let approval_txn = submit_command(
            &state,
            &session_id,
            "rm -rf /project",
            &mut sink,
            &mut output,
        )
        .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a command that can require approval must still get full AI analysis"
        );
        let approval_detail = get_transaction_detail(&state, &approval_txn).unwrap();
        assert_eq!(approval_detail.ai_skipped, Some(false));
    }

    /// Seeds `name` with `content` as though a *prior, already-committed*
    /// transaction had created it, by writing it directly into the active
    /// write layer and sealing it into a real checkpoint — bypassing
    /// `submit_command` for the setup step. **Deliberately not** "run
    /// `touch`/`echo >` through `submit_command`, then run the command
    /// under test in a second `submit_command` call": that sequence hits
    /// a genuine, pre-existing bug in every `SimulationBackend`
    /// (`copyup.rs`/`overlayfs.rs`/`fuse_overlay.rs`'s `mount_view`, for
    /// `WriteTarget::Transient`, composes `[transient, ...checkpoints,
    /// base]` and never includes `layers.active_write` — so a previous
    /// transaction's committed content, which lives in `active_write`
    /// until some *later* transaction's own snapshot step seals it into a
    /// checkpoint, is invisible to that later transaction's own
    /// simulation, even though real execution finds it fine (its own
    /// snapshot step seals `active_write` immediately before it runs).
    /// The result is a spurious predicted/actual mismatch and an
    /// automatic rollback — reproducible on `main` before this change
    /// with nothing but `touch a.txt` then `cat a.txt`, entirely
    /// independent of any new command added here. Out of scope for this
    /// change (three backend files, core transaction-pipeline semantics,
    /// its own dedicated fix and test pass) and reported separately;
    /// this helper works around it in test setup only, the same way
    /// `simulation::manager`'s own existing tests already do
    /// (`simulating_a_command_that_reads_a_checkpoint_file_sees_it`).
    fn seed_committed_file(state: &AppState, session_id: &str, name: &str, content: &[u8]) {
        let mut sessions = state.sessions.lock().unwrap();
        let session = sessions.get_mut(session_id).unwrap();
        std::fs::write(session.stack.active_write.join(name), content).unwrap();
        session
            .backend
            .seal_active_layer(&mut session.stack)
            .unwrap();
    }

    #[test]
    fn cp_runs_through_the_full_pipeline_and_commits() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();
        seed_committed_file(&state, &session_id, "a.txt", b"hello");

        let txn_id = submit_command(
            &state,
            &session_id,
            "cp a.txt b.txt",
            &mut sink,
            &mut output,
        )
        .unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("COMMITTED"));
        assert!(
            state
                .sessions
                .lock()
                .unwrap()
                .get(&session_id)
                .unwrap()
                .stack
                .active_write
                .join("b.txt")
                .exists(),
            "cp's destination must persist to the active write layer"
        );
    }

    #[test]
    fn mv_runs_through_the_full_pipeline_pauses_for_approval_and_commits_on_approve() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();
        seed_committed_file(&state, &session_id, "a.txt", b"hello");

        // `mv` is unconditionally Medium risk in `policy::risk` (§20.4) —
        // the Policy Engine has no filesystem access to know whether the
        // destination really would clobber something, so every `mv`
        // requires approval regardless. Unaffected by this change;
        // preserved exactly as-is.
        let txn_id = submit_command(
            &state,
            &session_id,
            "mv a.txt b.txt",
            &mut sink,
            &mut output,
        )
        .unwrap();
        assert_eq!(
            get_transaction_state(&state, &txn_id).unwrap().as_deref(),
            Some("WAITING_FOR_APPROVAL")
        );

        approve_transaction(&state, &txn_id, &mut sink, &mut output).unwrap();
        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("COMMITTED"));
        let write_layer = state
            .sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .stack
            .active_write
            .clone();
        assert!(write_layer.join("b.txt").exists());
    }

    #[test]
    fn undo_after_a_committed_mv_restores_the_pre_transaction_state() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();
        seed_committed_file(&state, &session_id, "a.txt", b"hello");

        let txn_id = submit_command(
            &state,
            &session_id,
            "mv a.txt b.txt",
            &mut sink,
            &mut output,
        )
        .unwrap();
        approve_transaction(&state, &txn_id, &mut sink, &mut output).unwrap();
        assert_eq!(
            get_transaction_detail(&state, &txn_id)
                .unwrap()
                .final_state
                .as_deref(),
            Some("COMMITTED")
        );

        let outcome = undo_last_transaction(&state, &session_id).unwrap();
        assert!(outcome.success, "undo must succeed after a committed mv");

        assert!(
            !state
                .sessions
                .lock()
                .unwrap()
                .get(&session_id)
                .unwrap()
                .stack
                .active_write
                .join("b.txt")
                .exists(),
            "b.txt must be gone again after undoing the mv that created it"
        );
    }

    #[test]
    fn echo_redirect_writes_a_real_file_through_the_full_pipeline() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        // `>` truncate redirection is unconditionally Medium risk in
        // `policy::risk` (§20.4), independent of which command it's
        // attached to. Unaffected by this change; preserved exactly
        // as-is.
        let txn_id = submit_command(
            &state,
            &session_id,
            "echo hello > greeting.txt",
            &mut sink,
            &mut output,
        )
        .unwrap();
        assert_eq!(
            get_transaction_state(&state, &txn_id).unwrap().as_deref(),
            Some("WAITING_FOR_APPROVAL")
        );
        approve_transaction(&state, &txn_id, &mut sink, &mut output).unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("COMMITTED"));
        // Redirected output never reaches the terminal itself.
        assert_eq!(output.events[0].stdout, "");
        assert_eq!(
            std::fs::read_to_string(
                state
                    .sessions
                    .lock()
                    .unwrap()
                    .get(&session_id)
                    .unwrap()
                    .stack
                    .active_write
                    .join("greeting.txt")
            )
            .unwrap(),
            "hello\n"
        );
    }

    #[test]
    fn grep_finds_a_match_through_the_full_pipeline() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();
        seed_committed_file(&state, &session_id, "a.txt", b"apple\nbanana\n");

        // `grep` is a `partially_supported`-tier command (documented
        // divergence: "supports a subset of real grep's flags") —
        // `policy::risk`'s "partially-supported-command divergence -> at
        // least Medium" rule (§20.4) means it always requires approval,
        // unconditionally, same as every other partially-supported
        // command. Unaffected by this change; preserved exactly as-is.
        let txn_id = submit_command(
            &state,
            &session_id,
            "grep apple a.txt",
            &mut sink,
            &mut output,
        )
        .unwrap();
        assert_eq!(
            get_transaction_state(&state, &txn_id).unwrap().as_deref(),
            Some("WAITING_FOR_APPROVAL")
        );
        approve_transaction(&state, &txn_id, &mut sink, &mut output).unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("COMMITTED"));
        assert_eq!(output.events.last().unwrap().stdout, "apple\n");
    }

    #[test]
    fn chmod_777_on_a_single_file_now_requires_approval_and_commits_on_approve() {
        // The exact gap a user reported live: `chmod 777 file` used to
        // sail through as Low risk with no approval pause. Now Medium
        // (policy::risk's new non-recursive world-writable rule).
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();
        seed_committed_file(&state, &session_id, "a.txt", b"hello");

        let txn_id = submit_command(
            &state,
            &session_id,
            "chmod 777 a.txt",
            &mut sink,
            &mut output,
        )
        .unwrap();
        assert_eq!(
            get_transaction_state(&state, &txn_id).unwrap().as_deref(),
            Some("WAITING_FOR_APPROVAL")
        );
        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.policy_risk_level.as_deref(), Some("medium"));

        approve_transaction(&state, &txn_id, &mut sink, &mut output).unwrap();
        assert_eq!(
            get_transaction_detail(&state, &txn_id)
                .unwrap()
                .final_state
                .as_deref(),
            Some("COMMITTED")
        );

        use std::os::unix::fs::PermissionsExt;
        let write_layer = state
            .sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .stack
            .active_write
            .clone();
        let mode = std::fs::metadata(write_layer.join("a.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o777);
    }

    #[test]
    fn chmod_644_on_a_single_file_still_auto_commits_with_no_approval_pause() {
        // A non-dangerous mode must not regress to requiring approval.
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();
        seed_committed_file(&state, &session_id, "a.txt", b"hello");

        let txn_id = submit_command(
            &state,
            &session_id,
            "chmod 644 a.txt",
            &mut sink,
            &mut output,
        )
        .unwrap();
        assert_eq!(
            get_transaction_detail(&state, &txn_id)
                .unwrap()
                .final_state
                .as_deref(),
            Some("COMMITTED")
        );
    }

    #[test]
    fn truncate_requires_approval_and_discards_content_on_approve() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();
        seed_committed_file(&state, &session_id, "a.txt", b"hello world");

        let txn_id = submit_command(
            &state,
            &session_id,
            "truncate -s 0 a.txt",
            &mut sink,
            &mut output,
        )
        .unwrap();
        assert_eq!(
            get_transaction_state(&state, &txn_id).unwrap().as_deref(),
            Some("WAITING_FOR_APPROVAL")
        );
        approve_transaction(&state, &txn_id, &mut sink, &mut output).unwrap();
        assert_eq!(
            get_transaction_detail(&state, &txn_id)
                .unwrap()
                .final_state
                .as_deref(),
            Some("COMMITTED")
        );

        let write_layer = state
            .sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .stack
            .active_write
            .clone();
        assert_eq!(
            std::fs::metadata(write_layer.join("a.txt")).unwrap().len(),
            0
        );
    }

    #[test]
    fn shred_is_high_risk_and_destroys_content_on_approve() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();
        seed_committed_file(&state, &session_id, "secret.txt", b"top secret");

        let txn_id = submit_command(
            &state,
            &session_id,
            "shred secret.txt",
            &mut sink,
            &mut output,
        )
        .unwrap();
        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.category.as_deref(), Some("dangerous_containable"));
        assert_eq!(detail.policy_risk_level.as_deref(), Some("high"));

        approve_transaction(&state, &txn_id, &mut sink, &mut output).unwrap();
        assert_eq!(
            get_transaction_detail(&state, &txn_id)
                .unwrap()
                .final_state
                .as_deref(),
            Some("COMMITTED")
        );

        let write_layer = state
            .sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .stack
            .active_write
            .clone();
        let contents = std::fs::read(write_layer.join("secret.txt")).unwrap();
        assert!(contents.iter().all(|&b| b == 0));
    }

    #[test]
    fn safeshell_pkg_remove_of_the_essential_package_is_high_risk_through_the_full_pipeline() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        // Seeded for real from simulated-root-image/mock-package-db.json
        // by `create_session` — no manual setup needed.
        let txn_id = submit_command(
            &state,
            &session_id,
            "safeshell-pkg remove safeshell-toolchain",
            &mut sink,
            &mut output,
        )
        .unwrap();
        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.policy_risk_level.as_deref(), Some("high"));
        assert_eq!(
            get_transaction_state(&state, &txn_id).unwrap().as_deref(),
            Some("WAITING_FOR_APPROVAL")
        );

        approve_transaction(&state, &txn_id, &mut sink, &mut output).unwrap();
        assert_eq!(
            get_transaction_detail(&state, &txn_id)
                .unwrap()
                .final_state
                .as_deref(),
            Some("COMMITTED")
        );
        assert!(!state
            .sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .terminal
            .packages
            .iter()
            .any(|p| p.name == "safeshell-toolchain"));
    }

    #[test]
    fn safeshell_pkg_list_is_medium_risk_from_the_partially_supported_divergence_alone() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        let txn_id = submit_command(
            &state,
            &session_id,
            "safeshell-pkg list",
            &mut sink,
            &mut output,
        )
        .unwrap();
        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.policy_risk_level.as_deref(), Some("medium"));
        approve_transaction(&state, &txn_id, &mut sink, &mut output).unwrap();
        assert!(output
            .events
            .last()
            .unwrap()
            .stdout
            .contains("safeshell-toolchain"));
    }

    #[test]
    fn an_unimplemented_command_still_fails_closed_through_the_full_pipeline() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        // `awk` is in the policy tiers' `unsupported` list — recognized,
        // never implemented — and must fail closed as "not implemented",
        // never execute anything, regardless of how many other commands
        // now have real handlers.
        let txn_id =
            submit_command(&state, &session_id, "awk '{}'", &mut sink, &mut output).unwrap();
        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("FAILED"));
    }

    #[test]
    fn shell_invocation_is_still_denied_through_the_full_pipeline() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        let txn_id = submit_command(&state, &session_id, "bash", &mut sink, &mut output).unwrap();
        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("DENIED"));
    }

    #[test]
    fn rejecting_a_pending_transaction_never_touches_the_active_write_layer() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        let txn_id = submit_command(
            &state,
            &session_id,
            "rm -rf /project",
            &mut sink,
            &mut output,
        )
        .unwrap();
        reject_transaction(&state, &txn_id, &mut sink).unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("REJECTED"));
        assert!(detail.execution.is_none());
    }

    #[test]
    fn a_shell_invocation_is_denied_with_the_canonical_reason_surfaced() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        let txn_id = submit_command(&state, &session_id, "bash", &mut sink, &mut output).unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("DENIED"));
        assert!(!detail.policy_reason_codes.is_empty());
        assert!(detail.policy_reason_codes[0]
            .canonical_text
            .contains("shell"));
        assert_eq!(output.events.len(), 1);
    }

    /// The real fail-closed path, not a constructed scenario: uses
    /// [`AppState::new`] (the genuine `PreflightCapabilityChecker` probe),
    /// not `test_state()`'s synthetic all-capabilities-available fixture.
    /// This project's own development sandbox really does lack user
    /// namespaces and a delegated cgroups v2 subtree (see
    /// `sandbox/preflight.rs`'s own tests, which report that honestly),
    /// so `CapabilityReport::execution_available()` is really `false`
    /// here — proving docs/CLAUDE.md invariant #19 end to end against
    /// this machine's actual state, the same way
    /// `namespace_backend::tests::create_session_fails_closed_when_capabilities_are_unavailable`
    /// already does for session creation.
    #[test]
    fn a_real_capability_gap_denies_commands_end_to_end_in_this_environment() {
        let tmp = tempfile::tempdir().unwrap();
        let policies_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../policies/supported_commands.toml"
        );
        let base_image_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../simulated-root-image");
        let state = AppState::new(
            tmp.path().join("data"),
            Path::new(policies_path),
            Path::new(base_image_path),
            Box::new(NullBackend),
        )
        .unwrap();
        if state.capability_report.execution_available() {
            eprintln!(
                "skipping: this machine actually has full sandbox capability, which this test isn't equipped to safely exercise end-to-end"
            );
            return;
        }

        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();
        let txn_id =
            submit_command(&state, &session_id, "mkdir newdir", &mut sink, &mut output).unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(
            detail.final_state.as_deref(),
            Some("DENIED"),
            "a command that would otherwise be low-risk and auto-approved must still fail \
             closed when required sandbox capabilities are unavailable"
        );
        assert!(detail
            .policy_reason_codes
            .iter()
            .any(|r| r.code == "DENY_CAPABILITY_UNAVAILABLE"));
    }

    /// Build order phase 13 ("seed environment"): proves
    /// `seed_base_from_image` is real wiring, not inert files sitting in
    /// a docs folder — a freshly created session can `cat` a file that
    /// only exists because it was seeded from `simulated-root-image/`,
    /// through the full real pipeline (parse → policy → simulate →
    /// snapshot → execute → verify → commit), and the base image's own
    /// manifest files (`nondeterministic-paths.toml`, `mock-users.json`,
    /// `mock-package-db.json`) must never leak into the simulated root
    /// alongside it.
    #[test]
    fn a_fresh_session_is_seeded_with_the_real_base_image_content() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        let txn_id = submit_command(
            &state,
            &session_id,
            "cat project/README.md",
            &mut sink,
            &mut output,
        )
        .unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("COMMITTED"));
        assert_eq!(output.events.len(), 1);
        assert!(
            output.events[0].stdout.contains("Demo Project"),
            "expected the seeded README's real content, got: {:?}",
            output.events[0].stdout
        );

        let base = state
            .sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .stack
            .base
            .clone();
        assert!(base.join("home/user/notes.txt").exists());
        assert!(base.join("etc/hostname").exists());
        assert!(
            !base.join("nondeterministic-paths.toml").exists(),
            "the base image's own manifest files must never be copied into a session's root"
        );
        assert!(!base.join("mock-users.json").exists());
        assert!(!base.join("mock-package-db.json").exists());
    }

    /// Real bug, found via a live interactive session and reproduced
    /// here: `cd` mutates `TerminalSession.cwd`, not the filesystem, so
    /// that mutation is invisible to the diff/verification machinery —
    /// which made it easy for `submit_command` to previously simulate
    /// `cd` against the *real* session instead of a disposable copy,
    /// silently applying the cwd change during simulation (before
    /// approval/execution ever happened) and then having
    /// `executor::execute` apply the same `cd` a *second* time relative
    /// to the already-changed cwd — resolving `cd home` to `home/home`
    /// (which doesn't exist) on the real, user-facing execution pass,
    /// while `cwd` itself silently ended up correct anyway because
    /// simulation's copy had already set it. This test drives the exact
    /// scenario that surfaced it: `cd` into a real seeded top-level
    /// directory must succeed cleanly, with `cwd` changed exactly once.
    #[test]
    fn cd_into_a_seeded_directory_resolves_correctly_and_mutates_cwd_only_once() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        let txn_id =
            submit_command(&state, &session_id, "cd home", &mut sink, &mut output).unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("COMMITTED"));
        assert_eq!(output.events.len(), 1);
        assert_eq!(
            output.events[0].exit_code, 0,
            "cd into a real seeded directory must succeed: stderr={:?}",
            output.events[0].stderr
        );

        let cwd = state
            .sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .terminal
            .cwd()
            .to_string();
        assert_eq!(
            cwd, "/home",
            "cwd must be exactly the target, not doubled by a second internal cd \
             (e.g. \"/home/home\") from simulation and execution both mutating the same session"
        );
    }

    /// End-to-end `rm -rf /project` through the full real pipeline (parse
    /// → policy → simulate → approve → execute → verify → commit) against
    /// the real seeded base image content, not synthetic fixtures — proves
    /// the whiteout mechanism holds together across every layer this
    /// session touched: `LayeredResolver::remove` in both the simulation
    /// pass and the real execution pass, `simulation::diff`'s whiteout
    /// detection feeding both the predicted diff (for the approval panel)
    /// and the actual diff (for verification), and `verification::verify`
    /// agreeing the two sides match so the transaction commits instead of
    /// rolling back.
    #[test]
    fn rm_recursive_on_a_seeded_directory_commits_and_removes_it_end_to_end() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        let txn_id = submit_command(
            &state,
            &session_id,
            "rm -rf /project",
            &mut sink,
            &mut output,
        )
        .unwrap();

        let waiting = get_transaction_state(&state, &txn_id).unwrap();
        assert_eq!(
            waiting.as_deref(),
            Some("WAITING_FOR_APPROVAL"),
            "recursive rm of a non-top-level directory is HIGH risk and must pause"
        );

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        let diff_ready_event = detail
            .events
            .iter()
            .find(|e| e.stage == "DIFF_READY")
            .expect("a DIFF_READY event must have been recorded");
        let metrics: serde_json::Value =
            serde_json::from_str(diff_ready_event.metrics_json.as_deref().unwrap()).unwrap();
        assert!(
            metrics["predicted_diff"]["directories_deleted"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("project")),
            "the approval panel needs to see the predicted deletion: {metrics}"
        );

        approve_transaction(&state, &txn_id, &mut sink, &mut output).unwrap();

        let detail = get_transaction_detail(&state, &txn_id).unwrap();
        assert_eq!(
            detail.final_state.as_deref(),
            Some("COMMITTED"),
            "predicted and actual whiteout-based deletions must agree and commit cleanly"
        );
        assert_eq!(output.events.len(), 1);
        assert_eq!(
            output.events[0].exit_code, 0,
            "stderr: {}",
            output.events[0].stderr
        );

        let active_write = state
            .sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .stack
            .active_write
            .clone();
        assert!(
            active_write.join(".wh.project").exists(),
            "the committed active write layer must carry the whiteout marker forward"
        );

        // A second transaction confirms the deletion is really visible
        // through the full stack, not just in the layer that recorded it.
        let ls_txn = submit_command(&state, &session_id, "ls /", &mut sink, &mut output).unwrap();
        let ls_detail = get_transaction_detail(&state, &ls_txn).unwrap();
        assert_eq!(ls_detail.final_state.as_deref(), Some("COMMITTED"));
        assert!(
            !output.events.last().unwrap().stdout.contains("project"),
            "project must no longer be listed after being removed: {:?}",
            output.events.last().unwrap().stdout
        );
    }

    #[test]
    fn history_lists_the_command_newest_first() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        submit_command(&state, &session_id, "mkdir a", &mut sink, &mut output).unwrap();
        submit_command(&state, &session_id, "mkdir b", &mut sink, &mut output).unwrap();

        let history = get_transaction_history(&state, &session_id, 0).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].raw_command, "mkdir b");
        assert_eq!(history[1].raw_command, "mkdir a");
    }

    #[test]
    fn undo_last_transaction_with_nothing_committed_reports_no_recoverable_checkpoint() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let result = undo_last_transaction(&state, &session_id);
        assert!(matches!(
            result,
            Err(OrchestratorError::NoRecoverableCheckpoint)
        ));
    }

    #[test]
    fn undo_last_transaction_restores_the_state_before_the_last_commit() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        submit_command(&state, &session_id, "mkdir newdir", &mut sink, &mut output).unwrap();
        let outcome = undo_last_transaction(&state, &session_id).unwrap();
        assert!(outcome.success);

        let sessions = state.sessions.lock().unwrap();
        assert!(!sessions
            .get(&session_id)
            .unwrap()
            .stack
            .active_write
            .join("newdir")
            .exists());
    }

    #[test]
    fn restore_to_checkpoint_refuses_an_unknown_checkpoint_id() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let bogus = format!("ckpt_{}", Ulid::new());
        let result = restore_to_checkpoint(&state, &session_id, &bogus);
        assert!(matches!(
            result,
            Err(OrchestratorError::UnknownCheckpoint(_))
        ));
    }

    #[test]
    fn quarantine_recovery_lifts_the_quarantine_and_allows_new_commands() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        state
            .db
            .lock()
            .unwrap()
            .update_session_status(&session_id, "quarantined")
            .unwrap();

        let outcome = quarantine_recovery_reset_to_base(&state, &session_id).unwrap();
        assert!(outcome.success);
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .get_session_status(&session_id)
                .unwrap(),
            Some("active".to_string())
        );

        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();
        let result = submit_command(&state, &session_id, "mkdir newdir", &mut sink, &mut output);
        assert!(
            result.is_ok(),
            "quarantine must be lifted for new commands to be accepted"
        );
    }

    #[test]
    fn get_storage_status_reflects_a_sealed_checkpoint() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();
        let txn_id =
            submit_command(&state, &session_id, "mkdir newdir", &mut sink, &mut output).unwrap();

        let status = get_storage_status(&state, &session_id).unwrap();
        assert_eq!(status.checkpoints_retained, 1);
        assert_eq!(status.max_checkpoints, 10);
        assert_eq!(status.oldest_recoverable_transaction_id, Some(txn_id));
    }

    #[test]
    fn storage_ceiling_reached_fails_closed_before_snapshotting() {
        let (mut state, _tmp) = test_state();
        // A tiny policy this test can actually reach without sealing ten
        // real checkpoints: one retained checkpoint is enough to be "at
        // the count ceiling," and a ten-byte budget is enough to be "over
        // the byte ceiling" once that one checkpoint holds real content.
        state.retention_policy = crate::snapshot::retention::RetentionPolicy {
            max_checkpoints: 1,
            storage_ceiling_bytes: 10,
        };
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        // None of the currently-implemented handlers (`mkdir`, `touch`,
        // …) write nonzero file content, so a checkpoint sealed purely
        // through the pipeline is always 0 bytes — seed real bytes
        // directly into the active write layer first, the same way
        // `rollback`/`snapshot` tests do, so the first command's
        // checkpoint actually carries weight to be over budget.
        let active_write = state
            .sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .stack
            .active_write
            .clone();
        std::fs::write(active_write.join("seed.bin"), vec![0u8; 50]).unwrap();

        // First command seals the one checkpoint this policy allows, now
        // over the byte ceiling too.
        let first =
            submit_command(&state, &session_id, "mkdir newdir", &mut sink, &mut output).unwrap();
        assert_eq!(
            get_transaction_detail(&state, &first)
                .unwrap()
                .final_state
                .as_deref(),
            Some("COMMITTED")
        );

        // A second command needing a snapshot must be refused outright —
        // fail closed, never executed, rather than skip the snapshot to
        // save disk (docs/CLAUDE.md invariant #24).
        let second = submit_command(
            &state,
            &session_id,
            "touch file.txt",
            &mut sink,
            &mut output,
        )
        .unwrap();
        let detail = get_transaction_detail(&state, &second).unwrap();
        assert_eq!(detail.final_state.as_deref(), Some("FAILED"));
        assert!(
            !state
                .sessions
                .lock()
                .unwrap()
                .get(&session_id)
                .unwrap()
                .stack
                .active_write
                .join("file.txt")
                .exists(),
            "a fail-closed transaction must never have executed at all"
        );
    }

    /// Build order phase 13 ("Demo + benchmarks"): real, measured
    /// end-to-end latency for a category-1 (safe, no-approval-pause)
    /// command through the actual `submit_command` pipeline — parse →
    /// policy → AI (`NullBackend`) → simulate → snapshot → execute →
    /// verify → commit — against a real `CopyUpSimulationBackend` and a
    /// real SQLite database, not a mock. Not a `#[bench]` (nightly-only,
    /// unavailable here) and not asserting a specific number (this
    /// sandbox's timing is not representative hardware — see this
    /// function's own `println!`, captured into `docs/benchmarks.md`
    /// verbatim, not fabricated); it exists to produce a real number to
    /// report and to keep producing one on demand, not to gate the build
    /// on a latency budget.
    #[test]
    fn bench_category_one_end_to_end_latency() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        const ITERATIONS: usize = 50;
        let mut samples_us: Vec<u128> = Vec::with_capacity(ITERATIONS);
        for i in 0..ITERATIONS {
            let line = format!("touch file_{i}.txt");
            let start = std::time::Instant::now();
            let txn_id =
                submit_command(&state, &session_id, &line, &mut sink, &mut output).unwrap();
            samples_us.push(start.elapsed().as_micros());
            assert_eq!(
                get_transaction_detail(&state, &txn_id)
                    .unwrap()
                    .final_state
                    .as_deref(),
                Some("COMMITTED")
            );
        }

        samples_us.sort_unstable();
        let p50 = samples_us[ITERATIONS / 2];
        let p95 = samples_us[(ITERATIONS * 95) / 100];
        let max = *samples_us.last().unwrap();
        let mean: u128 = samples_us.iter().sum::<u128>() / ITERATIONS as u128;
        println!(
            "bench_category_one_end_to_end_latency (n={ITERATIONS}, this dev sandbox, \
             CopyUpSimulationBackend, NullBackend): mean={mean}us p50={p50}us p95={p95}us \
             max={max}us"
        );
    }

    /// Same real-measurement posture as
    /// [`bench_category_one_end_to_end_latency`], for the two other
    /// numbers §43's benchmarking table names that are cheap to measure
    /// here: a category-3 `DENIED` command (stops at `POLICY_CHECK`,
    /// never reaches simulation) and session creation (sandbox startup,
    /// §43: "once per session, not per command").
    #[test]
    fn bench_deny_path_and_session_creation_latency() {
        let (state, _tmp) = test_state();
        let session_id = create_session(&state).unwrap();
        let mut sink = CollectingEventSink::default();
        let mut output = CollectingTerminalOutputSink::default();

        const ITERATIONS: usize = 50;
        let mut deny_samples_us: Vec<u128> = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let start = std::time::Instant::now();
            let txn_id =
                submit_command(&state, &session_id, "bash", &mut sink, &mut output).unwrap();
            deny_samples_us.push(start.elapsed().as_micros());
            assert_eq!(
                get_transaction_detail(&state, &txn_id)
                    .unwrap()
                    .final_state
                    .as_deref(),
                Some("DENIED")
            );
        }
        deny_samples_us.sort_unstable();
        let deny_p50 = deny_samples_us[ITERATIONS / 2];
        let deny_mean: u128 = deny_samples_us.iter().sum::<u128>() / ITERATIONS as u128;

        let mut session_samples_us: Vec<u128> = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let start = std::time::Instant::now();
            create_session(&state).unwrap();
            session_samples_us.push(start.elapsed().as_micros());
        }
        session_samples_us.sort_unstable();
        let session_p50 = session_samples_us[ITERATIONS / 2];
        let session_mean: u128 = session_samples_us.iter().sum::<u128>() / ITERATIONS as u128;

        println!("bench_deny_path_latency (n={ITERATIONS}): mean={deny_mean}us p50={deny_p50}us");
        println!(
            "bench_session_creation_latency (n={ITERATIONS}): mean={session_mean}us \
             p50={session_p50}us"
        );
    }
}

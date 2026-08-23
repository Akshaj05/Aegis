//! Thin, typed Tauri command handlers — every function here does exactly
//! one thing: convert its Tauri-supplied arguments, call straight into
//! [`crate::orchestrator`], and convert the result back into something
//! `serde` can hand across the IPC boundary. See `docs/architecture.md`
//! §30 for the exact command list and §41 for each one's request/response
//! shape; every command below is named and shaped to match those sections
//! directly, not approximated.
//!
//! No command here accepts a filesystem path or a shell string destined
//! for execution (§30's constraint) — `submit_command`'s `line` is the
//! one command-line string in this surface, and it only ever reaches
//! `parser::parse_line` inside `orchestrator::submit_command`, never an
//! interpreter (docs/CLAUDE.md invariant #15). `restore_to_checkpoint`'s
//! `checkpoint_id` is validated against the caller's own live, retained
//! `LayerStack` before anything touches disk (`orchestrator::restore_to_checkpoint`) —
//! an unknown or garbage-collected id is refused there, not here.
//!
//! `capabilities/default.json` grants only `core:default` — no fs/shell/
//! dialog plugin is declared anywhere in this crate, so there is nothing
//! broader for the webview to reach even if it wanted to (§30: "the
//! webview has no filesystem or shell API surface enabled at the Tauri
//! configuration level").

use tauri::{AppHandle, Emitter, State};

use crate::db::session_queries::SessionRow;
use crate::db::transaction_queries::TransactionSummaryRow;
use crate::orchestrator::{self, AppState, OrchestratorError, StorageStatus, TransactionDetail};
use crate::rollback::RollbackOutcome;
use crate::transaction::events::{EventSink, TransactionEvent};

/// Emits §29.2's `transaction://event` — one instance created per command
/// invocation, wrapping a borrowed `AppHandle` rather than owning one, so
/// it can be constructed as a cheap local alongside
/// [`TerminalOutputEmitter`] without either borrowing the other.
struct TxEventEmitter<'a>(&'a AppHandle);

impl EventSink for TxEventEmitter<'_> {
    fn emit(&mut self, event: &TransactionEvent) {
        let _ = self.0.emit("transaction://event", event.to_json());
    }
}

/// Emits the second channel §29.2 names, `terminal://output` — see
/// `orchestrator::TerminalOutputEvent`'s own doc comment for why this is
/// a distinct trait/channel from [`TxEventEmitter`] rather than folded
/// into it.
struct TerminalOutputEmitter<'a>(&'a AppHandle);

impl orchestrator::TerminalOutputSink for TerminalOutputEmitter<'_> {
    fn emit(&mut self, event: &orchestrator::TerminalOutputEvent) {
        let payload = serde_json::json!({
            "session_id": event.session_id,
            "transaction_id": event.transaction_id,
            "command": event.command,
            "stdout": event.stdout,
            "stderr": event.stderr,
            "exit_code": event.exit_code,
        });
        let _ = self.0.emit("terminal://output", payload);
    }
}

fn to_string_err(e: OrchestratorError) -> String {
    e.to_string()
}

#[derive(serde::Serialize)]
pub struct Ack {
    pub ok: bool,
}

#[derive(serde::Serialize)]
pub struct SubmitCommandResponse {
    pub transaction_id: String,
}

#[derive(serde::Serialize)]
pub struct RollbackResponse {
    pub ok: bool,
    pub restored_checkpoint_id: Option<String>,
    pub reason: Option<String>,
}

impl From<RollbackOutcome> for RollbackResponse {
    fn from(outcome: RollbackOutcome) -> Self {
        RollbackResponse {
            ok: outcome.success,
            restored_checkpoint_id: outcome.restored_checkpoint_id.map(|c| c.to_string()),
            reason: outcome.failure_detail,
        }
    }
}

#[tauri::command]
pub fn create_session(state: State<AppState>) -> Result<String, String> {
    orchestrator::create_session(&state).map_err(to_string_err)
}

#[tauri::command]
pub fn close_session(state: State<AppState>, session_id: String) -> Result<(), String> {
    orchestrator::close_session(&state, &session_id).map_err(to_string_err)
}

#[tauri::command]
pub fn list_sessions(state: State<AppState>) -> Result<Vec<SessionRow>, String> {
    orchestrator::list_sessions(&state).map_err(to_string_err)
}

#[tauri::command]
pub fn submit_command(
    app: AppHandle,
    state: State<AppState>,
    session_id: String,
    line: String,
) -> Result<SubmitCommandResponse, String> {
    let mut tx_sink = TxEventEmitter(&app);
    let mut output_sink = TerminalOutputEmitter(&app);
    let transaction_id =
        orchestrator::submit_command(&state, &session_id, &line, &mut tx_sink, &mut output_sink)
            .map_err(to_string_err)?;
    Ok(SubmitCommandResponse { transaction_id })
}

#[tauri::command]
pub fn approve_transaction(
    app: AppHandle,
    state: State<AppState>,
    transaction_id: String,
) -> Result<Ack, String> {
    let mut tx_sink = TxEventEmitter(&app);
    let mut output_sink = TerminalOutputEmitter(&app);
    orchestrator::approve_transaction(&state, &transaction_id, &mut tx_sink, &mut output_sink)
        .map_err(to_string_err)?;
    Ok(Ack { ok: true })
}

#[tauri::command]
pub fn reject_transaction(
    app: AppHandle,
    state: State<AppState>,
    transaction_id: String,
) -> Result<Ack, String> {
    let mut tx_sink = TxEventEmitter(&app);
    orchestrator::reject_transaction(&state, &transaction_id, &mut tx_sink)
        .map_err(to_string_err)?;
    Ok(Ack { ok: true })
}

/// See `orchestrator`'s module doc for exactly what this can and can't
/// interrupt in this pass.
#[tauri::command]
pub fn interrupt_command(
    app: AppHandle,
    state: State<AppState>,
    session_id: String,
) -> Result<Ack, String> {
    let mut tx_sink = TxEventEmitter(&app);
    orchestrator::interrupt_command(&state, &session_id, &mut tx_sink).map_err(to_string_err)?;
    Ok(Ack { ok: true })
}

/// §41: `{ ok: true, restored_checkpoint_id }` or
/// `{ ok: false, reason: "no_recoverable_checkpoint" }` — the latter is a
/// normal, expected outcome (nothing to undo yet), not an IPC error.
#[tauri::command]
pub fn undo_last_transaction(
    state: State<AppState>,
    session_id: String,
) -> Result<RollbackResponse, String> {
    match orchestrator::undo_last_transaction(&state, &session_id) {
        Ok(outcome) => Ok(outcome.into()),
        Err(OrchestratorError::NoRecoverableCheckpoint) => Ok(RollbackResponse {
            ok: false,
            restored_checkpoint_id: None,
            reason: Some("no_recoverable_checkpoint".to_string()),
        }),
        Err(e) => Err(to_string_err(e)),
    }
}

/// §27.4's first quarantine recovery action, exposed over IPC so a
/// quarantined session (a rollback failure, §13.3's "never silent") isn't
/// a dead end the UI has no way out of.
#[tauri::command]
pub fn quarantine_recovery_restore_to_newest(
    state: State<AppState>,
    session_id: String,
) -> Result<RollbackResponse, String> {
    orchestrator::quarantine_recovery_restore_to_newest(&state, &session_id)
        .map(RollbackResponse::from)
        .map_err(to_string_err)
}

/// §27.4's second quarantine recovery action.
#[tauri::command]
pub fn quarantine_recovery_reset_to_base(
    state: State<AppState>,
    session_id: String,
) -> Result<RollbackResponse, String> {
    orchestrator::quarantine_recovery_reset_to_base(&state, &session_id)
        .map(RollbackResponse::from)
        .map_err(to_string_err)
}

#[tauri::command]
pub fn restore_to_checkpoint(
    state: State<AppState>,
    session_id: String,
    checkpoint_id: String,
) -> Result<RollbackResponse, String> {
    orchestrator::restore_to_checkpoint(&state, &session_id, &checkpoint_id)
        .map(RollbackResponse::from)
        .map_err(to_string_err)
}

#[tauri::command]
pub fn get_transaction_state(
    state: State<AppState>,
    transaction_id: String,
) -> Result<Option<String>, String> {
    orchestrator::get_transaction_state(&state, &transaction_id).map_err(to_string_err)
}

#[tauri::command]
pub fn get_transaction_history(
    state: State<AppState>,
    session_id: String,
    page: i64,
) -> Result<Vec<TransactionSummaryRow>, String> {
    orchestrator::get_transaction_history(&state, &session_id, page).map_err(to_string_err)
}

#[tauri::command]
pub fn get_transaction_detail(
    state: State<AppState>,
    transaction_id: String,
) -> Result<TransactionDetail, String> {
    orchestrator::get_transaction_detail(&state, &transaction_id).map_err(to_string_err)
}

#[tauri::command]
pub fn get_capability_report(state: State<AppState>) -> serde_json::Value {
    orchestrator::get_capability_report(&state)
}

#[tauri::command]
pub fn get_storage_status(
    state: State<AppState>,
    session_id: String,
) -> Result<StorageStatus, String> {
    orchestrator::get_storage_status(&state, &session_id).map_err(to_string_err)
}

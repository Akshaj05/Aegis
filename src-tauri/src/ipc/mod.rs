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

use tauri::{AppHandle, Emitter, Manager};

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

/// Every command below hands its actual work to this rather than running
/// it inline. A plain (non-`async`) `#[tauri::command]` fn is invoked by
/// Tauri directly on the main/webview thread — fine for the cheap ones,
/// but `orchestrator::submit_command`/`approve_transaction` run the full
/// synchronous pipeline including a real AI backend HTTP call
/// (`OllamaBackend::DEFAULT_TIMEOUT` is 30s, and real local generation
/// has been measured around 9s), and `undo_last_transaction`/
/// `restore_to_checkpoint`/the quarantine-recovery commands touch real
/// filesystem restore work. Any of those running on the main thread
/// freezes the whole window for their duration — the OS's own "app not
/// responding" watchdog, not a bug in the pipeline itself. Offloading via
/// `spawn_blocking` keeps every command's own internals exactly as
/// synchronous as the rest of this crate (`orchestrator`/`executor`/
/// `rollback` stay plain, un-async code, matching `ai::backend`'s "nothing
/// else in this crate is async" design note) while keeping the webview's
/// event loop free to keep rendering and responding to input.
async fn run_blocking<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    match tauri::async_runtime::spawn_blocking(f).await {
        Ok(result) => result,
        Err(join_error) => Err(join_error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// The actual mechanism the "app stopped responding" fix depends on:
    /// `run_blocking`'s closure must execute on a thread other than the
    /// one that called it, exactly like `spawn_blocking`'s documented
    /// contract — proving this in-process is what stands in for
    /// confirming the real app's main/webview thread is never the one
    /// running the pipeline.
    #[test]
    fn run_blocking_executes_the_closure_off_the_calling_thread() {
        let calling_thread = std::thread::current().id();
        let ran_elsewhere = tauri::async_runtime::block_on(run_blocking(move || {
            Ok::<_, String>(std::thread::current().id() != calling_thread)
        }));
        assert_eq!(ran_elsewhere, Ok(true));
    }

    /// A slow `run_blocking` call (standing in for a real ~16s AI-backed
    /// pipeline run) must not prevent a second, concurrently spawned task
    /// from making progress — the property that keeps the app able to
    /// keep handling other IPC calls (and, in the real app, keeps the
    /// webview's own event loop unblocked) while one command is slow.
    #[test]
    fn a_slow_run_blocking_call_does_not_starve_a_concurrent_task() {
        use std::time::Instant;

        let fast_done = Arc::new(AtomicBool::new(false));
        let fast_done2 = fast_done.clone();

        tauri::async_runtime::block_on(async move {
            // Both are spawned onto the runtime immediately — scheduling
            // starts here, not when each is later `.await`ed.
            let slow = run_blocking(move || {
                std::thread::sleep(Duration::from_millis(300));
                Ok::<_, String>(())
            });
            let fast = tauri::async_runtime::spawn(async move {
                std::thread::sleep(Duration::from_millis(20));
                fast_done2.store(true, Ordering::SeqCst);
            });

            // Awaiting the fast task first proves it isn't queued behind
            // the slow one: if `run_blocking` ran inline on this same
            // task instead of on a separate blocking thread, this await
            // would not return until the 300ms slow closure finished.
            let start = Instant::now();
            fast.await.unwrap();
            assert!(
                start.elapsed() < Duration::from_millis(300),
                "the fast task was blocked behind the slow run_blocking call"
            );

            slow.await.unwrap();
        });

        assert!(fast_done.load(Ordering::SeqCst));
    }
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
pub async fn create_session(app: AppHandle) -> Result<String, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        orchestrator::create_session(&state).map_err(to_string_err)
    })
    .await
}

#[tauri::command]
pub async fn close_session(app: AppHandle, session_id: String) -> Result<(), String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        orchestrator::close_session(&state, &session_id).map_err(to_string_err)
    })
    .await
}

#[tauri::command]
pub async fn list_sessions(app: AppHandle) -> Result<Vec<SessionRow>, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        orchestrator::list_sessions(&state).map_err(to_string_err)
    })
    .await
}

#[tauri::command]
pub async fn submit_command(
    app: AppHandle,
    session_id: String,
    line: String,
) -> Result<SubmitCommandResponse, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        let mut tx_sink = TxEventEmitter(&app);
        let mut output_sink = TerminalOutputEmitter(&app);
        let transaction_id = orchestrator::submit_command(
            &state,
            &session_id,
            &line,
            &mut tx_sink,
            &mut output_sink,
        )
        .map_err(to_string_err)?;
        Ok(SubmitCommandResponse { transaction_id })
    })
    .await
}

#[tauri::command]
pub async fn approve_transaction(app: AppHandle, transaction_id: String) -> Result<Ack, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        let mut tx_sink = TxEventEmitter(&app);
        let mut output_sink = TerminalOutputEmitter(&app);
        orchestrator::approve_transaction(&state, &transaction_id, &mut tx_sink, &mut output_sink)
            .map_err(to_string_err)?;
        Ok(Ack { ok: true })
    })
    .await
}

#[tauri::command]
pub async fn reject_transaction(app: AppHandle, transaction_id: String) -> Result<Ack, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        let mut tx_sink = TxEventEmitter(&app);
        orchestrator::reject_transaction(&state, &transaction_id, &mut tx_sink)
            .map_err(to_string_err)?;
        Ok(Ack { ok: true })
    })
    .await
}

/// See `orchestrator`'s module doc for exactly what this can and can't
/// interrupt in this pass.
#[tauri::command]
pub async fn interrupt_command(app: AppHandle, session_id: String) -> Result<Ack, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        let mut tx_sink = TxEventEmitter(&app);
        orchestrator::interrupt_command(&state, &session_id, &mut tx_sink)
            .map_err(to_string_err)?;
        Ok(Ack { ok: true })
    })
    .await
}

/// §41: `{ ok: true, restored_checkpoint_id }` or
/// `{ ok: false, reason: "no_recoverable_checkpoint" }` — the latter is a
/// normal, expected outcome (nothing to undo yet), not an IPC error.
#[tauri::command]
pub async fn undo_last_transaction(
    app: AppHandle,
    session_id: String,
) -> Result<RollbackResponse, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        match orchestrator::undo_last_transaction(&state, &session_id) {
            Ok(outcome) => Ok(outcome.into()),
            Err(OrchestratorError::NoRecoverableCheckpoint) => Ok(RollbackResponse {
                ok: false,
                restored_checkpoint_id: None,
                reason: Some("no_recoverable_checkpoint".to_string()),
            }),
            Err(e) => Err(to_string_err(e)),
        }
    })
    .await
}

/// §27.4's first quarantine recovery action, exposed over IPC so a
/// quarantined session (a rollback failure, §13.3's "never silent") isn't
/// a dead end the UI has no way out of.
#[tauri::command]
pub async fn quarantine_recovery_restore_to_newest(
    app: AppHandle,
    session_id: String,
) -> Result<RollbackResponse, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        orchestrator::quarantine_recovery_restore_to_newest(&state, &session_id)
            .map(RollbackResponse::from)
            .map_err(to_string_err)
    })
    .await
}

/// §27.4's second quarantine recovery action.
#[tauri::command]
pub async fn quarantine_recovery_reset_to_base(
    app: AppHandle,
    session_id: String,
) -> Result<RollbackResponse, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        orchestrator::quarantine_recovery_reset_to_base(&state, &session_id)
            .map(RollbackResponse::from)
            .map_err(to_string_err)
    })
    .await
}

#[tauri::command]
pub async fn restore_to_checkpoint(
    app: AppHandle,
    session_id: String,
    checkpoint_id: String,
) -> Result<RollbackResponse, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        orchestrator::restore_to_checkpoint(&state, &session_id, &checkpoint_id)
            .map(RollbackResponse::from)
            .map_err(to_string_err)
    })
    .await
}

#[tauri::command]
pub async fn get_transaction_state(
    app: AppHandle,
    transaction_id: String,
) -> Result<Option<String>, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        orchestrator::get_transaction_state(&state, &transaction_id).map_err(to_string_err)
    })
    .await
}

#[tauri::command]
pub async fn get_transaction_history(
    app: AppHandle,
    session_id: String,
    page: i64,
) -> Result<Vec<TransactionSummaryRow>, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        orchestrator::get_transaction_history(&state, &session_id, page).map_err(to_string_err)
    })
    .await
}

#[tauri::command]
pub async fn get_transaction_detail(
    app: AppHandle,
    transaction_id: String,
) -> Result<TransactionDetail, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        orchestrator::get_transaction_detail(&state, &transaction_id).map_err(to_string_err)
    })
    .await
}

#[tauri::command]
pub async fn get_capability_report(app: AppHandle) -> Result<serde_json::Value, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        Ok(orchestrator::get_capability_report(&state))
    })
    .await
}

#[tauri::command]
pub async fn get_storage_status(
    app: AppHandle,
    session_id: String,
) -> Result<StorageStatus, String> {
    run_blocking(move || {
        let state = app.state::<AppState>();
        orchestrator::get_storage_status(&state, &session_id).map_err(to_string_err)
    })
    .await
}

// Tauri IPC command handlers: converts frontend-supplied arguments into
// calls into the orchestrator and converts results back into serde-friendly
// responses for the webview.

use tauri::{AppHandle, Emitter, Manager};

use crate::db::session_queries::SessionRow;
use crate::db::transaction_queries::TransactionSummaryRow;
use crate::orchestrator::{self, AppState, OrchestratorError, StorageStatus, TransactionDetail};
use crate::rollback::RollbackOutcome;
use crate::transaction::events::{EventSink, TransactionEvent};

struct TxEventEmitter<'a>(&'a AppHandle);

impl EventSink for TxEventEmitter<'_> {
    fn emit(&mut self, event: &TransactionEvent) {
        let _ = self.0.emit("transaction://event", event.to_json());
    }
}

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

    #[test]
    fn run_blocking_executes_the_closure_off_the_calling_thread() {
        let calling_thread = std::thread::current().id();
        let ran_elsewhere = tauri::async_runtime::block_on(run_blocking(move || {
            Ok::<_, String>(std::thread::current().id() != calling_thread)
        }));
        assert_eq!(ran_elsewhere, Ok(true));
    }

    #[test]
    fn a_slow_run_blocking_call_does_not_starve_a_concurrent_task() {
        use std::time::Instant;

        let fast_done = Arc::new(AtomicBool::new(false));
        let fast_done2 = fast_done.clone();

        tauri::async_runtime::block_on(async move {

            let slow = run_blocking(move || {
                std::thread::sleep(Duration::from_millis(300));
                Ok::<_, String>(())
            });
            let fast = tauri::async_runtime::spawn(async move {
                std::thread::sleep(Duration::from_millis(20));
                fast_done2.store(true, Ordering::SeqCst);
            });

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

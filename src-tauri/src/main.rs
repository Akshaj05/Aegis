#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Desktop application entry point: selects the AI backend from environment
// configuration, resolves the data/policy/base-image paths, builds
// AppState, and launches the Tauri app with its IPC command handlers.

use std::path::PathBuf;

use safeshell::ai::backend::{AiBackend, NullBackend, OllamaBackend, RemoteBackend};
use safeshell::orchestrator::AppState;

fn build_ai_backend() -> Box<dyn AiBackend + Send + Sync> {
    if let Ok(model) = std::env::var("SAFESHELL_OLLAMA_MODEL") {
        if !model.is_empty() {
            let endpoint = std::env::var("SAFESHELL_OLLAMA_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "http://localhost:11434".to_string());
            let mut backend = OllamaBackend::new(endpoint, model);
            if let Ok(ms) = std::env::var("SAFESHELL_OLLAMA_TIMEOUT_MS") {
                if let Ok(ms) = ms.parse::<u64>() {
                    backend = backend.with_timeout(std::time::Duration::from_millis(ms));
                }
            }
            return Box::new(backend);
        }
    }

    match std::env::var("SAFESHELL_AI_ENDPOINT") {
        Ok(endpoint) if !endpoint.is_empty() => {
            let mut backend = RemoteBackend::new(endpoint);
            if let Ok(key) = std::env::var("SAFESHELL_AI_API_KEY") {
                if !key.is_empty() {
                    backend = backend.with_api_key(key);
                }
            }
            Box::new(backend)
        }
        _ => Box::new(NullBackend),
    }
}

fn data_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("safeshell");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".local/share/safeshell");
        }
    }
    std::env::temp_dir().join("safeshell")
}

fn main() {

    let _ = dotenvy::dotenv();

    let ai_backend = build_ai_backend();

    let policies_path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../policies/supported_commands.toml"
    ));
    let base_image_path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../simulated-root-image"
    ));

    let state = AppState::new(data_dir(), &policies_path, &base_image_path, ai_backend)
        .expect("failed to initialize SafeShell application state");

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            safeshell::ipc::create_session,
            safeshell::ipc::close_session,
            safeshell::ipc::list_sessions,
            safeshell::ipc::submit_command,
            safeshell::ipc::approve_transaction,
            safeshell::ipc::reject_transaction,
            safeshell::ipc::interrupt_command,
            safeshell::ipc::undo_last_transaction,
            safeshell::ipc::restore_to_checkpoint,
            safeshell::ipc::quarantine_recovery_restore_to_newest,
            safeshell::ipc::quarantine_recovery_reset_to_base,
            safeshell::ipc::get_transaction_state,
            safeshell::ipc::get_transaction_history,
            safeshell::ipc::get_transaction_detail,
            safeshell::ipc::get_capability_report,
            safeshell::ipc::get_storage_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the SafeShell desktop shell");
}

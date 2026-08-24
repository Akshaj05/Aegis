#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use safeshell::ai::backend::{AiBackend, NullBackend, OllamaBackend, RemoteBackend};
use safeshell::orchestrator::AppState;

/// §21.10: "local versus remote model" is a deployment choice, not a
/// compile-time one — `NullBackend` must be a fully working configuration
/// at every phase (docs/CLAUDE.md's Build order closing note), so the
/// default here is `NullBackend`. Three mutually exclusive opt-ins, local
/// checked first since it's the deployment §21.10 calls out as needing no
/// external dependency or API key:
///
/// - `SAFESHELL_OLLAMA_MODEL` set → `OllamaBackend` against a local Ollama
///   server, defaulting to `http://localhost:11434` unless
///   `SAFESHELL_OLLAMA_ENDPOINT` overrides it, and to
///   `OllamaBackend::DEFAULT_TIMEOUT` (30s — see that type's doc comment
///   for why it differs from §21.9's 2.5s) unless
///   `SAFESHELL_OLLAMA_TIMEOUT_MS` overrides it.
/// - else `SAFESHELL_AI_ENDPOINT` set → `RemoteBackend` (`ai::backend`,
///   Build order phase 9) against that endpoint; `SAFESHELL_AI_API_KEY` is
///   optional on top of that.
/// - else `NullBackend`.
///
/// AI unavailability of any kind (nothing configured, unreachable, timed
/// out, malformed output) never blocks the pipeline (§21.9) — it only
/// ever changes which `AiBackend` this app was started with.
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

/// `$XDG_DATA_HOME/safeshell` (falling back to `$HOME/.local/share/safeshell`,
/// then the system temp dir if even `$HOME` is unset) — where the SQLite
/// database and every session's on-disk layers live. Not `~/SafeShellLab/`
/// or any other name implying that directory itself *is* the isolation
/// boundary (docs/CLAUDE.md invariant #18) — it is ordinary SafeShell
/// application state, no different in kind from any other desktop app's
/// data directory; the real isolation is the layer/simulation model this
/// directory's contents are managed through, not the directory's location.
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
    // Best-effort: populates `std::env` from `src-tauri/.env` if that file
    // exists, so `SAFESHELL_OLLAMA_MODEL` and friends survive across
    // launches without needing to be exported in whatever shell starts the
    // app. Never overrides a variable already set in the real environment
    // (`dotenvy::dotenv`'s documented behavior), and does nothing at all
    // when no `.env` file is present — `build_ai_backend` below falls back
    // to `NullBackend` exactly as before in that case.
    let _ = dotenvy::dotenv();

    let ai_backend = build_ai_backend();
    // Dev-only resolution: `policies/` and `simulated-root-image/` are
    // siblings of `src-tauri/` in this repository, resolved at compile
    // time via `CARGO_MANIFEST_DIR`. A packaged, installed build would
    // need these bundled as Tauri resources instead — real packaging/
    // distribution is future work beyond this MVP, stated here rather
    // than silently assumed solved.
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

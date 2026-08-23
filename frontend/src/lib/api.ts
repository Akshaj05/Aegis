// Thin wrapper over `@tauri-apps/api` — the entire IPC surface this
// frontend is allowed to use, matching `docs/architecture.md` §30's
// command list exactly. Nothing outside this file should call `invoke`
// or `listen` directly (docs/CLAUDE.md: "Frontend is a pure renderer of
// the event stream. No hardcoded timelines, no client-side risk logic,
// no derived security decisions.") — every decision behind these calls
// was already made by the Rust core before the response/event arrives.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  Ack,
  CapabilityReport,
  RollbackResponse,
  SessionRow,
  StorageStatus,
  SubmitCommandResponse,
  TerminalOutputEvent,
  TransactionDetail,
  TransactionEvent,
  TransactionSummaryRow,
} from "./types";

export const api = {
  createSession: () => invoke<string>("create_session"),
  closeSession: (sessionId: string) => invoke<void>("close_session", { sessionId }),
  listSessions: () => invoke<SessionRow[]>("list_sessions"),

  submitCommand: (sessionId: string, line: string) =>
    invoke<SubmitCommandResponse>("submit_command", { sessionId, line }),
  approveTransaction: (transactionId: string) =>
    invoke<Ack>("approve_transaction", { transactionId }),
  rejectTransaction: (transactionId: string) =>
    invoke<Ack>("reject_transaction", { transactionId }),
  interruptCommand: (sessionId: string) => invoke<Ack>("interrupt_command", { sessionId }),

  undoLastTransaction: (sessionId: string) =>
    invoke<RollbackResponse>("undo_last_transaction", { sessionId }),
  restoreToCheckpoint: (sessionId: string, checkpointId: string) =>
    invoke<RollbackResponse>("restore_to_checkpoint", { sessionId, checkpointId }),
  quarantineRecoveryRestoreToNewest: (sessionId: string) =>
    invoke<RollbackResponse>("quarantine_recovery_restore_to_newest", { sessionId }),
  quarantineRecoveryResetToBase: (sessionId: string) =>
    invoke<RollbackResponse>("quarantine_recovery_reset_to_base", { sessionId }),

  getTransactionState: (transactionId: string) =>
    invoke<string | null>("get_transaction_state", { transactionId }),
  getTransactionHistory: (sessionId: string, page: number) =>
    invoke<TransactionSummaryRow[]>("get_transaction_history", { sessionId, page }),
  getTransactionDetail: (transactionId: string) =>
    invoke<TransactionDetail>("get_transaction_detail", { transactionId }),
  getCapabilityReport: () => invoke<CapabilityReport>("get_capability_report"),
  getStorageStatus: (sessionId: string) =>
    invoke<StorageStatus>("get_storage_status", { sessionId }),
};

/** §29.1: "Every state transition... emits an event, unconditionally." */
export function onTransactionEvent(
  handler: (event: TransactionEvent) => void,
): Promise<UnlistenFn> {
  return listen<TransactionEvent>("transaction://event", (e) => handler(e.payload));
}

export function onTerminalOutput(
  handler: (event: TerminalOutputEvent) => void,
): Promise<UnlistenFn> {
  return listen<TerminalOutputEvent>("terminal://output", (e) => handler(e.payload));
}

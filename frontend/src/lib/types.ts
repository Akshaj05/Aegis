// TypeScript type definitions mirroring the backend IPC/event payloads
// used throughout the frontend.
export type TransactionStage =
  | "RECEIVED"
  | "PARSED"
  | "POLICY_CHECK"
  | "AI_ANALYSIS"
  | "SIMULATING"
  | "DIFF_READY"
  | "WAITING_FOR_APPROVAL"
  | "SNAPSHOTTING"
  | "EXECUTING"
  | "VERIFYING"
  | "COMMITTED"
  | "ROLLING_BACK"
  | "RESTORED"
  | "REJECTED"
  | "DENIED"
  | "FAILED"
  | "ROLLBACK_FAILED";

export const TERMINAL_STAGES: readonly TransactionStage[] = [
  "COMMITTED",
  "REJECTED",
  "DENIED",
  "FAILED",
  "RESTORED",
  "ROLLBACK_FAILED",
];

export type EventStatus = "started" | "in_progress" | "completed" | "failed";
export type Category = "safe" | "dangerous_containable" | "unsafe_to_contain";
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface TransactionEvent {
  transaction_id: string;
  session_id: string;
  command: string;
  stage: TransactionStage;
  status: EventStatus;
  timestamp: string;
  duration_ms: number | null;
  category: Category | null;
  policy_risk_level: RiskLevel | null;
  metrics: Record<string, unknown> | null;
  message: string;
  sequence: number;
}

export interface TerminalOutputEvent {
  session_id: string;
  transaction_id: string;
  command: string;
  stdout: string;
  stderr: string;
  exit_code: number;
}

export interface PredictedDiff {
  files_created: string[];
  files_modified: string[];
  directories_created: string[];
  files_deleted: string[];
  directories_deleted: string[];
  bytes_affected: number;
  bytes_deleted: number;
}

export interface SessionRow {
  id: string;
  created_at: string;
  simulation_backend: string | null;
  status: string;
}

export interface TransactionSummaryRow {
  id: string;
  raw_command: string;
  final_state: string | null;
  category: string | null;
  policy_risk_level: string | null;
  requires_approval: boolean | null;
  created_at: string;
  completed_at: string | null;
}

export interface TransactionEventRow {
  transaction_id: string;
  stage: string;
  status: string;
  timestamp: string;
  duration_ms: number | null;
  metrics_json: string | null;
  message: string;
  sequence: number;
}

export interface ExecutionResultRow {
  exit_code: number;
  stdout: string;
  stderr: string;
  files_created: number;
  files_modified: number;
  files_deleted: number;
  bytes_affected: number;
  executed_at: string;
}

export interface VerificationDetail {
  matched: boolean;
  mismatch_kind: string | null;
  mismatch_details: string | null;
}

export interface AiPlanDetail {
  schema_version: string | null;
  intent: string | null;
  risk_level: string | null;
  confidence: number | null;
  recovery_recommendation: { strategy?: string; description?: string } | null;
  explanation: string | null;
  divergence: Record<string, unknown> | null;
}

export interface DenyReasonDetail {
  code: string;
  canonical_text: string;
}

export interface TransactionDetail {
  transaction_id: string;
  command: string;
  final_state: string | null;
  category: string | null;
  support_tier: string | null;
  policy_risk_level: string | null;
  policy_reason_codes: DenyReasonDetail[];
  events: TransactionEventRow[];
  ai_plan: AiPlanDetail | null;
  ai_skipped: boolean | null;
  ai_skipped_reason: string | null;
  requires_approval: boolean | null;
  approved_by_user: boolean | null;
  execution: ExecutionResultRow | null;
  verification: VerificationDetail | null;
  recoverable: boolean;
  created_at: string;
  completed_at: string | null;
}

export interface CapabilityReport {
  user_namespaces: string;
  mount_namespaces: string;
  pid_namespaces: string;
  seccomp: string;
  cgroups_v2: string;
  landlock: string;
  overlayfs: string;
  openat2: string;
  execution_available: boolean;
  degradations: string[];
}

export interface StorageStatus {
  checkpoints_retained: number;
  max_checkpoints: number;
  bytes_used: number;
  ceiling_bytes: number;
  oldest_recoverable_transaction_id: string | null;
}

export interface Ack {
  ok: boolean;
}

export interface SubmitCommandResponse {
  transaction_id: string;
}

export interface RollbackResponse {
  ok: boolean;
  restored_checkpoint_id: string | null;
  reason: string | null;
}

export function extractPredictedDiff(event: TransactionEvent): PredictedDiff | null {
  const metrics = event.metrics as { predicted_diff?: PredictedDiff } | null;
  return metrics?.predicted_diff ?? null;
}

export interface FlowEvent {
  stage: string;
  status: string;
  duration_ms: number | null;
}

export function detailEventsToFlowEvents(detail: TransactionDetail): FlowEvent[] {
  return detail.events.map((e) => ({
    stage: e.stage,
    status: e.status,
    duration_ms: e.duration_ms,
  }));
}

export function extractPredictedDiffFromDetail(detail: TransactionDetail): PredictedDiff | null {
  const diffReady = detail.events.find((e) => e.stage === "DIFF_READY");
  if (!diffReady?.metrics_json) return null;
  try {
    const metrics = JSON.parse(diffReady.metrics_json) as { predicted_diff?: PredictedDiff };
    return metrics.predicted_diff ?? null;
  } catch {
    return null;
  }
}

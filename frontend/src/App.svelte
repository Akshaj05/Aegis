<script lang="ts">
  // Root app component: owns session/transaction state, subscribes to
  // IPC events, and wires the terminal, pipeline view, and side panels
  // together.
  import { onMount } from "svelte";
  import Terminal from "./terminal/Terminal.svelte";
  import ApprovalPanel from "./transaction/ApprovalPanel.svelte";
  import DenyPanel from "./transaction/DenyPanel.svelte";
  import UnsupportedNotice from "./transaction/UnsupportedNotice.svelte";
  import History from "./transaction/History.svelte";
  import Badge from "./transaction/Badge.svelte";
  import TopBar from "./TopBar.svelte";
  import PipelineFlow from "./visualization/PipelineFlow.svelte";
  import { api, onTerminalOutput, onTransactionEvent } from "./lib/api";
  import { TERMINAL_STAGES, detailEventsToFlowEvents } from "./lib/types";
  import type {
    CapabilityReport,
    FlowEvent,
    SessionRow,
    StorageStatus,
    TransactionDetail,
    TransactionSummaryRow,
  } from "./lib/types";
  import { categoryLabel, categoryTone, riskLabel, riskTone } from "./lib/format";

  let terminalRef: Terminal;

  let sessionId: string | null = null;
  let simulationBackend: string | null = null;
  let capabilityReport: CapabilityReport | null = null;
  let storageStatus: StorageStatus | null = null;
  let historyItems: TransactionSummaryRow[] = [];

  let activeTransactionId: string | null = null;
  let activeTransactionEvents: FlowEvent[] = [];
  let currentCategory: string | null = null;
  let currentRisk: string | null = null;
  let viewingHistorical = false;

  $: displayedEvents = viewingHistorical && panelDetail
    ? detailEventsToFlowEvents(panelDetail)
    : activeTransactionEvents;
  $: displayedCategory = viewingHistorical && panelDetail ? panelDetail.category : currentCategory;
  let panelDetail: TransactionDetail | null = null;
  let panelKind: "approval" | "deny" | "unsupported" | null = null;
  let approvalBusy = false;

  let quarantined = false;
  let quarantineBusy = false;
  let bannerMessage: string | null = null;

  async function refreshHistory() {
    if (!sessionId) return;
    historyItems = await api.getTransactionHistory(sessionId, 0);
  }

  async function refreshStorage() {
    if (!sessionId) return;
    try {
      storageStatus = await api.getStorageStatus(sessionId);
    } catch {
    }
  }

  async function handleSubmit(event: CustomEvent<string>) {
    if (!sessionId) return;
    const line = event.detail;
    bannerMessage = null;
    try {
      await api.submitCommand(sessionId, line);
    } catch (e) {
      terminalRef.writeSystemLine(String(e), "38;5;174");
      if (String(e).includes("quarantined")) {
        quarantined = true;
      }
    }
  }

  async function handleInterrupt() {
    if (!sessionId) return;
    await api.interruptCommand(sessionId).catch(() => {});
  }

  async function handleTransactionEvent(evt: import("./lib/types").TransactionEvent) {
    if (evt.session_id !== sessionId) return;
    if (evt.stage === "RECEIVED") {
      activeTransactionId = evt.transaction_id;
      activeTransactionEvents = [];
      viewingHistorical = false;
      panelDetail = null;
      panelKind = null;
      currentCategory = null;
      currentRisk = null;
    }
    if (evt.transaction_id !== activeTransactionId) return;
    activeTransactionEvents = [...activeTransactionEvents, evt];
    currentCategory = evt.category ?? currentCategory;
    currentRisk = evt.policy_risk_level ?? currentRisk;

    if (evt.stage === "WAITING_FOR_APPROVAL" && evt.status === "started") {
      panelDetail = await api.getTransactionDetail(evt.transaction_id);
      panelKind = "approval";
      terminalRef.writeSystemLine(
        "awaiting approval — see the panel on the right.",
        "38;5;173",
      );
      return;
    }

    if (TERMINAL_STAGES.includes(evt.stage) && evt.status !== "started") {
      const detail = await api.getTransactionDetail(evt.transaction_id);
      if (evt.stage === "DENIED") {
        panelDetail = detail;
        panelKind = "deny";
      } else if (evt.stage === "FAILED" && detail.support_tier === "unsupported") {
        panelDetail = detail;
        panelKind = "unsupported";
      } else {
        panelDetail = null;
        panelKind = null;
      }
      if (evt.stage === "ROLLBACK_FAILED") {
        quarantined = true;
        bannerMessage =
          "Rollback failed. This session is quarantined — recover it below before submitting more commands.";
      }
      await refreshHistory();
      await refreshStorage();
    }
  }

  function handleOutput(evt: import("./lib/types").TerminalOutputEvent) {
    if (evt.session_id !== sessionId) return;
    terminalRef.writeOutput(evt.stdout, evt.stderr);
  }

  async function handleApprove() {
    if (!activeTransactionId) return;
    approvalBusy = true;
    try {
      await api.approveTransaction(activeTransactionId);
      panelDetail = null;
      panelKind = null;
    } catch (e) {
      terminalRef.writeSystemLine(String(e), "38;5;174");
    } finally {
      approvalBusy = false;
    }
  }

  async function handleReject() {
    if (!activeTransactionId) return;
    approvalBusy = true;
    try {
      await api.rejectTransaction(activeTransactionId);
      panelDetail = null;
      panelKind = null;
      terminalRef.writeSystemLine("rejected — no changes were made.", "38;5;173");
      await refreshHistory();
    } catch (e) {
      terminalRef.writeSystemLine(String(e), "38;5;174");
    } finally {
      approvalBusy = false;
    }
  }

  async function handleHistorySelect(event: CustomEvent<string>) {
    const detail = await api.getTransactionDetail(event.detail);
    viewingHistorical = true;
    if (detail.final_state === "DENIED") {
      panelDetail = detail;
      panelKind = "deny";
    } else if (detail.final_state === "FAILED" && detail.support_tier === "unsupported") {
      panelDetail = detail;
      panelKind = "unsupported";
    } else {
      panelDetail = detail;
      panelKind = null;
    }
  }

  let undoBusy = false;

  async function handleUndo() {
    if (!sessionId) return;
    undoBusy = true;
    try {
      const outcome = await api.undoLastTransaction(sessionId);
      if (outcome.ok) {
        terminalRef.writeSystemLine(
          `restored to checkpoint ${outcome.restored_checkpoint_id ?? "(base)"}.`,
          "38;5;173",
        );
        await refreshHistory();
        await refreshStorage();
      } else {
        terminalRef.writeSystemLine(
          `nothing to undo: ${outcome.reason ?? "no recoverable checkpoint"}.`,
          "38;5;173",
        );
      }
    } catch (e) {
      terminalRef.writeSystemLine(String(e), "38;5;174");
    } finally {
      undoBusy = false;
    }
  }

  async function recoverQuarantine(resetToBase: boolean) {
    if (!sessionId) return;
    quarantineBusy = true;
    try {
      const outcome = resetToBase
        ? await api.quarantineRecoveryResetToBase(sessionId)
        : await api.quarantineRecoveryRestoreToNewest(sessionId);
      if (outcome.ok) {
        quarantined = false;
        bannerMessage = null;
        await refreshStorage();
      } else {
        bannerMessage = `Recovery attempt did not succeed: ${outcome.reason ?? "unknown reason"}`;
      }
    } finally {
      quarantineBusy = false;
    }
  }

  onMount(() => {
    let unlistenTx: (() => void) | undefined;
    let unlistenOutput: (() => void) | undefined;

    (async () => {
      sessionId = await api.createSession();
      const sessions: SessionRow[] = await api.listSessions();
      simulationBackend = sessions.find((s) => s.id === sessionId)?.simulation_backend ?? null;
      capabilityReport = await api.getCapabilityReport();
      await refreshHistory();
      await refreshStorage();

      unlistenTx = await onTransactionEvent(handleTransactionEvent);
      unlistenOutput = await onTerminalOutput(handleOutput);
    })();

    return () => {
      unlistenTx?.();
      unlistenOutput?.();
    };
  });
</script>

<div class="app">
  <TopBar {sessionId} {simulationBackend} {capabilityReport} {storageStatus} />

  {#if quarantined}
    <div class="quarantine-banner">
      <span>{bannerMessage ?? "This session is quarantined following a rollback failure."}</span>
      <div class="actions">
        <button disabled={quarantineBusy} on:click={() => recoverQuarantine(false)}>
          Restore to newest checkpoint
        </button>
        <button disabled={quarantineBusy} on:click={() => recoverQuarantine(true)}>
          Reset to base
        </button>
      </div>
    </div>
  {/if}

  <div class="main">
    <div class="terminal-pane">
      <Terminal bind:this={terminalRef} on:submit={handleSubmit} on:interrupt={handleInterrupt} />
    </div>

    <div class="side-pane">
      <section class="stage-block">
        <div class="stage-block-header">
          <h3>Pipeline{viewingHistorical ? " · history" : ""}</h3>
          {#if displayedEvents.length}
            <div class="badges">
              <Badge label={categoryLabel(displayedCategory)} tone={categoryTone(displayedCategory)} />
              {#if !viewingHistorical}
                <Badge label={riskLabel(currentRisk)} tone={riskTone(currentRisk)} />
              {/if}
            </div>
          {/if}
        </div>
        {#if displayedEvents.length}
          <PipelineFlow events={displayedEvents} />
        {:else}
          <p class="muted">Idle — submit a command in the terminal.</p>
        {/if}
      </section>

      {#if panelKind === "approval" && panelDetail}
        <ApprovalPanel detail={panelDetail} busy={approvalBusy} on:approve={handleApprove} on:reject={handleReject} />
      {:else if panelKind === "deny" && panelDetail}
        <DenyPanel detail={panelDetail} />
      {:else if panelKind === "unsupported" && panelDetail}
        <UnsupportedNotice detail={panelDetail} />
      {/if}
    </div>
  </div>

  <History items={historyItems} {undoBusy} on:select={handleHistorySelect} on:undo={handleUndo} />
</div>

<style>
  :global(html) {
    --bg: #0a0a0b;
    --bg-hover: #17171a;
    --bg-inset: #131315;

    --border-hair: rgba(255, 255, 255, 0.07);
    --border-hair-strong: rgba(255, 255, 255, 0.11);

    --text: #e7e5e1;
    --text-secondary: #9a9894;
    --text-tertiary: #6b6966;

    --accent: #d99a6c;
    --accent-strong: #e8ac7e;
    --accent-soft: rgba(217, 154, 108, 0.14);
    --accent-soft-strong: rgba(217, 154, 108, 0.24);
    --accent-ink: #201409;

    --danger: #c9847a;
    --danger-soft: rgba(201, 132, 122, 0.14);

    --safe: #8caf90;
    --safe-soft: rgba(140, 175, 144, 0.13);

    --neutral: #8f8d89;
    --neutral-soft: rgba(143, 141, 137, 0.11);

    --ai: #a794c7;
    --ai-soft: rgba(167, 148, 199, 0.12);

    --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif;
  }

  :global(html, body) {
    margin: 0;
    height: 100%;
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
  }
  :global(#app) {
    height: 100%;
  }
  :global(code, pre) {
    font-family: var(--mono);
  }

  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .quarantine-banner {
    background: var(--danger-soft);
    color: var(--danger);
    padding: 0.55rem 1.25rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 0.82rem;
    gap: 1rem;
  }
  .quarantine-banner .actions {
    display: flex;
    gap: 0.5rem;
    flex-shrink: 0;
  }
  .quarantine-banner button {
    background: transparent;
    color: var(--text);
    border: none;
    border-radius: 5px;
    padding: 0.3rem 0.7rem;
    font-size: 0.76rem;
    cursor: pointer;
    transition: background-color 0.12s ease;
  }
  .quarantine-banner button:hover {
    background: rgba(255, 255, 255, 0.06);
  }

  .main {
    flex: 1;
    display: grid;
    grid-template-columns: 66% 34%;
    min-height: 0;
  }

  .terminal-pane {
    min-width: 0;
    border-right: 1px solid var(--border-hair);
  }

  .side-pane {
    min-width: 0;
    overflow-y: auto;
    overflow-x: hidden;
    padding: 1.5rem 1.5rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 1.75rem;
  }

  .stage-block {
    min-width: 0;
  }
  .stage-block-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin-bottom: 0.85rem;
  }
  .stage-block h3 {
    margin: 0;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text);
  }
  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }
  .muted {
    color: var(--text-tertiary);
    margin: 0;
    font-size: 0.82rem;
  }
</style>

<script lang="ts">
  // §31.2's layout: top bar, dominant terminal + right column (pipeline
  // flow / approval panel), collapsible history strip. This component is
  // the one place that subscribes to `transaction://event`/
  // `terminal://output` and calls `api.*` — every child below only
  // renders props and dispatches user-intent events (`submit`, `approve`,
  // `reject`, …) back up here, matching docs/CLAUDE.md's "frontend is a
  // pure renderer of the event stream" rule. `activeTransactionEvents`
  // simply accumulates the raw event list for whichever transaction is
  // "current" — `PipelineFlow` (§32) derives every node's state from
  // that list on each recompute; this component does no stage-tracking
  // of its own beyond collecting the events themselves.
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
      // No checkpoints/session state yet — not an error worth surfacing.
    }
  }

  async function handleSubmit(event: CustomEvent<string>) {
    if (!sessionId) return;
    const line = event.detail;
    bannerMessage = null;
    try {
      await api.submitCommand(sessionId, line);
      // Deliberately not setting `activeTransactionId` from this
      // response: the Rust side emits every pipeline-stage event
      // synchronously *inside* `submit_command`, all before it returns
      // this ack, so by the time this `await` resolves every event for
      // a fast (non-approval-gated) command has already arrived and
      // would've been dropped waiting on this assignment. See
      // `handleTransactionEvent`'s `RECEIVED`-stage branch below, which
      // picks up the new transaction id the moment its first real event
      // arrives instead.
    } catch (e) {
      terminalRef.writeSystemLine(String(e), "31");
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
      // The first event of every transaction, always — start tracking
      // it here rather than from `submit_command`'s own resolved
      // promise (see `handleSubmit`'s comment for why that's too late).
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
      terminalRef.writeSystemLine(String(e), "31");
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
      terminalRef.writeSystemLine("rejected — no changes were made.", "33");
      await refreshHistory();
    } catch (e) {
      terminalRef.writeSystemLine(String(e), "31");
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
          "33",
        );
        await refreshHistory();
        await refreshStorage();
      } else {
        terminalRef.writeSystemLine(
          `nothing to undo: ${outcome.reason ?? "no recoverable checkpoint"}.`,
          "33",
        );
      }
    } catch (e) {
      terminalRef.writeSystemLine(String(e), "31");
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
      <section class="stage-card">
        <div class="stage-card-header">
          <h3>Pipeline{viewingHistorical ? " (history)" : ""}</h3>
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
          <PipelineFlow events={displayedEvents} category={displayedCategory} />
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
  :global(html, body) {
    margin: 0;
    height: 100%;
    background: #0d1117;
    color: #c9d1d9;
    font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  }
  :global(#app) {
    height: 100%;
  }

  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .quarantine-banner {
    background: #3d1a1a;
    border-bottom: 1px solid #f85149;
    color: #ffb3ac;
    padding: 0.5rem 1rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 0.85rem;
    gap: 1rem;
  }
  .quarantine-banner .actions {
    display: flex;
    gap: 0.5rem;
    flex-shrink: 0;
  }
  .quarantine-banner button {
    background: #21262d;
    color: #c9d1d9;
    border: 1px solid #f85149;
    border-radius: 6px;
    padding: 0.3rem 0.7rem;
    font-size: 0.78rem;
    cursor: pointer;
  }

  .main {
    flex: 1;
    display: grid;
    grid-template-columns: 68% 32%;
    min-height: 0;
  }

  .terminal-pane {
    min-width: 0;
    border-right: 1px solid #30363d;
  }

  .side-pane {
    min-width: 0;
    overflow-y: auto;
    padding: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .stage-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.75rem 1rem;
  }
  .stage-card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.4rem;
  }
  .stage-card h3 {
    margin: 0;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #8b949e;
  }
  .badges {
    display: flex;
    gap: 0.4rem;
  }
  .muted {
    color: #8b949e;
    margin: 0;
    font-size: 0.85rem;
  }
</style>

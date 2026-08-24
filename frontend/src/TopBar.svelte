<script lang="ts">
  // §31.2's top bar: "environment indicator | session id | sandbox
  // backend | capability status | storage: 412 MB / 1 GB, 7/10
  // checkpoints."
  import type { CapabilityReport, StorageStatus } from "./lib/types";
  import { formatBytes } from "./lib/format";

  export let sessionId: string | null;
  export let simulationBackend: string | null;
  export let capabilityReport: CapabilityReport | null;
  export let storageStatus: StorageStatus | null;

  $: degraded = capabilityReport ? capabilityReport.degradations.length > 0 : false;
  $: executionAvailable = capabilityReport?.execution_available ?? null;
</script>

<div class="topbar">
  <div class="item brand">
    <span class="dot" class:ok={executionAvailable === true} class:bad={executionAvailable === false}></span>
    Aegis
  </div>
  <div class="item">session <code>{sessionId ?? "…"}</code></div>
  <div class="item">backend <code>{simulationBackend ?? "…"}</code></div>
  {#if capabilityReport}
    <div class="item" class:warn={degraded}>
      capabilities {executionAvailable ? "available" : "unavailable"}
      {#if degraded}
        <span class="degradations" title={capabilityReport.degradations.join(", ")}>
          ({capabilityReport.degradations.length} degraded)
        </span>
      {/if}
    </div>
  {/if}
  {#if storageStatus}
    <div class="item">
      storage {formatBytes(storageStatus.bytes_used)} / {formatBytes(storageStatus.ceiling_bytes)}
      <span class="dim">·</span>
      {storageStatus.checkpoints_retained}/{storageStatus.max_checkpoints} checkpoints
    </div>
  {/if}
</div>

<style>
  .topbar {
    display: flex;
    align-items: center;
    gap: 1.75rem;
    padding: 0.6rem 1.25rem;
    background: var(--bg);
    border-bottom: 1px solid var(--border-hair);
    font-size: 0.76rem;
    color: var(--text-secondary);
    flex-wrap: wrap;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    white-space: nowrap;
  }
  .item.brand {
    color: var(--text);
    font-weight: 500;
    letter-spacing: 0.01em;
    margin-right: 0.25rem;
  }
  .item code {
    color: var(--text);
    font-size: 0.76rem;
  }
  .item.warn {
    color: var(--accent);
  }
  .dim {
    color: var(--text-tertiary);
  }
  .dot {
    width: 0.4rem;
    height: 0.4rem;
    border-radius: 999px;
    background: var(--text-tertiary);
    display: inline-block;
  }
  .dot.ok {
    background: var(--safe);
  }
  .dot.bad {
    background: var(--danger);
  }
  .degradations {
    color: var(--accent);
  }
</style>

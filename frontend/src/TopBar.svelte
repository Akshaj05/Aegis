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
  <div class="item">
    <span class="dot" class:ok={executionAvailable === true} class:bad={executionAvailable === false}></span>
    SafeShell
  </div>
  <div class="item">session: <code>{sessionId ?? "…"}</code></div>
  <div class="item">backend: <code>{simulationBackend ?? "…"}</code></div>
  {#if capabilityReport}
    <div class="item" class:warn={degraded}>
      capabilities: {executionAvailable ? "available" : "unavailable"}
      {#if degraded}
        <span class="degradations" title={capabilityReport.degradations.join(", ")}>
          ({capabilityReport.degradations.length} degraded)
        </span>
      {/if}
    </div>
  {/if}
  {#if storageStatus}
    <div class="item">
      storage: {formatBytes(storageStatus.bytes_used)} / {formatBytes(storageStatus.ceiling_bytes)},
      {storageStatus.checkpoints_retained}/{storageStatus.max_checkpoints} checkpoints
    </div>
  {/if}
</div>

<style>
  .topbar {
    display: flex;
    align-items: center;
    gap: 1.5rem;
    padding: 0.5rem 1rem;
    background: #010409;
    border-bottom: 1px solid #30363d;
    font-size: 0.78rem;
    color: #8b949e;
    flex-wrap: wrap;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    white-space: nowrap;
  }
  .item code {
    color: #c9d1d9;
    font-size: 0.78rem;
  }
  .item.warn {
    color: #d29922;
  }
  .dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 999px;
    background: #8b949e;
    display: inline-block;
  }
  .dot.ok {
    background: #3fb950;
  }
  .dot.bad {
    background: #f85149;
  }
  .degradations {
    color: #d29922;
  }
</style>

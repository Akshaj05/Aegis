<script lang="ts">
  // §31.2's bottom strip: "transaction history + recoverability."
  import { createEventDispatcher } from "svelte";
  import type { TransactionSummaryRow } from "../lib/types";
  import { categoryTone, formatTimestamp } from "../lib/format";
  import Badge from "./Badge.svelte";

  export let items: TransactionSummaryRow[] = [];
  export let collapsed = false;
  export let undoBusy = false;

  const dispatch = createEventDispatcher<{ select: string; undo: void }>();

  function toneFor(state: string | null): "safe" | "warn" | "danger" | "neutral" {
    switch (state) {
      case "COMMITTED":
      case "RESTORED":
        return "safe";
      case "DENIED":
      case "ROLLBACK_FAILED":
        return "danger";
      case "REJECTED":
      case "FAILED":
        return "warn";
      default:
        return "neutral";
    }
  }
</script>

<section class="history" class:collapsed>
  <div class="header-row">
    <button class="toggle-header" on:click={() => (collapsed = !collapsed)}>
      <h3>History ({items.length})</h3>
      <span class="toggle">{collapsed ? "▸" : "▾"}</span>
    </button>
    <!-- §44 step 4: "Undo Last Transaction." §23.5 is strictly LIFO — there
         is exactly one valid target, computed by the core, which is why
         this control needs no argument beyond the session id. -->
    <button
      class="undo"
      disabled={undoBusy}
      on:click={() => dispatch("undo")}
      title="Restore the environment to the state before the most recent committed transaction"
    >
      Undo Last Transaction
    </button>
  </div>
  {#if !collapsed}
    <div class="rows">
      {#each items as item (item.id)}
        <button class="row" on:click={() => dispatch("select", item.id)}>
          <code class="cmd">{item.raw_command}</code>
          <span class="meta">
            {#if item.final_state}
              <Badge label={item.final_state} tone={toneFor(item.final_state)} />
            {:else}
              <Badge label="in progress" tone="neutral" />
            {/if}
            <span class="time">{formatTimestamp(item.created_at)}</span>
          </span>
        </button>
      {:else}
        <p class="empty">No commands yet this session.</p>
      {/each}
    </div>
  {/if}
</section>

<style>
  .history {
    border-top: 1px solid #30363d;
    background: #0d1117;
  }
  .header-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.25rem 1rem;
  }
  .toggle-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.15rem 0;
    cursor: pointer;
    user-select: none;
    background: transparent;
    border: none;
    color: inherit;
    font: inherit;
  }
  .undo {
    background: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 0.25rem 0.6rem;
    font-size: 0.72rem;
    cursor: pointer;
  }
  .undo:hover:not(:disabled) {
    border-color: #58a6ff;
  }
  .undo:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  h3 {
    margin: 0;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #8b949e;
  }
  .toggle {
    color: #8b949e;
  }
  .rows {
    max-height: 9rem;
    overflow-y: auto;
    padding: 0 0.5rem 0.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: transparent;
    border: none;
    color: inherit;
    text-align: left;
    padding: 0.3rem 0.5rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.8rem;
  }
  .row:hover {
    background: #161b22;
  }
  .cmd {
    font-family: ui-monospace, monospace;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 24rem;
  }
  .meta {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-shrink: 0;
  }
  .time {
    color: #8b949e;
    font-size: 0.72rem;
  }
  .empty {
    color: #8b949e;
    font-size: 0.8rem;
    padding: 0.25rem 0.5rem;
  }
</style>

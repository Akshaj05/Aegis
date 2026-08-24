<script lang="ts">
  // History strip: lists past transactions and exposes undo-last-transaction.
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
      <span class="chevron" class:collapsed>▾</span>
      <h3>History <span class="count">{items.length}</span></h3>
    </button>
    <button
      class="undo"
      disabled={undoBusy}
      on:click={() => dispatch("undo")}
      title="Restore the environment to the state before the most recent committed transaction"
    >
      Undo last transaction
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
    background: var(--bg-inset);
  }
  .header-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.35rem 1.25rem;
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
    background: transparent;
    color: var(--danger);
    border: none;
    border-radius: 5px;
    padding: 0.3rem 0.6rem;
    font-size: 0.72rem;
    cursor: pointer;
    transition: background-color 0.12s ease, color 0.12s ease;
  }
  .undo:hover:not(:disabled) {
    background: var(--danger-soft);
    color: var(--danger);
  }
  .undo:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  h3 {
    margin: 0;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    color: var(--text);
  }
  .count {
    color: var(--text-tertiary);
    font-weight: 400;
  }
  .chevron {
    color: var(--text-tertiary);
    font-size: 0.65rem;
    transition: transform 0.15s ease;
  }
  .chevron.collapsed {
    transform: rotate(-90deg);
  }
  .rows {
    max-height: 9rem;
    overflow-y: auto;
    padding: 0 0.75rem 0.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: transparent;
    border: none;
    color: inherit;
    text-align: left;
    padding: 0.35rem 0.5rem;
    border-radius: 5px;
    cursor: pointer;
    font-size: 0.8rem;
  }
  .row:hover {
    background: var(--bg-hover);
  }
  .cmd {
    color: var(--text-secondary);
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
    color: var(--text-tertiary);
    font-size: 0.7rem;
  }
  .empty {
    color: var(--text-tertiary);
    font-size: 0.8rem;
    padding: 0.3rem 0.5rem;
  }
</style>

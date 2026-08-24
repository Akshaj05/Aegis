<script lang="ts">
  // Unsupported-command notice: informs the user a recognized command
  // isn't implemented yet.
  import type { TransactionDetail } from "../lib/types";

  export let detail: TransactionDetail;
</script>

<section class="panel">
  <header>
    <span class="eyebrow">Not yet supported</span>
  </header>
  <p class="command"><code>{detail.command}</code></p>
  <p class="lead">
    This command is recognized but not implemented yet in Aegis
    {#if detail.support_tier}(tier: {detail.support_tier}){/if}. This is not a security
    decision — nothing about this command was found to be unsafe.
  </p>
</section>

<style>
  .panel {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .eyebrow {
    font-size: 0.7rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-tertiary);
  }
  .command {
    margin: 0;
  }
  .command code {
    font-size: 0.9rem;
    color: var(--text);
  }
  .lead {
    margin: 0;
    font-size: 0.83rem;
    line-height: 1.5;
    color: var(--text-secondary);
  }
</style>

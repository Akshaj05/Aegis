<script lang="ts">
  // Deny panel: displays a denied transaction's policy reason codes.
  import type { TransactionDetail } from "../lib/types";

  export let detail: TransactionDetail;
</script>

<section class="panel">
  <header>
    <span class="eyebrow">Denied · containment boundary</span>
  </header>

  <p class="command"><code>{detail.command}</code></p>

  <p class="lead">
    This is a containment-boundary matter, not a risk judgment. Aegis does not run this
    operation in any form — not simulated, not approval-gated, not with a force flag.
  </p>

  {#if detail.policy_reason_codes.length}
    <div class="reasons">
      {#each detail.policy_reason_codes as reason}
        <div class="reason">
          <code class="code">{reason.code}</code>
          <p>{reason.canonical_text}</p>
        </div>
      {/each}
    </div>
  {/if}

  <p class="footnote">
    If this targets a host resource, the Aegis-managed equivalent (if any exists) is under
    the simulated environment's own root, not the host path referenced above.
  </p>
</section>

<style>
  .panel {
    border-left: 2px solid var(--danger);
    padding-left: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .eyebrow {
    font-size: 0.7rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--danger);
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
    font-size: 0.85rem;
    line-height: 1.5;
    color: var(--text-secondary);
  }
  .reasons {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .reason {
    padding: 0.1rem 0;
  }
  .code {
    font-size: 0.68rem;
    color: var(--danger);
  }
  .reason p {
    margin: 0.2rem 0 0;
    font-size: 0.83rem;
    color: var(--text-secondary);
  }
  .footnote {
    margin: 0;
    font-size: 0.76rem;
    color: var(--text-tertiary);
  }
</style>

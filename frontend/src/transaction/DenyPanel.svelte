<script lang="ts">
  // §31.4: "A DENY renders differently from an approval prompt, because
  // it is a different kind of thing." No approve control anywhere in
  // this component, and no styling shared with `ApprovalPanel` — it must
  // never be mistaken for a risk judgment the user could override.
  import type { TransactionDetail } from "../lib/types";

  export let detail: TransactionDetail;
</script>

<section class="panel">
  <header>
    <span class="stop">⛔</span>
    <h2>Denied — containment boundary</h2>
  </header>

  <p class="command"><code>{detail.command}</code></p>

  <p class="lead">
    This is a containment-boundary matter, not a risk judgment. SafeShell does not run this
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
    If this targets a host resource, the SafeShell-managed equivalent (if any exists) is under
    the simulated environment's own root, not the host path referenced above.
  </p>
</section>

<style>
  .panel {
    background: #2d1214;
    border: 1px solid #f85149;
    border-radius: 8px;
    padding: 1rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .stop {
    font-size: 1.1rem;
  }
  h2 {
    margin: 0;
    font-size: 1rem;
    color: #ffb3ac;
  }
  .command code {
    background: #0d1117;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-size: 0.85rem;
  }
  .lead {
    margin: 0;
    font-size: 0.88rem;
  }
  .reasons {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .reason {
    background: rgba(0, 0, 0, 0.2);
    border-radius: 6px;
    padding: 0.5rem 0.65rem;
  }
  .code {
    font-size: 0.7rem;
    color: #f85149;
  }
  .reason p {
    margin: 0.25rem 0 0;
    font-size: 0.85rem;
  }
  .footnote {
    margin: 0;
    font-size: 0.78rem;
    color: #d4a5a1;
  }
</style>

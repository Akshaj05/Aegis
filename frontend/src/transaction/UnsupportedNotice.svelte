<script lang="ts">
  // §31.5: "Plain, non-alarming: the command is recognized but not
  // implemented, with its tier named. No security framing, because it is
  // not a security matter." Deliberately styled neutral, not red/amber —
  // sharing color language with `DenyPanel` here would misrepresent this
  // as a security outcome.
  import type { TransactionDetail } from "../lib/types";

  export let detail: TransactionDetail;
</script>

<section class="panel">
  <header>
    <span class="icon">ℹ️</span>
    <h2>Not yet supported</h2>
  </header>
  <p class="command"><code>{detail.command}</code></p>
  <p class="lead">
    This command is recognized but not implemented yet in SafeShell
    {#if detail.support_tier}(tier: {detail.support_tier}){/if}. This is not a security
    decision — nothing about this command was found to be unsafe.
  </p>
</section>

<style>
  .panel {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  h2 {
    margin: 0;
    font-size: 1rem;
    color: #c9d1d9;
  }
  .command code {
    background: #0d1117;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-size: 0.85rem;
  }
  .lead {
    margin: 0;
    font-size: 0.85rem;
    color: #8b949e;
  }
</style>

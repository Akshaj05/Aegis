<script lang="ts">
  // §31.3: "the product's most important screen... presents facts, not
  // discouragement." Approve/Reject are rendered as equals — see the
  // stylesheet below: identical size and prominence for both actions,
  // deliberately (a filled/ghost pairing reads as "primary vs.
  // secondary" by convention, but neither is harder to reach or slower
  // to click — that's the equality that matters here, not identical
  // paint).
  import { createEventDispatcher } from "svelte";
  import type { TransactionDetail } from "../lib/types";
  import { extractPredictedDiffFromDetail } from "../lib/types";
  import { categoryLabel, categoryTone, riskLabel, riskTone } from "../lib/format";
  import Badge from "./Badge.svelte";

  export let detail: TransactionDetail;
  export let busy = false;

  const dispatch = createEventDispatcher<{ approve: void; reject: void }>();

  $: predictedDiff = extractPredictedDiffFromDetail(detail);
  $: filesTouched = predictedDiff
    ? predictedDiff.files_created.length + predictedDiff.files_modified.length
    : 0;
  $: dirsTouched = predictedDiff ? predictedDiff.directories_created.length : 0;
  $: filesDeleted = predictedDiff ? predictedDiff.files_deleted.length : 0;
  $: dirsDeleted = predictedDiff ? predictedDiff.directories_deleted.length : 0;
</script>

<section class="panel">
  <header>
    <span class="eyebrow">Approval required</span>
    <div class="badges">
      <Badge label={categoryLabel(detail.category)} tone={categoryTone(detail.category)} />
      <Badge label={riskLabel(detail.policy_risk_level)} tone={riskTone(detail.policy_risk_level)} />
    </div>
  </header>

  <p class="command"><code>{detail.command}</code></p>

  <div class="section">
    <h3>What will change</h3>
    {#if predictedDiff}
      <dl class="stats">
        <div class="stat"><dt>{filesTouched}</dt><dd>file{filesTouched === 1 ? "" : "s"} created or modified</dd></div>
        <div class="stat"><dt>{dirsTouched}</dt><dd>director{dirsTouched === 1 ? "y" : "ies"} created</dd></div>
        <div class="stat"><dt>{filesDeleted}</dt><dd>file{filesDeleted === 1 ? "" : "s"} deleted</dd></div>
        <div class="stat"><dt>{dirsDeleted}</dt><dd>director{dirsDeleted === 1 ? "y" : "ies"} deleted</dd></div>
        <div class="stat"><dt>{predictedDiff.bytes_affected}</dt><dd>bytes affected</dd></div>
        {#if predictedDiff.bytes_deleted}
          <div class="stat"><dt>{predictedDiff.bytes_deleted}</dt><dd>bytes deleted</dd></div>
        {/if}
      </dl>
      {#if predictedDiff.files_created.length || predictedDiff.directories_created.length || predictedDiff.files_modified.length || predictedDiff.files_deleted.length || predictedDiff.directories_deleted.length}
        <details open={filesDeleted > 0 || dirsDeleted > 0}>
          <summary>File-level detail</summary>
          <ul class="paths">
            {#each predictedDiff.directories_created as p}
              <li class="add">+&nbsp;&nbsp;dir&nbsp;&nbsp;{p}/</li>
            {/each}
            {#each predictedDiff.files_created as p}
              <li class="add">+&nbsp;&nbsp;file&nbsp;{p}</li>
            {/each}
            {#each predictedDiff.files_modified as p}
              <li class="mod">~&nbsp;&nbsp;file&nbsp;{p}</li>
            {/each}
            {#each predictedDiff.directories_deleted as p}
              <li class="del">-&nbsp;&nbsp;dir&nbsp;&nbsp;{p}/</li>
            {/each}
            {#each predictedDiff.files_deleted as p}
              <li class="del">-&nbsp;&nbsp;file&nbsp;{p}</li>
            {/each}
          </ul>
        </details>
      {:else}
        <p class="muted">No filesystem changes predicted.</p>
      {/if}
    {:else}
      <p class="muted">Predicted diff not yet available.</p>
    {/if}
  </div>

  {#if detail.support_tier}
    <div class="section">
      <h3>Why it is classified as it is</h3>
      <p class="muted">Support tier: {detail.support_tier}</p>
      {#if detail.policy_reason_codes.length}
        <ul class="reasons">
          {#each detail.policy_reason_codes as reason}
            <li>{reason.canonical_text}</li>
          {/each}
        </ul>
      {/if}
    </div>
  {/if}

  {#if detail.ai_plan}
    <div class="section ai">
      <h3>AI advisory <span class="ai-tag">advisory only</span></h3>
      <p>{detail.ai_plan.explanation}</p>
      {#if detail.ai_plan.recovery_recommendation?.description}
        <p class="muted">{detail.ai_plan.recovery_recommendation.description}</p>
      {/if}
    </div>
  {:else if detail.ai_skipped}
    <div class="section ai">
      <h3>AI advisory</h3>
      <p class="muted">AI analysis unavailable ({detail.ai_skipped_reason ?? "skipped"}) — routing is governed entirely by deterministic policy above.</p>
    </div>
  {/if}

  <div class="section">
    <h3>Reversibility</h3>
    <p class="muted">Fully reversible: a checkpoint is taken immediately before execution. <span class="text">Undo Last Transaction</span> will restore this exact state.</p>
  </div>

  <div class="actions">
    <button class="approve" disabled={busy} on:click={() => dispatch("approve")}>Approve</button>
    <button class="reject" disabled={busy} on:click={() => dispatch("reject")}>Reject</button>
  </div>
</section>

<style>
  /* Deliberately no outer card: no background, no border, no radius —
     the panel breathes against the app background, and structure comes
     entirely from spacing + the eyebrow/heading typographic hierarchy. */
  .panel {
    display: flex;
    flex-direction: column;
    gap: 1.1rem;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
  .eyebrow {
    font-size: 0.7rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-tertiary);
  }
  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }
  .command {
    margin: -0.4rem 0 0;
  }
  .command code {
    font-size: 0.92rem;
    color: var(--text);
  }
  .section h3 {
    margin: 0 0 0.5rem;
    font-size: 0.68rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    color: var(--text-tertiary);
  }
  .section.ai {
    border-left: 2px solid var(--ai);
    padding-left: 0.7rem;
  }
  .ai-tag {
    margin-left: 0.5rem;
    font-size: 0.62rem;
    text-transform: none;
    letter-spacing: 0;
    color: var(--ai);
    font-weight: 400;
  }
  .section p {
    margin: 0;
    font-size: 0.85rem;
    line-height: 1.5;
  }

  /* "What will change" — read like a structured log, not a form widget:
     a fixed, right-aligned numeric column feeding into a muted label,
     no bullets, no card background. */
  .stats {
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.83rem;
  }
  .stat {
    display: flex;
    gap: 0.6rem;
  }
  .stat dt {
    min-width: 1.6rem;
    text-align: right;
    color: var(--text);
    font-family: var(--mono);
    font-variant-numeric: tabular-nums;
  }
  .stat dd {
    margin: 0;
    color: var(--text-secondary);
  }

  details {
    margin-top: 0.6rem;
  }
  summary {
    cursor: pointer;
    font-size: 0.76rem;
    color: var(--text-secondary);
    user-select: none;
  }
  summary::marker {
    color: var(--text-tertiary);
  }
  .paths {
    list-style: none;
    max-height: 10rem;
    overflow-y: auto;
    font-family: var(--mono);
    font-size: 0.78rem;
    margin: 0.5rem 0 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
  .paths li {
    white-space: pre;
  }
  .paths .add {
    color: var(--safe);
  }
  .paths .del {
    color: var(--danger);
  }
  .paths .mod {
    color: var(--text-secondary);
  }

  .reasons {
    list-style: none;
    margin: 0.4rem 0 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.83rem;
    color: var(--text-secondary);
  }
  .reasons li {
    padding-left: 0.9rem;
    position: relative;
  }
  .reasons li::before {
    content: "·";
    position: absolute;
    left: 0;
    color: var(--text-tertiary);
  }

  .muted {
    color: var(--text-secondary);
  }
  .muted .text {
    color: var(--text);
    font-weight: 500;
  }

  .actions {
    display: flex;
    gap: 0.6rem;
    margin-top: 0.3rem;
  }
  button {
    flex: 1;
    padding: 0.55rem 1rem;
    font-size: 0.84rem;
    font-weight: 500;
    border-radius: 6px;
    border: none;
    cursor: pointer;
    font-family: var(--sans);
    transition: opacity 0.12s ease, background-color 0.12s ease;
  }
  button.approve {
    background: var(--accent);
    color: var(--accent-ink);
  }
  button.approve:hover:not(:disabled) {
    background: var(--accent-strong);
  }
  button.reject {
    background: transparent;
    color: var(--text-secondary);
  }
  button.reject:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--text);
  }
  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>

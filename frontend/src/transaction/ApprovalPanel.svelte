<script lang="ts">
  // §31.3: "the product's most important screen... presents facts, not
  // discouragement." Approve/Reject are rendered as equals — see the
  // stylesheet below: identical size, weight, and visual prominence for
  // both buttons, deliberately.
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
    <h2>Approval required</h2>
    <div class="badges">
      <Badge label={categoryLabel(detail.category)} tone={categoryTone(detail.category)} />
      <Badge label={riskLabel(detail.policy_risk_level)} tone={riskTone(detail.policy_risk_level)} />
    </div>
  </header>

  <p class="command"><code>{detail.command}</code></p>

  <div class="section">
    <h3>What will change</h3>
    {#if predictedDiff}
      <ul class="stats">
        <li><strong>{filesTouched}</strong> file(s) created or modified</li>
        <li><strong>{dirsTouched}</strong> director{dirsTouched === 1 ? "y" : "ies"} created</li>
        <li><strong>{filesDeleted}</strong> file(s) deleted</li>
        <li><strong>{dirsDeleted}</strong> director{dirsDeleted === 1 ? "y" : "ies"} deleted</li>
        <li><strong>{predictedDiff.bytes_affected}</strong> bytes affected</li>
        {#if predictedDiff.bytes_deleted}
          <li><strong>{predictedDiff.bytes_deleted}</strong> bytes deleted</li>
        {/if}
      </ul>
      {#if predictedDiff.files_created.length || predictedDiff.directories_created.length || predictedDiff.files_modified.length || predictedDiff.files_deleted.length || predictedDiff.directories_deleted.length}
        <details open={filesDeleted > 0 || dirsDeleted > 0}>
          <summary>File-level detail</summary>
          <ul class="paths">
            {#each predictedDiff.directories_created as p}
              <li>+ dir&nbsp;&nbsp;{p}/</li>
            {/each}
            {#each predictedDiff.files_created as p}
              <li>+ file&nbsp;{p}</li>
            {/each}
            {#each predictedDiff.files_modified as p}
              <li>~ file&nbsp;{p}</li>
            {/each}
            {#each predictedDiff.directories_deleted as p}
              <li>- dir&nbsp;&nbsp;{p}/</li>
            {/each}
            {#each predictedDiff.files_deleted as p}
              <li>- file&nbsp;{p}</li>
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
        <ul>
          {#each detail.policy_reason_codes as reason}
            <li>{reason.canonical_text}</li>
          {/each}
        </ul>
      {/if}
    </div>
  {/if}

  {#if detail.ai_plan}
    <div class="section ai">
      <h3>AI advisory <span class="ai-tag">AI-generated, advisory only</span></h3>
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
    <p>Fully reversible: a checkpoint is taken immediately before execution. <strong>Undo Last Transaction</strong> will restore this exact state.</p>
  </div>

  <div class="actions">
    <button class="approve" disabled={busy} on:click={() => dispatch("approve")}>Approve</button>
    <button class="reject" disabled={busy} on:click={() => dispatch("reject")}>Reject</button>
  </div>
</section>

<style>
  .panel {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
  h2 {
    margin: 0;
    font-size: 1rem;
  }
  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }
  .command code {
    background: #0d1117;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-size: 0.85rem;
  }
  .section h3 {
    margin: 0 0 0.35rem;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #8b949e;
  }
  .section.ai {
    border-left: 3px solid #a371f7;
    padding-left: 0.6rem;
  }
  .ai-tag {
    margin-left: 0.5rem;
    font-size: 0.65rem;
    text-transform: none;
    color: #a371f7;
    font-weight: 600;
  }
  .stats {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.85rem;
  }
  .paths {
    max-height: 10rem;
    overflow-y: auto;
    font-family: ui-monospace, monospace;
    font-size: 0.8rem;
    margin: 0.4rem 0 0;
  }
  .muted {
    color: #8b949e;
    margin: 0;
    font-size: 0.85rem;
  }
  .actions {
    display: flex;
    gap: 0.75rem;
    margin-top: 0.25rem;
  }
  button {
    flex: 1;
    padding: 0.55rem 1rem;
    font-size: 0.9rem;
    font-weight: 600;
    border-radius: 6px;
    border: 1px solid #30363d;
    cursor: pointer;
  }
  button.approve {
    background: #238636;
    color: white;
    border-color: #2ea043;
  }
  button.reject {
    background: #21262d;
    color: #c9d1d9;
  }
  button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>

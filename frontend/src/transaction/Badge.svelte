<script lang="ts">
  // Small colored label/tag used to display category, risk, or status.
  export let label: string;
  export let tone: "safe" | "warn" | "danger" | "neutral" = "neutral";
</script>

<span class="badge {tone}">{label}</span>

<style>
  .badge {
    display: inline-block;
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 500;
    letter-spacing: 0.03em;
    text-transform: uppercase;
  }
  .safe {
    background: var(--safe-soft);
    color: var(--safe);
  }
  .warn {
    background: var(--accent-soft);
    color: var(--accent-strong);
  }
  .danger {
    background: var(--danger-soft);
    color: var(--danger);
  }
  .neutral {
    background: var(--neutral-soft);
    color: var(--neutral);
  }
</style>

<script lang="ts">
  export let label: string;
  export let tone: "safe" | "warn" | "danger" | "neutral" = "neutral";
</script>

<span class="badge {tone}">{label}</span>

<style>
  .badge {
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    border: 1px solid transparent;
  }
  .safe {
    background: rgba(46, 160, 67, 0.15);
    color: #3fb950;
    border-color: rgba(46, 160, 67, 0.4);
  }
  .warn {
    background: rgba(210, 153, 34, 0.15);
    color: #d29922;
    border-color: rgba(210, 153, 34, 0.4);
  }
  .danger {
    background: rgba(248, 81, 73, 0.15);
    color: #f85149;
    border-color: rgba(248, 81, 73, 0.4);
  }
  .neutral {
    background: rgba(139, 148, 158, 0.15);
    color: #8b949e;
    border-color: rgba(139, 148, 158, 0.4);
  }
</style>

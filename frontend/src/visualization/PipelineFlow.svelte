<script lang="ts">
  // §32: "A fixed SVG diagram of the pipeline stages... on each
  // `transaction://event`, the corresponding node updates: idle → active
  // → done or error, with a duration label once `duration_ms` is known...
  // state-driven, not scripted." This component takes the *full* ordered
  // event list for one transaction and derives every node's status from
  // it on each recompute — there is no internal timeline, no per-stage
  // special-cased animation sequence, and no distinction between "replay
  // a finished transaction's history" and "render one flashing through in
  // real time": both are just `computeFlowState(events)` over whatever
  // list was passed in. That's what makes the exact same component
  // correct for both `App.svelte`'s live event accumulation and
  // `TransactionDetail.events` read back after the fact (via
  // `detailEventsToFlowEvents`, `lib/types.ts`).
  import type { FlowEvent } from "../lib/types";

  export let events: FlowEvent[] = [];
  export let category: string | null = null;

  const LABELS = [
    "Parse",
    "Policy",
    "AI",
    "Simulation",
    "Diff",
    "Approval",
    "Snapshot",
    "Execute",
    "Verify",
    "Commit/Rollback",
  ];

  // §13.2's state machine mapped onto §32's ten fixed nodes. Stages not
  // in this table (DENIED, REJECTED, FAILED, ROLLING_BACK, RESTORED,
  // ROLLBACK_FAILED) have no node of their own — they're outcomes that
  // land *on* one of these ten, handled in `computeFlowState` below.
  const STAGE_NODE_INDEX: Record<string, number> = {
    PARSED: 0,
    POLICY_CHECK: 1,
    AI_ANALYSIS: 2,
    SIMULATING: 3,
    DIFF_READY: 4,
    WAITING_FOR_APPROVAL: 5,
    SNAPSHOTTING: 6,
    EXECUTING: 7,
    VERIFYING: 8,
    COMMITTED: 9,
  };

  type NodeStatus = "idle" | "active" | "done" | "error" | "stopped";

  interface NodeState {
    label: string;
    status: NodeStatus;
    durationMs: number | null;
  }

  interface ReverseState {
    from: number;
    to: number;
    tone: "active" | "done" | "error";
  }

  interface FlowState {
    nodes: NodeState[];
    reverse: ReverseState | null;
  }

  function settleReverse(
    current: ReverseState | null,
    tone: ReverseState["tone"],
  ): ReverseState | null {
    return current ? { from: current.from, to: current.to, tone } : null;
  }

  function computeFlowState(evts: FlowEvent[]): FlowState {
    const nodes: NodeState[] = LABELS.map((label) => ({
      label,
      status: "idle",
      durationMs: null,
    }));
    let lastNodeIndex = -1;
    let reverse: ReverseState | null = null;

    for (const evt of evts) {
      const directIndex = STAGE_NODE_INDEX[evt.stage];
      if (directIndex !== undefined) {
        for (let i = 0; i < directIndex; i += 1) {
          if (nodes[i].status !== "error" && nodes[i].status !== "stopped") {
            nodes[i].status = "done";
          }
        }
        nodes[directIndex].status = evt.status === "completed" ? "done" : "active";
        nodes[directIndex].durationMs = evt.duration_ms;
        lastNodeIndex = Math.max(lastNodeIndex, directIndex);
        continue;
      }

      // §13.4/§32: DENIED terminates visibly at Policy — it never
      // animates through Simulation or Execute, which is true here
      // structurally (no event for those stages can ever arrive for a
      // denied transaction), not because this branch suppresses them.
      switch (evt.stage) {
        case "DENIED":
          nodes[1].status = "error";
          break;
        case "REJECTED":
          nodes[5].status = "stopped";
          break;
        case "FAILED": {
          const idx = lastNodeIndex >= 0 ? lastNodeIndex : 0;
          nodes[idx].status = "error";
          break;
        }
        case "ROLLING_BACK": {
          const from = lastNodeIndex >= 0 ? lastNodeIndex : 8;
          reverse = { from, to: 6, tone: "active" };
          nodes[9].status = "active";
          break;
        }
        case "RESTORED":
          reverse = settleReverse(reverse, "done");
          nodes[9].status = "done";
          break;
        case "ROLLBACK_FAILED":
          reverse = settleReverse(reverse, "error");
          nodes[9].status = "error";
          break;
        default:
          break;
      }
    }

    return { nodes, reverse };
  }

  $: flow = computeFlowState(events);
  $: nodes = flow.nodes;
  $: reverse = flow.reverse;

  const RADIUS = 15;
  const SPACING = 78;
  const START_X = 40;
  const Y = 46;
  $: width = START_X * 2 + SPACING * (LABELS.length - 1);
  const height = 108;

  function nodeX(i: number): number {
    return START_X + i * SPACING;
  }

  function toneColor(status: NodeStatus): string {
    switch (status) {
      case "error":
        return "#f85149";
      case "stopped":
        return "#8b949e";
      case "active":
      case "done":
        switch (category) {
          case "safe":
            return "#3fb950";
          case "dangerous_containable":
            return "#d29922";
          case "unsafe_to_contain":
            return "#f85149";
          default:
            return "#58a6ff";
        }
      default:
        return "#30363d";
    }
  }

  function connectorActive(i: number): boolean {
    return nodes[i + 1]?.status !== "idle";
  }

  $: activeNodeIndex = nodes.findIndex((n) => n.status === "active");
</script>

<div class="flow-wrap">
  <svg viewBox="0 0 {width} {height}" preserveAspectRatio="xMidYMid meet">
    {#each nodes.slice(0, -1) as _, i}
      <line
        x1={nodeX(i) + RADIUS}
        y1={Y}
        x2={nodeX(i + 1) - RADIUS}
        y2={Y}
        stroke={connectorActive(i) ? toneColor("done") : "#30363d"}
        stroke-width="2"
        class:flowing={i === activeNodeIndex - 1}
      />
    {/each}

    {#if reverse}
      <path
        d="M {nodeX(reverse.from)} {Y + RADIUS + 6} C {nodeX(reverse.from)} {Y + 34}, {nodeX(reverse.to)} {Y + 34}, {nodeX(reverse.to)} {Y + RADIUS + 6}"
        fill="none"
        stroke={reverse.tone === "error" ? "#f85149" : reverse.tone === "done" ? "#8b949e" : "#f85149"}
        stroke-width="2"
        stroke-dasharray="5 4"
        class:reverse-flowing={reverse.tone === "active"}
      />
      <text
        x={(nodeX(reverse.from) + nodeX(reverse.to)) / 2}
        y={Y + 46}
        text-anchor="middle"
        class="reverse-label"
      >
        rollback
      </text>
    {/if}

    {#each nodes as node, i}
      <g class="node" class:active={node.status === "active"}>
        <circle
          cx={nodeX(i)}
          cy={Y}
          r={RADIUS}
          fill={node.status === "idle" ? "#0d1117" : toneColor(node.status)}
          fill-opacity={node.status === "idle" ? 1 : node.status === "active" ? 0.35 : 0.22}
          stroke={toneColor(node.status)}
          stroke-width="2"
        />
        {#if node.status === "done"}
          <text x={nodeX(i)} y={Y + 5} text-anchor="middle" class="glyph" fill={toneColor(node.status)}>
            &#10003;
          </text>
        {:else if node.status === "error"}
          <text x={nodeX(i)} y={Y + 5} text-anchor="middle" class="glyph" fill={toneColor(node.status)}>
            &#10005;
          </text>
        {:else if node.status === "stopped"}
          <text x={nodeX(i)} y={Y + 5} text-anchor="middle" class="glyph" fill={toneColor(node.status)}>
            &#8722;
          </text>
        {/if}
        <text x={nodeX(i)} y={Y + RADIUS + 16} text-anchor="middle" class="node-label">{node.label}</text>
        {#if node.durationMs !== null}
          <text x={nodeX(i)} y={Y - RADIUS - 8} text-anchor="middle" class="duration-label">
            {node.durationMs}ms
          </text>
        {/if}
      </g>
    {/each}
  </svg>
</div>

<style>
  .flow-wrap {
    width: 100%;
    overflow-x: auto;
  }
  svg {
    width: 100%;
    min-width: 620px;
    height: auto;
    display: block;
  }
  .node-label {
    font-size: 6.5px;
    fill: #8b949e;
    font-family: ui-monospace, monospace;
  }
  .duration-label {
    font-size: 6px;
    fill: #58a6ff;
    font-family: ui-monospace, monospace;
  }
  .glyph {
    font-size: 12px;
    font-weight: 700;
  }
  .reverse-label {
    font-size: 6px;
    fill: #f85149;
    font-family: ui-monospace, monospace;
  }
  .node.active circle {
    animation: pulse 1.1s ease-in-out infinite;
  }
  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }
  line.flowing {
    stroke-dasharray: 4 3;
    animation: flow-forward 0.6s linear infinite;
  }
  @keyframes flow-forward {
    to {
      stroke-dashoffset: -7;
    }
  }
  path.reverse-flowing {
    animation: flow-reverse 0.6s linear infinite;
  }
  @keyframes flow-reverse {
    to {
      stroke-dashoffset: 9;
    }
  }
</style>

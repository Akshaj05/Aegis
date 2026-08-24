<script lang="ts">
  // Pipeline flow diagram: renders the fixed pipeline stages as an SVG
  // and derives each node's status from the transaction's event list.
  import type { FlowEvent } from "../lib/types";

  export let events: FlowEvent[] = [];

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
    "Commit",
  ];

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

  const RADIUS = 5;
  const SPACING = 82;
  const START_X = 30;
  const Y = 40;
  $: width = START_X * 2 + SPACING * (LABELS.length - 1);
  const height = 104;

  function nodeX(i: number): number {
    return START_X + i * SPACING;
  }

  function toneColor(status: NodeStatus): string {
    switch (status) {
      case "error":
        return "var(--danger)";
      case "stopped":
        return "var(--text-tertiary)";
      case "active":
      case "done":
        return "var(--accent)";
      default:
        return "var(--border-hair-strong)";
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
        x1={nodeX(i) + RADIUS + 2}
        y1={Y}
        x2={nodeX(i + 1) - RADIUS - 2}
        y2={Y}
        stroke={connectorActive(i) ? "var(--accent)" : "var(--border-hair-strong)"}
        stroke-opacity={connectorActive(i) ? 0.55 : 1}
        stroke-width="1"
      />
    {/each}

    {#if reverse}
      <path
        d="M {nodeX(reverse.from)} {Y + RADIUS + 5} C {nodeX(reverse.from)} {Y + 22}, {nodeX(reverse.to)} {Y + 22}, {nodeX(reverse.to)} {Y + RADIUS + 5}"
        fill="none"
        stroke={reverse.tone === "error" ? "var(--danger)" : reverse.tone === "done" ? "var(--text-tertiary)" : "var(--danger)"}
        stroke-width="1"
        stroke-dasharray="3 3"
        class:reverse-flowing={reverse.tone === "active"}
      />
      <text
        x={(nodeX(reverse.from) + nodeX(reverse.to)) / 2}
        y={Y + 32}
        text-anchor="middle"
        class="reverse-label"
      >
        rollback
      </text>
    {/if}

    {#each nodes as node, i}
      <g class="node" class:active={node.status === "active"}>
        {#if node.status === "active"}
          <circle cx={nodeX(i)} cy={Y} r={RADIUS + 3} fill="none" stroke="var(--accent)" stroke-opacity="0.35" class="pulse-ring" />
        {/if}
        <circle
          cx={nodeX(i)}
          cy={Y}
          r={RADIUS}
          fill={node.status === "idle" ? "var(--bg)" : toneColor(node.status)}
          stroke={toneColor(node.status)}
          stroke-width="1"
        />
        <text x={nodeX(i)} y={Y + RADIUS + 13} text-anchor="middle" class="node-label">{node.label}</text>
        {#if node.durationMs !== null}
          <text x={nodeX(i)} y={Y - RADIUS - 6} text-anchor="middle" class="duration-label">
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
  }
  svg {
    width: 100%;
    height: auto;
    display: block;
  }
  .node-label {
    font-size: 8.5px;
    font-weight: 700;
    fill: var(--text);
    font-family: var(--mono);
    letter-spacing: 0.01em;
  }
  .duration-label {
    font-size: 7px;
    fill: var(--text-tertiary);
    font-family: var(--mono);
  }
  .reverse-label {
    font-size: 5.5px;
    fill: var(--danger);
    font-family: var(--mono);
  }
  .pulse-ring {
    animation: pulse-ring 1.6s ease-in-out infinite;
    transform-origin: center;
    transform-box: fill-box;
  }
  @keyframes pulse-ring {
    0% {
      transform: scale(0.85);
      opacity: 0.5;
    }
    70% {
      transform: scale(1.6);
      opacity: 0;
    }
    100% {
      transform: scale(1.6);
      opacity: 0;
    }
  }
  path.reverse-flowing {
    animation: flow-reverse 0.8s linear infinite;
  }
  @keyframes flow-reverse {
    to {
      stroke-dashoffset: 6;
    }
  }
</style>

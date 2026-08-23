# SafeShell Security Claims

Canonical wording. This document governs the phrasing used in the UI (the
DENY panel, the approval panel, the environment indicator), the README, and
any presentation of SafeShell. Copy from it rather than paraphrasing
(docs/CLAUDE.md invariant #25). Sourced from docs/architecture.md §38;
consult that section for the reasoning behind each line, not just the text.

If a form of words is needed that isn't covered below, add it here first and
then use it elsewhere — don't originate new claims wording at the point of
use.

## What SafeShell claims

For the **supported command model** (docs/architecture.md §19) executed
against its **isolated simulated environment**, SafeShell provides:

- simulation before execution
- a predicted diff
- deterministic risk classification
- explicit user approval for medium-risk and above
- a checkpoint taken immediately before execution
- verification of actual against predicted effects
- deterministic rollback of filesystem effects to that checkpoint

Enforcement decisions are deterministic and are not influenced by AI output.

Recovery is performed by deterministic code, not by AI-generated commands.

Isolation is enforced by Linux namespaces, `pivot_root`,
`openat2`/`RESOLVE_BENEATH`, seccomp-bpf, cgroups v2, and (where available)
Landlock.

## What SafeShell explicitly does not claim

- **Not universal command safety.** Safety properties apply only to the
  supported command model, inside the simulated environment.
- **Not perfect rollback.** Rollback covers filesystem state within the
  simulated environment to a retained checkpoint. Non-filesystem mock state
  is disclosed as partially reversible. Checkpoints outside the retention
  window are gone.
- **Not complete Linux isolation.** The supported command set is closed;
  SafeShell is not a general-purpose sandbox for arbitrary binaries.
- **Not VM-level isolation. Linux namespaces share the host kernel.** There
  is one kernel. A sandboxed process is a real host process issuing real
  host syscalls. Namespaces change what it can see and address, not which
  kernel serves it.
- **Not protection against arbitrary kernel vulnerabilities.** A kernel
  privilege-escalation bug could in principle defeat namespace-based
  isolation. Stronger isolation requires a separate kernel — microVM
  (Firecracker) or full VM (QEMU/KVM) — which is future work, not a present
  capability, and must never be described as if it already existed.
- **Not perfect simulation.** Simulation fidelity is high because
  simulation and execution share a handler implementation, and it is
  measured rather than asserted — but divergence is possible, which is
  precisely why verification and automatic rollback exist.
- **Not AI-certified safety.** The AI certifies nothing. It explains. A
  risk level shown to the user is a deterministic heuristic aid to the
  user's own judgment, not a certification that an approved command is
  safe.
- **Not tamper-proof auditing.** The audit log is tamper-evident only.

## Scoping statement (canonical wording)

> SafeShell's guarantees are scoped to its supported command model and its
> isolated simulated environment. Within that scope, effects are
> previewed, approved, checkpointed, verified, and reversible. Outside
> that scope, SafeShell makes no guarantee, and operations that would take
> it outside that scope are denied rather than attempted.

## Terms that are retired from use

- **"Full kernel access"** — inaccurate; retired in favor of the framing in
  docs/architecture.md §18 (one shared host kernel; namespaces change what
  a process can see and address, not which kernel serves its syscalls).
- **"Completely secure" / "perfect rollback" / "AI-certified safety"** —
  never used anywhere in SafeShell's own text, per docs/CLAUDE.md
  invariant #25.
- Placing files under `~/SafeShellLab/` (or any backing-store path) is a
  storage decision, never described as isolation in itself
  (docs/architecture.md §14.1, §25.4).

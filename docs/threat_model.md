# SafeShell Threat Model

Sourced from docs/architecture.md §37 (adversary scope) and §36 (mitigation
inventory). This document exists so implementation and review work has a
single place to check "is this in scope?" without re-deriving it from the
full architecture document each time.

## In-scope adversary

A malicious or malformed command string typed or pasted into the SafeShell
terminal, and malicious content encountered within the simulated filesystem
(for example, a crafted file whose contents are shown to the AI).

Goal: escape the sandbox, reach or corrupt host data, achieve host code
execution, or induce SafeShell to lose or corrupt recoverable state.

## Out-of-scope adversary

- A local user with host root deliberately attacking their own SafeShell
  installation. No unprivileged host process can defend against host root.
- A network adversary. The application listens on no network socket by
  default, and the sandbox has no route.

## Disclosed data flow: the AI backend (`ai::backend::RemoteBackend`, `ai::backend::OllamaBackend`)

Not a network *adversary* claim above — a plain disclosure the claims-wording
review (Build order phase 13) found missing. When SafeShell is configured
with `SAFESHELL_AI_ENDPOINT` set (`main.rs`), the host-side core makes real
outbound HTTPS-style requests to that endpoint (`ai::backend::RemoteBackend`,
via `ureq`), carrying the submitted command text, its policy category, risk
level, and policy reasons (`ai::schema::AiRequest`) — never file contents,
never anything read from the simulated filesystem, and never the API key
itself beyond the request's own auth header. This is client-initiated
outbound traffic, not a listening socket, so it doesn't contradict "the
application listens on no network socket by default" above — but it is a
real data flow to a third party the user configured, and belongs in this
document rather than only in `ai::backend`'s own doc comment. With no
endpoint configured (the default), `NullBackend` is used and no network
request of any kind is ever made (§21.9, §21.10).

The same disclosure applies to `SAFESHELL_OLLAMA_MODEL`: it makes SafeShell
send the identical `AiRequest` fields (as a rendered prompt, not the raw
struct) to a local Ollama server's `/api/generate` endpoint over plain HTTP,
defaulting to `http://localhost:11434` unless `SAFESHELL_OLLAMA_ENDPOINT`
overrides it. This traffic normally never leaves the machine — but "Ollama
server" is a network destination like any other from this process's point of
view, and nothing stops a user from pointing `SAFESHELL_OLLAMA_ENDPOINT` at a
non-local host, at which point the same third-party-data-flow disclosure
above applies verbatim. `SAFESHELL_OLLAMA_MODEL` and `SAFESHELL_AI_ENDPOINT`
are mutually exclusive opt-ins (`main.rs::build_ai_backend`, Ollama checked
first); as with `RemoteBackend`, the model's raw output is never trusted
directly — it goes through the same `ai::validation::validate` every other
backend's output does before it can become an `AiPlan` (§21.7).

## Disclosed data flow: the coreutils sidecar subprocesses (`handlers::coreutils_proc`)

Not a network flow — a local one, disclosed for the same reason the AI backend flow above is: it's
a real, undisclosed-until-now process boundary a reviewer would otherwise have to find in the code
themselves. `wc`, `sort`, `uniq`, `cut`, `head`, `tail`, and `date` are implemented by spawning a
real OS process — one of SafeShell's own compiled `safeshell-{wc,sort,uniq,cut,head,tail,date}`
binaries (real `uutils`/coreutils crates under the hood), via `std::process::Command` with an
explicit argv, never a shell string. Two properties keep this from being a general
subprocess-execution primitive: the binary is always one of these seven fixed, SafeShell-compiled
paths (never a user-named or `PATH`-resolved command), and its argv never contains a filesystem
path — only flags. Any file content the command needs is read beforehand through the sandboxed
resolver (§25's `openat2`+`RESOLVE_BENEATH` containment) and piped to the subprocess over stdin;
its stdout/stderr are captured, never inherited by or shared with SafeShell's own process. A
compromised or buggy sidecar binary therefore has no path handed to it to reach in the first
place — worst case is a wrong or hung transformation of bytes SafeShell already had, not a
containment breach. One caveat worth stating plainly: the subprocess is spawned with this
process's full environment (not the simulated session's `TerminalSession` environment, and not
cleared) — none of these seven commands read environment variables for anything security-relevant,
but this is a real difference from how the simulated shell's own `env`/`printenv` commands report
environment state, and is disclosed here rather than left implicit.

## Explicitly not modeled as an adversary

The user performing destructive operations on purpose inside the SafeShell
environment. That is the product's intended use, not an attack. The threat
model concerns the boundary, not the user's intentions within it.

## Primary demonstrated scenario

A command that, had it escaped, would destroy real user data — demonstrated
by showing that a fully approved, fully executed `rm -rf` affects only the
simulated environment, and that the environment is then restored by a
single deterministic undo (docs/architecture.md §44).

## Mitigation inventory

Full detail lives in docs/architecture.md §36; summarized here by category
so a reviewer can see at a glance what class of guarantee applies to a given
threat.

### Guaranteed by MVP design (§36.1)

Command/shell injection, path traversal escaping the sandbox, symlink
attacks, frontend executing arbitrary commands or reading arbitrary paths,
fork bombs and runaway resource use, AI output altering enforcement, AI
output triggering or misdirecting rollback, prompt injection escalating
privilege, execution without a snapshot, execution after rejection or
denial.

### Defense in depth — risk reduction, not a standalone guarantee (§36.2)

Namespace escape via kernel vulnerability (documented residual risk: a
kernel privilege-escalation bug could in principle permit namespace escape
— an industry-wide property of shared-kernel isolation, not specific to
SafeShell), TOCTOU between analysis and execution, malicious content within
the simulated filesystem, audit log tampering, bugs in the host-side Rust
core, dependency vulnerabilities, memory-safety defects.

### Explicitly out of scope for MVP (§36.3)

Protection against a kernel 0-day enabling namespace escape (inherent to
non-VM sandboxing); protection of the audit log against a host-root actor;
protection against host-level resource exhaustion from many concurrent
SafeShell sessions; any claim about commands not typed into SafeShell's own
terminal.

## Relationship to docs/security_claims.md

This document says what SafeShell defends against and against whom.
`docs/security_claims.md` says how that is worded for a user-facing
audience. When the two would appear to conflict, the threat model is the
more detailed/technical statement and the claims document is its
user-facing distillation — they should never actually disagree; if a
change to one doesn't have a corresponding update to the other, that's a
bug in the docs, not a real discrepancy to route around.

# Kubernetes: future layout (design only, not implemented)

No Kubernetes manifests exist in this repository yet, deliberately. This
document describes how the Docker deployment (`docs/deployment.md`) was
structured so that adding them later is a packaging exercise, not an
application change — and names the parts of a real deployment that would need
genuine design work first rather than being a mechanical translation.

## Why this is deferred, not built

The Docker deployment's central fact — Ageis is a native GUI app rendered via
noVNC — carries over to Kubernetes unchanged, but two things make a real
Kubernetes deployment a bigger decision than "write a Deployment YAML":

1. **Sandbox capability grants are node-dependent, not just container-config.**
   `docker-compose.yml`'s `cap_add: [SYS_ADMIN]` / `security_opt` maps to a Pod
   `securityContext` well enough, but the Ubuntu-24.04-AppArmor-sysctl
   requirement (`docs/deployment.md`) is a **host kernel setting**. In a
   cluster, that means either a `DaemonSet`/init step touching node sysctls
   (itself a cluster-admin-level decision, not something a workload manifest
   should do implicitly) or accepting that some nodes will run SafeShell in
   its degraded (`CopyUpSimulationBackend`, capability-gated) mode and others
   won't, depending on node kernel/config drift — a real scheduling/affinity
   question, not a template-filling one.
2. **This is a single-user desktop app, not a horizontally-scalable service.**
   One running instance = one interactive session with its own SQLite DB and
   layered filesystem state (`docs/architecture.md` §23). Multi-user
   Kubernetes deployment means either one Pod per user (a real multi-tenancy
   and lifecycle-management design, including how a user's Pod gets
   provisioned/torn down and how `NOVNC_PORT`/ingress routing maps users to
   their own Pod) or a redesign of the storage/session model to be genuinely
   multi-tenant — the latter would be an application change, explicitly out
   of scope here.

Building either of these prematurely, without a real answer to "who runs this
in a cluster and how many of them," would be scaffolding nobody asked for
(`docs/CLAUDE.md`'s own "Scope guard" says as much for this project generally).

## What does carry over cleanly today

The Docker image itself (`docker/Dockerfile`) is already cluster-ready as an
artifact — nothing about it is Compose-specific:

- It's a single, self-contained multi-stage build producing one runtime image
  with no build-time dependency on Compose.
- Configuration is entirely environment-variable-driven (`SAFESHELL_OLLAMA_*`,
  `VNC_PASSWORD`, `SCREEN_GEOMETRY`) — the same shape a Kubernetes
  `ConfigMap`/`Secret` would inject, no translation needed.
- State is already split into two named volumes with clear ownership
  (`ageis_data` for SQLite + session layers, `ollama_data` for model weights)
  — the same split a `PersistentVolumeClaim` per concern would use.
- The healthchecks (`docker-compose.yml`) are plain HTTP/CLI probes with no
  Docker-specific mechanics — they map directly to `livenessProbe`/
  `readinessProbe` `httpGet`/`exec` stanzas.

## Sketch of the eventual shape (illustrative, not a spec)

```
Namespace: ageis
  Deployment: ollama (1 replica, or a shared/external Ollama service)
    PVC: ollama-models
    Service: ollama (ClusterIP, port 11434) — same role docker-compose's
      service-name resolution plays today; SAFESHELL_OLLAMA_ENDPOINT would
      point at "http://ollama.ageis.svc.cluster.local:11434"

  Per user session (StatefulSet or per-user Deployment — an open question,
  not decided here):
    Pod: ageis
      securityContext: capabilities.add: [SYS_ADMIN]; the seccomp/AppArmor
        equivalents of docker-compose's security_opt (a Pod-level
        seccompProfile/appArmorProfile, or a cluster-provided profile)
      PVC (per-session): ageis-data
      Service + Ingress (or a session-aware gateway): routes to that Pod's
        noVNC port — this is the multi-tenancy question from above; a plain
        single Service in front of multiple replicas would NOT work, since
        each Pod has its own independent session/window, unlike a stateless
        web backend.
```

## What would need to be decided before writing real manifests

- Single-shared-instance vs. per-user Pod provisioning (see above) — a
  product decision, not a Kubernetes one.
- Whether node sysctl requirements (the Ubuntu AppArmor case) are handled via
  node selectors/taints restricting scheduling to prepared nodes, or accepted
  as a source of degraded-but-safe fallback behavior across the fleet.
- GPU scheduling for Ollama, if a non-CPU model is desired at cluster scale
  (`nvidia.com/gpu` resource requests) — orthogonal to everything above.
- Ingress/TLS termination in front of noVNC, and whether `VNC_PASSWORD`
  remains sufficient authentication or should be replaced by whatever the
  cluster's existing auth boundary is (e.g. an authenticating proxy in front
  of the Ingress, rather than relying on noVNC's own weak auth alone).

None of this blocks the current Docker Compose deployment; it's recorded here
so the next real Kubernetes effort starts from these questions instead of
re-deriving them.

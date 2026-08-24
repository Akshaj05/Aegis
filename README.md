# Ageis (SafeShell)

A transactional shell sandbox: every command is parsed, risk-classified,
simulated, explained, approved where warranted, executed, verified, and
reversible. See `docs/architecture.md` for the full design.

## Run it with Docker (recommended for a first look)

```bash
git clone <repo-url> ageis
cd ageis
cp .env.example .env
docker compose up --build
```

Then open `http://localhost:6080` in a browser — Ageis is a native desktop
app, so this deployment gives it a virtual display viewable from any browser
rather than requiring a native Linux GUI setup. Full setup, environment
variables, Ollama model pull instructions, sandbox-capability details, and
troubleshooting: **[`docs/deployment.md`](docs/deployment.md)**.

## Run it natively (developing on it directly)

```bash
cd src-tauri && cargo check          # fast loop
npm run tauri dev                    # full app, native window
```

See `docs/CLAUDE.md` for the working contract and build order, and
`src-tauri/.env.example` for local AI/Ollama configuration when running this
way (not the Docker path above, which uses the root `.env.example` instead).

## Documentation

- `docs/architecture.md` — the authoritative design spec.
- `docs/threat_model.md`, `docs/security_claims.md` — what Ageis defends
  against, and the canonical wording for what it claims (and explicitly does
  not claim).
- `docs/deployment.md` — Docker deployment, sandbox compatibility inside
  containers, troubleshooting.
- `docs/deployment-kubernetes.md` — future Kubernetes layout (design notes,
  not implemented).

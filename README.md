# Aegis

A transactional shell sandbox: every command is parsed, risk-classified,
simulated, explained, approved where warranted, executed, verified, and
reversible. See `docs/architecture.md` for the full design.

## Run it natively (developing on it directly)

```bash
cd src-tauri && cargo check          # fast loop
npm run tauri dev                    # full app, native window
```

See `docs/CLAUDE.md` for the working contract and build order, and
`src-tauri/.env.example` for local AI/Ollama configuration.

## Documentation

- `docs/architecture.md` — the authoritative design spec.
- `docs/threat_model.md`, `docs/security_claims.md` — what Ageis defends
  against, and the canonical wording for what it claims (and explicitly does
  not claim).

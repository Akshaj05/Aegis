# Demo Project

A small seeded project used by SafeShell's demo scenario
(docs/architecture.md §44) and by manual exploration of the terminal.

Nothing about this directory or its contents is special from SafeShell's
point of view — it is ordinary simulated-filesystem content, subject to
the same simulate → approve → execute → verify → recover pipeline as
anything else a user creates. It exists only so a first-run session has
something to `ls`, `cd`, and `cat` before the user has typed anything.

## Layout

- `src/main.rs` — a placeholder source file.
- `README.md` — this file.

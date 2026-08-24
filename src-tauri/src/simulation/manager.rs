//! Ties transient-layer lifecycle, `LayeredResolver`, and the shared
//! `handlers::dispatch` code path together into one simulation pass
//! (§22.2). This is the concrete realization of docs/CLAUDE.md invariant
//! #12: "Simulation writes only to a disposable transient layer, unlinked
//! on every path (success, error, panic-unwind, rejection, teardown). Tie
//! its lifetime to an RAII guard" — [`TransientLayerGuard`] is that guard.
//!
//! **Scope**: one command, not a pipeline — `handlers::dispatch` itself
//! only handles a single stage (§17.8's pipe-wiring between stages isn't
//! implemented yet), so `simulate` doesn't attempt to either. Extending to
//! pipelines is a `handlers/`-level change this module would then just
//! call once, not a `simulation/`-level redesign.

use crate::handlers::{self, CommandResult};
use crate::parser::ParsedCommand;
use crate::session::TerminalSession;
use crate::simulation::diff::{self, SimulationDiff};
use crate::simulation::resolver::LayeredResolver;
use crate::snapshot::backend::{
    LayerId, LayerStack, SimulationBackend, SimulationError, WriteTarget,
};

pub struct SimulationOutcome {
    pub command_result: CommandResult,
    pub diff: SimulationDiff,
}

/// Owns a transient layer for exactly as long as this guard lives, and
/// discards it on drop — unconditionally, regardless of whether the scope
/// exited normally, via `?`, or via an unwinding panic. Errors from the
/// discard itself are swallowed: a guard's `Drop` can't return a
/// `Result`, and a failed cleanup of a *disposable* layer (never anything
/// persistent) isn't something any caller could meaningfully act on
/// differently than "log and move on" — this doesn't log yet either
/// (no `audit`/logging wiring reaches this deep into `simulation/`),
/// which is a real, disclosed gap, not a silent one: swallowing a
/// transient-layer discard failure here has no correctness impact (worst
/// case is a leaked directory under the layers root, not a security or
/// persistence issue), but should get a log line once this module has
/// somewhere to send one.
struct TransientLayerGuard<'a> {
    backend: &'a dyn SimulationBackend,
    id: crate::snapshot::backend::TransientLayerId,
}

impl Drop for TransientLayerGuard<'_> {
    fn drop(&mut self) {
        let _ = self.backend.discard_layer(LayerId::Transient(self.id));
    }
}

/// §22.2's mechanism, steps 1-5: fresh transient layer, mount a view with
/// it as the write target, run the shared handler code path against that
/// view, compute the diff, discard the transient layer. Step 5 (discard)
/// happens via `TransientLayerGuard`'s `Drop`, so it runs on every exit
/// path from this function, including an early `?` return from a failed
/// `mount_view`/`LayeredResolver::from_mounted_view` — matching §22.4:
/// "If the transient layer cannot be created, the view cannot be mounted,
/// or the handler errors during simulation, the transaction moves to
/// FAILED. It does not proceed to execution."
pub fn simulate(
    backend: &dyn SimulationBackend,
    layers: &LayerStack,
    session: &mut TerminalSession,
    parsed: &ParsedCommand,
) -> Result<SimulationOutcome, SimulationError> {
    let transient_id = backend.create_transient_layer(layers)?;
    let guard = TransientLayerGuard {
        backend,
        id: transient_id,
    };

    let view = backend.mount_view(layers, WriteTarget::Transient(transient_id))?;
    let resolver = LayeredResolver::from_mounted_view(&view)?;

    let command_result = handlers::dispatch(
        &parsed.name,
        &parsed.args,
        &parsed.redirections,
        session,
        &resolver,
    );

    let transient_layer_path = view
        .layers
        .first()
        .expect("mount_view always returns at least one layer")
        .clone();
    let diff = diff::compute(&transient_layer_path, &view)?;

    drop(guard); // explicit for clarity; would happen at scope end regardless.
    Ok(SimulationOutcome {
        command_result,
        diff,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_line;
    use crate::snapshot::copyup::CopyUpSimulationBackend;
    use std::collections::HashMap;

    fn fresh_stack(root: &std::path::Path) -> (CopyUpSimulationBackend, LayerStack) {
        let backend = CopyUpSimulationBackend::new(root.join("layers")).unwrap();
        let base = root.join("base");
        std::fs::create_dir_all(&base).unwrap();
        let active_write = root.join("write");
        std::fs::create_dir_all(&active_write).unwrap();
        (
            backend,
            LayerStack {
                base,
                checkpoints: Vec::new(),
                active_write,
            },
        )
    }

    fn parse(line: &str) -> ParsedCommand {
        parse_line(line, &HashMap::new())
            .unwrap()
            .segments
            .into_iter()
            .next()
            .unwrap()
            .0
    }

    #[test]
    fn simulating_mkdir_never_touches_persistent_state() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, stack) = fresh_stack(tmp.path());
        let mut session = TerminalSession::new();
        let cmd = parse("mkdir project");

        let outcome = simulate(&backend, &stack, &mut session, &cmd).unwrap();

        assert_eq!(
            outcome.command_result.exit_code, 0,
            "stderr: {}",
            outcome.command_result.stderr
        );
        assert_eq!(
            outcome.diff.directories_created,
            vec!["project".to_string()]
        );
        // The whole point: nothing landed in the active write layer or base.
        assert!(!stack.active_write.join("project").exists());
        assert!(!stack.base.join("project").exists());
    }

    #[test]
    fn transient_layer_is_discarded_after_simulation() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, stack) = fresh_stack(tmp.path());
        let mut session = TerminalSession::new();
        let cmd = parse("mkdir project");

        let before: Vec<_> = std::fs::read_dir(tmp.path().join("layers/transient"))
            .unwrap()
            .collect();
        assert!(before.is_empty());

        simulate(&backend, &stack, &mut session, &cmd).unwrap();

        let after: Vec<_> = std::fs::read_dir(tmp.path().join("layers/transient"))
            .unwrap()
            .collect();
        assert!(
            after.is_empty(),
            "transient layer directory must be discarded after simulation"
        );
    }

    #[test]
    fn simulating_touch_on_an_existing_base_file_reports_no_change() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, stack) = fresh_stack(tmp.path());
        std::fs::write(stack.base.join("existing.txt"), b"already here").unwrap();
        let mut session = TerminalSession::new();
        let cmd = parse("touch existing.txt");

        let outcome = simulate(&backend, &stack, &mut session, &cmd).unwrap();
        assert_eq!(outcome.command_result.exit_code, 0);
        assert!(outcome.diff.files_created.is_empty());
        assert!(outcome.diff.files_modified.is_empty());
    }

    #[test]
    fn simulating_a_command_that_reads_a_checkpoint_file_sees_it() {
        let tmp = tempfile::tempdir().unwrap();
        let (backend, mut stack) = fresh_stack(tmp.path());
        std::fs::write(stack.active_write.join("a.txt"), b"hello").unwrap();
        backend.seal_active_layer(&mut stack).unwrap();
        let mut session = TerminalSession::new();
        let cmd = parse("cat a.txt");

        let outcome = simulate(&backend, &stack, &mut session, &cmd).unwrap();
        assert_eq!(
            outcome.command_result.exit_code, 0,
            "stderr: {}",
            outcome.command_result.stderr
        );
        assert_eq!(outcome.command_result.stdout, "hello");
    }

    #[test]
    fn simulation_failure_leaves_no_trace_and_returns_an_error() {
        // Simulate against a layer stack whose base directory doesn't
        // exist at all — mount_view (and therefore the whole pass) should
        // fail cleanly rather than silently proceeding.
        let tmp = tempfile::tempdir().unwrap();
        let backend = CopyUpSimulationBackend::new(tmp.path().join("layers")).unwrap();
        let stack = LayerStack {
            base: tmp.path().join("does-not-exist"),
            checkpoints: Vec::new(),
            active_write: tmp.path().join("write"),
        };
        std::fs::create_dir_all(&stack.active_write).unwrap();
        let mut session = TerminalSession::new();
        let cmd = parse("ls");

        let result = simulate(&backend, &stack, &mut session, &cmd);
        assert!(result.is_err());
    }
}

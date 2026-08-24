//! Shared subprocess-spawning helper for the stdin/stdout-only filter tier
//! (`wc`, `sort`, `uniq`, `cut`, `head`, `tail`, `date` — see
//! `handlers/text_filters.rs`).
//!
//! **Why a real subprocess, not an in-process library call**: uutils' own
//! per-command crates (`uu_wc`, `uu_sort`, ...) expose exactly one public
//! entry point, `uumain(args: impl uucore::Args) -> i32` — it takes
//! injectable *argv*, but internally reads/writes the real, process-global
//! `std::io::stdin()`/`std::io::stdout()` directly (verified against the
//! published crate source; there is no injectable-reader/writer variant).
//! That's fine for a real, separate OS process — stdin/stdout are already
//! private per-process — but not safe to call in-process here: SafeShell
//! runs commands from multiple sessions concurrently on a blocking thread
//! pool (`ipc::run_blocking`), and process-wide stdout is one shared
//! mutable OS resource every thread would be racing to redirect and read
//! back. A real subprocess sidesteps that for free, the same way a real
//! shell's own pipeline does.
//!
//! **Why this doesn't weaken containment**: every command in this tier
//! only ever receives *flags* in argv — never a path. The bytes it
//! operates on are read beforehand through
//! [`crate::simulation::resolver::LayeredResolver`] (already
//! `openat2`+`RESOLVE_BENEATH`-contained) and piped to the subprocess over
//! stdin; its output is captured from stdout, never written to a real
//! path directly. A compromised or buggy filter binary that never
//! received a path to begin with has nothing on the simulated filesystem
//! to reach — worst case is a wrong or hung transformation of bytes
//! SafeShell already had. This is `std::process::Command` with an
//! explicit, SafeShell-constructed argv array (docs/CLAUDE.md invariant
//! #15) — never a shell string, never user input concatenated into one.

use std::io::Write;
use std::process::{Command, Stdio};

/// Locates the sidecar binary `safeshell-<name>` alongside the running
/// `safeshell` executable. Each is a tiny `[[bin]]` target under
/// `src/bin/` (e.g. `safeshell-wc.rs`) that does nothing but call the real
/// `uu_<name>::uumain` — built by the same cargo workspace, so it's always
/// present next to `safeshell` in `cargo test`/`cargo run`'s target
/// directory. Shipping it in a packaged release build additionally needs
/// a `tauri.conf.json` `bundle.externalBin` entry, which is a packaging
/// concern outside this change's scope (dev/test environments, which is
/// everything this pass can verify, don't need it).
fn sidecar_path(name: &str) -> std::io::Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?;
    let mut dir = exe
        .parent()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not resolve the running executable's directory",
            )
        })?
        .to_path_buf();
    // Under `cargo test`, `current_exe()` is a test harness binary living
    // in `target/<profile>/deps/`, one level below where cargo actually
    // places `[[bin]]` targets like `safeshell-wc` — normal `cargo run`/a
    // packaged build's `current_exe()` has no `deps` component and is left
    // alone.
    if dir.file_name().is_some_and(|f| f == "deps") {
        dir.pop();
    }
    Ok(dir.join(format!("safeshell-{name}")))
}

/// Runs `safeshell-<name>` with `flags` as its only argv (no path
/// arguments, ever — see module doc), `stdin_bytes` piped in, and
/// stdout/stderr captured (never inherited from this process). Returns
/// `(stdout, stderr, exit_code)`. stdin is written from a helper thread so
/// a large input can never deadlock against a filter that starts writing
/// output before it has finished reading input (both pipes have bounded
/// kernel buffers).
pub fn run_filter(name: &str, flags: &[&str], stdin_bytes: &[u8]) -> (String, String, i32) {
    let path = match sidecar_path(name) {
        Ok(p) => p,
        Err(e) => {
            return (
                String::new(),
                format!("{name}: sidecar binary not found: {e}\n"),
                127,
            )
        }
    };

    let mut child = match Command::new(&path)
        .args(flags)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (String::new(), format!("{name}: {e}\n"), 127),
    };

    let mut stdin = child.stdin.take().expect("stdin was requested as piped");
    let owned_input = stdin_bytes.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&owned_input);
        // `stdin` drops here, closing the pipe — the child's read of EOF.
    });

    let output = child.wait_with_output();
    let _ = writer.join();

    match output {
        Ok(out) => (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(1),
        ),
        Err(e) => (String::new(), format!("{name}: {e}\n"), 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_filter_pipes_stdin_and_captures_stdout() {
        let (stdout, stderr, code) = run_filter("wc", &["-l"], b"a\nb\nc\n");
        assert_eq!(code, 0, "stderr: {stderr}");
        assert_eq!(stdout.trim(), "3");
    }

    #[test]
    fn run_filter_never_receives_a_path_argument() {
        // The whole point of this tier: flags only, content over stdin.
        let (stdout, stderr, code) = run_filter("sort", &[], b"banana\napple\ncherry\n");
        assert_eq!(code, 0, "stderr: {stderr}");
        assert_eq!(stdout, "apple\nbanana\ncherry\n");
    }

    #[test]
    fn a_missing_sidecar_fails_closed_rather_than_falling_back_to_a_real_shell() {
        let (_stdout, stderr, code) = run_filter("does-not-exist-command", &[], b"");
        assert_eq!(code, 127);
        assert!(!stderr.is_empty());
    }
}

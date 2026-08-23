//! Typed handlers, one per supported command. See `docs/architecture.md`
//! §17.7, §19.3.
//!
//! Now run against [`crate::simulation::resolver::LayeredResolver`] rather
//! than Phase 1's original [`crate::fs_abstraction::PlainDirBackend`] —
//! that type's own module doc always said it was temporary, "not the
//! permanent implementation," replaced once real path resolution existed.
//! It now does: `LayeredResolver` composes `sandbox/worker/resolver.rs`'s
//! `RootResolver`, so every read/write here inherits real
//! `openat2`+`RESOLVE_BENEATH` kernel-enforced containment (§25.2) instead
//! of `PlainDirBackend`'s string-validation-only checks. This is a
//! genuine security upgrade, not just a refactor for layering's sake.
//! `PlainDirBackend` itself is now unused anywhere in this crate and has
//! been deleted from `fs_abstraction` rather than left as dead code.
//!
//! This module depends on `simulation::resolver` for `LayeredResolver`,
//! while `simulation::manager` depends on this module's [`dispatch`] —
//! deliberately bidirectional within the crate (Rust doesn't restrict
//! intra-crate module dependency direction the way it restricts crate
//! dependencies): `simulation/backend.rs`'s own module doc already said
//! building the merged read/write API was "explicitly Build order phase
//! 6's job," which put it in `simulation/`, and handlers are the natural
//! thing that API serves.
//!
//! Still Phase-1-tier scope: `pwd, cd, mkdir, touch, ls, cat, echo, rm`.
//! `rm` is the first handler whose predicted/actual diffs can contain
//! deletions — it relies on `LayeredResolver::remove`'s whiteout-marker
//! design (see that module's doc comment) to represent "this path, which
//! may live in a lower snapshot layer, no longer exists" without a real
//! kernel overlay filesystem. The remaining commands (`rmdir, cp, mv,
//! chmod, chown, ln, grep, find, head, tail, wc, mkfifo, export, env,
//! which, history`) and the process-affecting partially-supported
//! commands (`ps`, `kill`) are still not implemented — same reasoning as
//! before: adding them is direct repetition of this module's pattern, not
//! a new design question.
//!
//! [`dispatch`] is still not the architecture's real command-dispatch
//! layer — §19's support-tier routing (now real, in `policy::support_tiers`
//! since Build order phase 4) still isn't wired to this dispatcher. It
//! returns exit code 127 for anything it doesn't recognize, matching
//! POSIX shell behavior for a missing command (§17.4) as a placeholder.
//!
//! **This pass is what makes §19.3/§22.2's "no separate dry-run
//! implementation" invariant load-bearing for real**: [`dispatch`] is now
//! called both by `simulation::manager` (writing to a disposable transient
//! layer) and will be called by `executor/` once it exists (Build order
//! phase 6-7, writing to the persistent active write layer) — same
//! function, same code, differing only in which `LayeredResolver` (built
//! from a different `WriteTarget`, per `snapshot::backend`) it's given.

use crate::fs_abstraction::SandboxPath;
use crate::parser::Arg;
use crate::sandbox::worker::protocol::FileKind;
use crate::session::TerminalSession;
use crate::simulation::resolver::LayeredResolver;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl CommandResult {
    fn ok(stdout: impl Into<String>) -> Self {
        CommandResult {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: 0,
        }
    }

    fn error(stderr: impl Into<String>, exit_code: i32) -> Self {
        CommandResult {
            stdout: String::new(),
            stderr: stderr.into(),
            exit_code,
        }
    }
}

/// Phase-1-tier dispatcher. See module docs for its intended lifetime.
pub fn dispatch(
    name: &str,
    args: &[Arg],
    session: &mut TerminalSession,
    resolver: &LayeredResolver,
) -> CommandResult {
    match name {
        "pwd" => cmd_pwd(session),
        "cd" => cmd_cd(session, resolver, args),
        "mkdir" => cmd_mkdir(session, resolver, args),
        "touch" => cmd_touch(session, resolver, args),
        "ls" => cmd_ls(session, resolver, args),
        "cat" => cmd_cat(session, resolver, args),
        "echo" => cmd_echo(args),
        "rm" => cmd_rm(session, resolver, args),
        _ => CommandResult::error(format!("{name}: command not found"), 127),
    }
}

/// Resolves a path argument against the session's cwd, handling `..`/`.`
/// and a leading `/` the way a real shell would (§17.3). See
/// [`SandboxPath::resolve_relative`] for why this differs from `parse`.
/// This remains a redundant, defense-in-depth second check (§25.1) — the
/// primary control is `LayeredResolver`'s underlying `openat2`/
/// `RESOLVE_BENEATH`, not this string-level normalization.
fn resolve_arg(session: &TerminalSession, raw: &str) -> Result<SandboxPath, String> {
    session
        .cwd()
        .resolve_relative(raw)
        .map_err(|e| format!("{raw}: {e}"))
}

fn cmd_pwd(session: &TerminalSession) -> CommandResult {
    CommandResult::ok(format!("{}\n", session.cwd()))
}

fn cmd_cd(
    session: &mut TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    let target_raw = match args.first() {
        Some(a) => a.as_str(),
        None => "/", // bare `cd` goes to the sandbox root; SafeShell has no
                     // real per-user HOME directory concept beyond the
                     // seeded $HOME value, so root is the defined default.
    };

    let target = match resolve_arg(session, target_raw) {
        Ok(p) => p,
        Err(e) => return CommandResult::error(format!("cd: {e}\n"), 1),
    };

    match resolver.stat(target.as_str()) {
        Ok(info) if info.kind == FileKind::Directory => {
            session.set_cwd(target);
            CommandResult::ok("")
        }
        Ok(_) => CommandResult::error(format!("cd: {target_raw}: Not a directory\n"), 1),
        Err(e) => CommandResult::error(format!("cd: {target_raw}: {e}\n"), 1),
    }
}

fn cmd_mkdir(session: &TerminalSession, resolver: &LayeredResolver, args: &[Arg]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::error("mkdir: missing operand\n", 1);
    }

    let mut stderr = String::new();
    let mut exit_code = 0;

    for arg in args {
        let target = match resolve_arg(session, arg.as_str()) {
            Ok(p) => p,
            Err(e) => {
                stderr.push_str(&format!("mkdir: {e}\n"));
                exit_code = 1;
                continue;
            }
        };
        let Some(name) = target.file_name() else {
            stderr.push_str("mkdir: cannot create the sandbox root\n");
            exit_code = 1;
            continue;
        };
        let parent = target.parent().unwrap_or_else(SandboxPath::root);
        if let Err(e) = resolver.mkdir(parent.as_str(), name) {
            stderr.push_str(&format!(
                "mkdir: cannot create directory '{}': {e}\n",
                arg.as_str()
            ));
            exit_code = 1;
        }
    }

    CommandResult {
        stdout: String::new(),
        stderr,
        exit_code,
    }
}

fn cmd_touch(session: &TerminalSession, resolver: &LayeredResolver, args: &[Arg]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::error("touch: missing operand\n", 1);
    }

    let mut stderr = String::new();
    let mut exit_code = 0;

    for arg in args {
        let target = match resolve_arg(session, arg.as_str()) {
            Ok(p) => p,
            Err(e) => {
                stderr.push_str(&format!("touch: {e}\n"));
                exit_code = 1;
                continue;
            }
        };
        if let Err(e) = resolver.touch(target.as_str()) {
            stderr.push_str(&format!("touch: cannot touch '{}': {e}\n", arg.as_str()));
            exit_code = 1;
        }
    }

    CommandResult {
        stdout: String::new(),
        stderr,
        exit_code,
    }
}

fn cmd_ls(session: &TerminalSession, resolver: &LayeredResolver, args: &[Arg]) -> CommandResult {
    let target = if let Some(arg) = args.first() {
        match resolve_arg(session, arg.as_str()) {
            Ok(p) => p,
            Err(e) => return CommandResult::error(format!("ls: {e}\n"), 1),
        }
    } else {
        session.cwd().clone()
    };

    match resolver.read_dir(target.as_str()) {
        Ok(names) => {
            let stdout = if names.is_empty() {
                String::new()
            } else {
                format!("{}\n", names.join("\n"))
            };
            CommandResult::ok(stdout)
        }
        Err(e) => CommandResult::error(format!("ls: cannot access '{target}': {e}\n"), 1),
    }
}

fn cmd_cat(session: &TerminalSession, resolver: &LayeredResolver, args: &[Arg]) -> CommandResult {
    if args.is_empty() {
        return CommandResult::error("cat: missing operand\n", 1);
    }

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = 0;

    for arg in args {
        let target = match resolve_arg(session, arg.as_str()) {
            Ok(p) => p,
            Err(e) => {
                stderr.push_str(&format!("cat: {e}\n"));
                exit_code = 1;
                continue;
            }
        };
        match resolver.read_file(target.as_str()) {
            // Real `cat` is byte-oriented; SafeShell's terminal output is
            // text (§17.4's `CommandResult` is `String`-typed). Lossy
            // UTF-8 conversion is a documented, deliberate simplification
            // for this command set — no handler yet needs to round-trip
            // arbitrary binary content.
            Ok(bytes) => stdout.push_str(&String::from_utf8_lossy(&bytes)),
            Err(e) => {
                stderr.push_str(&format!("cat: {}: {e}\n", arg.as_str()));
                exit_code = 1;
            }
        }
    }

    CommandResult {
        stdout,
        stderr,
        exit_code,
    }
}

/// Matches `name` against `pattern`, where `pattern` may contain any
/// number of `*` wildcards (each matching zero or more characters) and no
/// other special syntax — `?`/character classes/brace expansion are not
/// part of `parser`'s documented "basic `*` glob expansion" scope
/// (`parser::mod` module doc, §17.2).
fn glob_match(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }

    let mut rest = name;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            if !rest.starts_with(part) {
                return false;
            }
            rest = &rest[part.len()..];
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else if part.is_empty() {
            continue;
        } else {
            match rest.find(part) {
                Some(idx) => rest = &rest[idx + part.len()..],
                None => return false,
            }
        }
    }
    true
}

/// Expands a `*`-containing final path component against `parent`'s real
/// directory listing (§17.2's "basic `*` glob expansion... scoped to the
/// immediate directory" — a wildcard earlier in the path, e.g. `/tmp/*/f`,
/// is not supported, matching that documented scope). Returns `None` when
/// `name` has no `*` at all, so callers fall back to treating it as a
/// single literal target. An empty match list (nothing in `parent` fits
/// the pattern) is returned as `Some(vec![])` rather than falling back to
/// the literal pattern — real shells behave the same only under
/// `nullglob`, but silently operating on a literal `*`/`file-*.log`
/// argument is never useful for SafeShell's typed handlers, and every
/// caller here already treats "nothing to do" as success.
fn expand_glob(
    resolver: &LayeredResolver,
    parent: &SandboxPath,
    name: &str,
) -> Option<Vec<String>> {
    if !name.contains('*') {
        return None;
    }
    let entries = resolver.read_dir(parent.as_str()).unwrap_or_default();
    let mut matches: Vec<String> = entries
        .into_iter()
        .filter(|entry| glob_match(name, entry))
        .collect();
    matches.sort();
    Some(matches)
}

/// `rm [-r|-R] [-f] TARGET...`. Flag parsing deliberately mirrors
/// `policy::risk::has_short_flag`'s narrow rule (a single leading `-`
/// followed by letters — `-rf`/`-fr`/`-r`/`-f`, not `--recursive`) so the
/// same command the Policy Engine classified as HIGH/CRITICAL for
/// recursion is the same command this handler treats as recursive; a
/// mismatch between the two would mean the risk shown to the user and the
/// actual blast radius executed could disagree.
fn cmd_rm(session: &TerminalSession, resolver: &LayeredResolver, args: &[Arg]) -> CommandResult {
    let mut recursive = false;
    let mut force = false;
    let mut targets: Vec<&str> = Vec::new();

    for arg in args {
        let s = arg.as_str();
        if s.len() > 1 && s.starts_with('-') && !s.starts_with("--") {
            for c in s[1..].chars() {
                match c {
                    'r' | 'R' => recursive = true,
                    'f' => force = true,
                    _ => {}
                }
            }
        } else {
            targets.push(s);
        }
    }

    if targets.is_empty() {
        // Real `rm -f` with no operands is a silent no-op; without `-f`
        // it is a usage error.
        return if force {
            CommandResult::ok("")
        } else {
            CommandResult::error("rm: missing operand\n", 1)
        };
    }

    let mut stderr = String::new();
    let mut exit_code = 0;

    for raw in targets {
        let target = match resolve_arg(session, raw) {
            Ok(p) => p,
            Err(e) => {
                if !force {
                    stderr.push_str(&format!("rm: {e}\n"));
                    exit_code = 1;
                }
                continue;
            }
        };
        let Some(name) = target.file_name() else {
            if !force {
                stderr.push_str("rm: cannot remove the sandbox root\n");
                exit_code = 1;
            }
            continue;
        };
        let parent = target.parent().unwrap_or_else(SandboxPath::root);

        let names: Vec<String> = match expand_glob(resolver, &parent, name) {
            Some(matches) => matches,
            None => vec![name.to_string()],
        };

        for n in &names {
            if let Err(e) = resolver.remove(parent.as_str(), n, recursive) {
                if force && e.kind() == std::io::ErrorKind::NotFound {
                    continue;
                }
                stderr.push_str(&format!("rm: cannot remove '{raw}': {e}\n"));
                exit_code = 1;
            }
        }
    }

    CommandResult {
        stdout: String::new(),
        stderr,
        exit_code,
    }
}

fn cmd_echo(args: &[Arg]) -> CommandResult {
    let words: Vec<&str> = args.iter().map(Arg::as_str).collect();
    CommandResult::ok(format!("{}\n", words.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::backend::MountedView;

    fn resolver() -> (tempfile::TempDir, LayeredResolver) {
        let tmp = tempfile::tempdir().unwrap();
        let view = MountedView {
            layers: vec![tmp.path().to_path_buf()],
        };
        (tmp, LayeredResolver::from_mounted_view(&view).unwrap())
    }

    fn args(words: &[&str]) -> Vec<Arg> {
        words.iter().map(|w| Arg(w.to_string())).collect()
    }

    #[test]
    fn pwd_reports_root_initially() {
        let session = TerminalSession::new();
        let result = cmd_pwd(&session);
        assert_eq!(result, CommandResult::ok("/\n"));
    }

    #[test]
    fn mkdir_then_ls_then_cd_then_pwd() {
        let (_tmp, resolver) = resolver();
        let mut session = TerminalSession::new();

        let r = dispatch("mkdir", &args(&["project"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("ls", &[], &mut session, &resolver);
        assert_eq!(r, CommandResult::ok("project\n"));

        let r = dispatch("cd", &args(&["project"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = cmd_pwd(&session);
        assert_eq!(r, CommandResult::ok("/project\n"));
    }

    #[test]
    fn cd_into_nonexistent_directory_fails_and_does_not_move_cwd() {
        let (_tmp, resolver) = resolver();
        let mut session = TerminalSession::new();

        let r = dispatch("cd", &args(&["nowhere"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
        assert!(session.cwd().is_root());
    }

    #[test]
    fn cd_dotdot_from_root_stays_at_root() {
        let (_tmp, resolver) = resolver();
        let mut session = TerminalSession::new();

        let r = dispatch("cd", &args(&[".."]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(session.cwd().is_root());
    }

    #[test]
    fn touch_creates_empty_file_then_cat_reads_it() {
        let (_tmp, resolver) = resolver();
        let mut session = TerminalSession::new();

        let r = dispatch("touch", &args(&["a.txt"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("cat", &args(&["a.txt"]), &mut session, &resolver);
        assert_eq!(r, CommandResult::ok(""));
    }

    #[test]
    fn cat_missing_file_reports_error_and_nonzero_exit() {
        let (_tmp, resolver) = resolver();
        let mut session = TerminalSession::new();

        let r = dispatch("cat", &args(&["missing.txt"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
        assert!(r.stderr.contains("missing.txt"));
    }

    #[test]
    fn echo_joins_args_with_spaces() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("echo", &args(&["hello", "world"]), &mut session, &resolver);
        assert_eq!(r, CommandResult::ok("hello world\n"));
    }

    #[test]
    fn unknown_command_returns_exit_127() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("frobnicate", &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 127);
    }

    #[test]
    fn mkdir_missing_operand_is_an_error() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("mkdir", &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn mkdir_root_is_rejected_cleanly() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("mkdir", &args(&["/"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn rm_removes_a_file_created_earlier_in_the_same_layer() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        let r = dispatch("touch", &args(&["a.txt"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("rm", &args(&["a.txt"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("cat", &args(&["a.txt"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn rm_without_recursive_flag_refuses_a_directory() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        let r = dispatch("mkdir", &args(&["project"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("rm", &args(&["project"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
        assert!(r.stderr.contains("project"));
    }

    #[test]
    fn rm_recursive_removes_a_directory_and_its_contents() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("mkdir", &args(&["project"]), &mut session, &resolver);
        dispatch(
            "touch",
            &args(&["project/file.txt"]),
            &mut session,
            &resolver,
        );

        let r = dispatch("rm", &args(&["-r", "project"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("ls", &[], &mut session, &resolver);
        assert_eq!(r, CommandResult::ok(""));
    }

    #[test]
    fn rm_dash_rf_combined_flag_is_recognized() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("mkdir", &args(&["project"]), &mut session, &resolver);
        let r = dispatch("rm", &args(&["-rf", "project"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
    }

    #[test]
    fn rm_missing_target_is_an_error() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        let r = dispatch("rm", &args(&["missing.txt"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
        assert!(r.stderr.contains("missing.txt"));
    }

    #[test]
    fn rm_force_on_a_missing_target_is_silent_and_succeeds() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        let r = dispatch("rm", &args(&["-f", "missing.txt"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(r.stderr.is_empty());
    }

    #[test]
    fn rm_missing_operand_without_force_is_an_error() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        let r = dispatch("rm", &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn rm_then_recreating_the_same_name_succeeds_and_is_visible() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("touch", &args(&["a.txt"]), &mut session, &resolver);
        dispatch("rm", &args(&["a.txt"]), &mut session, &resolver);
        let r = dispatch("touch", &args(&["a.txt"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("cat", &args(&["a.txt"]), &mut session, &resolver);
        assert_eq!(r, CommandResult::ok(""));
    }

    #[test]
    fn rm_star_glob_removes_every_matching_file_in_the_directory() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("mkdir", &args(&["d"]), &mut session, &resolver);
        dispatch("touch", &args(&["d/a.txt"]), &mut session, &resolver);
        dispatch("touch", &args(&["d/b.txt"]), &mut session, &resolver);
        dispatch("touch", &args(&["d/keep.log"]), &mut session, &resolver);

        let r = dispatch("rm", &args(&["d/*.txt"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("ls", &args(&["d"]), &mut session, &resolver);
        assert_eq!(r, CommandResult::ok("keep.log\n"));
    }

    #[test]
    fn rm_rf_star_removes_every_entry_including_directories() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("mkdir", &args(&["d"]), &mut session, &resolver);
        dispatch("mkdir", &args(&["d/sub"]), &mut session, &resolver);
        dispatch("touch", &args(&["d/sub/f.txt"]), &mut session, &resolver);
        dispatch("touch", &args(&["d/a.txt"]), &mut session, &resolver);

        let r = dispatch("rm", &args(&["-rf", "d/*"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("ls", &args(&["d"]), &mut session, &resolver);
        assert_eq!(r, CommandResult::ok(""));
    }

    #[test]
    fn rm_star_with_no_matches_and_force_is_a_silent_no_op() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("mkdir", &args(&["d"]), &mut session, &resolver);

        let r = dispatch("rm", &args(&["-f", "d/*"]), &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(r.stderr.is_empty());
    }

    #[test]
    fn glob_match_supports_leading_trailing_and_multiple_wildcards() {
        assert!(glob_match("*.txt", "a.txt"));
        assert!(!glob_match("*.txt", "a.log"));
        assert!(glob_match("a*", "a.txt"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a*c", "abc"));
        assert!(glob_match("a*c", "ac"));
        assert!(!glob_match("a*c", "abd"));
        assert!(glob_match("file.txt", "file.txt"));
        assert!(!glob_match("file.txt", "other.txt"));
    }
}

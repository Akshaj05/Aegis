//! Pure stdin/stdout filter commands: `wc`, `sort`, `uniq`, `cut`, `head`,
//! `tail`, `date` (real uutils, spawned via [`coreutils_proc::run_filter`])
//! and `grep` (hand-written — grep is not actually part of uutils/
//! coreutils; GNU grep is a separate project, and uutils' own grep effort
//! lives in a separate, immature repository, so it's implemented here with
//! the `regex` crate instead, against bytes already read through
//! [`LayeredResolver`]).
//!
//! **Scope, deliberately bounded**: every command here that reads a file
//! (`wc`, `sort`, `uniq`, `cut`, `head`, `tail`, `grep`) requires exactly
//! one file operand, given last — real coreutils' near-universal
//! convention (`head -n 5 file.txt`, `cut -d, -f1 file.txt`) — rather than
//! supporting stdin or multiple files. There is no stdin to read from (no
//! handler pipes another handler's output into one yet — `parser`'s
//! `pipeline_next` isn't wired to `handlers::dispatch` at all, a
//! pre-existing gap, not something this pass changes), and concatenating
//! multiple files' bytes before handing them to the real uutils binary
//! would silently lose each command's real per-file semantics (`wc`'s
//! per-file line counts, `head`'s per-file `==>` headers) rather than
//! reproducing them — failing closed with a clear error on 2+ files is
//! more honest than a subtly-wrong multi-file result.

use crate::parser::Arg;
use crate::session::TerminalSession;
use crate::simulation::resolver::LayeredResolver;

use super::coreutils_proc;
use super::{resolve_arg, CommandResult};

fn split_flags_and_single_file(args: &[Arg]) -> Result<(Vec<&str>, &str), String> {
    if args.is_empty() {
        return Err("missing file operand (reading stdin is not supported)".to_string());
    }
    let last = args.last().unwrap().as_str();
    if last.starts_with('-') && last.len() > 1 {
        return Err("missing file operand (reading stdin is not supported)".to_string());
    }
    let flags: Vec<&str> = args[..args.len() - 1].iter().map(Arg::as_str).collect();
    Ok((flags, last))
}

fn run_uutils_filter_on_one_file(
    tool: &str,
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    let (flags, file_raw) = match split_flags_and_single_file(args) {
        Ok(v) => v,
        Err(e) => return CommandResult::error(format!("{tool}: {e}\n"), 1),
    };
    let target = match resolve_arg(session, file_raw) {
        Ok(p) => p,
        Err(e) => return CommandResult::error(format!("{tool}: {e}\n"), 1),
    };
    let bytes = match resolver.read_file(target.as_str()) {
        Ok(b) => b,
        Err(e) => return CommandResult::error(format!("{tool}: {file_raw}: {e}\n"), 1),
    };
    let (stdout, stderr, exit_code) = coreutils_proc::run_filter(tool, &flags, &bytes);
    CommandResult {
        stdout,
        stderr,
        exit_code,
    }
}

pub fn cmd_wc(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    run_uutils_filter_on_one_file("wc", session, resolver, args)
}

pub fn cmd_sort(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    run_uutils_filter_on_one_file("sort", session, resolver, args)
}

pub fn cmd_uniq(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    run_uutils_filter_on_one_file("uniq", session, resolver, args)
}

pub fn cmd_cut(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    run_uutils_filter_on_one_file("cut", session, resolver, args)
}

pub fn cmd_head(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    run_uutils_filter_on_one_file("head", session, resolver, args)
}

/// `tail`, with `-f`/`-F`/`--follow` refused up front: SafeShell's stdin
/// pipe to the sidecar is a finite, already-fully-written buffer, not a
/// live, growing file descriptor — `-f` has nothing meaningful to follow,
/// and letting the subprocess try would depend on GNU tail's
/// not-formally-specified-here behavior on a closed, non-seekable pipe
/// rather than a deliberate SafeShell decision. `safeshell-tail.rs`'s doc
/// comment states this same promise.
pub fn cmd_tail(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    if args
        .iter()
        .any(|a| matches!(a.as_str(), "-f" | "-F" | "--follow"))
    {
        return CommandResult::error("tail: -f/-F (follow) is not supported\n", 1);
    }
    run_uutils_filter_on_one_file("tail", session, resolver, args)
}

/// `date [FORMAT/FLAGS]` — no file operand, no stdin needed. `-s`/`--set`
/// is refused up front rather than handed to the subprocess: it would
/// attempt to change the real host system clock, entirely outside the
/// simulated environment (`safeshell-date.rs`'s doc comment states this
/// same promise).
pub fn cmd_date(args: &[Arg]) -> CommandResult {
    let flags: Vec<&str> = args.iter().map(Arg::as_str).collect();
    if flags.iter().any(|f| *f == "-s" || f.starts_with("--set")) {
        return CommandResult::error("date: setting the system clock is not supported\n", 1);
    }
    let (stdout, stderr, exit_code) = coreutils_proc::run_filter("date", &flags, b"");
    CommandResult {
        stdout,
        stderr,
        exit_code,
    }
}

/// `grep [-i] [-n] [-v] PATTERN FILE` — a documented subset of real
/// grep's flags (`policies/supported_commands.toml`'s
/// `partially_supported.divergences`): no `-r`/recursive directory search,
/// no multiple files, no reading stdin. Not sourced from uutils (see
/// module doc) — hand-written against the `regex` crate over bytes read
/// through [`LayeredResolver`].
pub fn cmd_grep(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    let mut ignore_case = false;
    let mut show_line_numbers = false;
    let mut invert = false;
    let mut operands: Vec<&str> = Vec::new();
    for arg in args {
        let s = arg.as_str();
        if s.len() > 1 && s.starts_with('-') && !s.starts_with("--") {
            for c in s[1..].chars() {
                match c {
                    'i' => ignore_case = true,
                    'n' => show_line_numbers = true,
                    'v' => invert = true,
                    _ => {}
                }
            }
        } else {
            operands.push(s);
        }
    }

    if operands.is_empty() {
        return CommandResult::error("grep: missing pattern\n", 2);
    }
    let pattern_raw = operands[0];
    if operands.len() < 2 {
        return CommandResult::error(
            "grep: missing file operand (reading stdin is not supported)\n",
            2,
        );
    }
    if operands.len() > 2 {
        return CommandResult::error("grep: only a single file target is supported\n", 2);
    }
    let file_raw = operands[1];

    let pattern = if ignore_case {
        format!("(?i){pattern_raw}")
    } else {
        pattern_raw.to_string()
    };
    let re = match regex::Regex::new(&pattern) {
        Ok(r) => r,
        Err(e) => return CommandResult::error(format!("grep: invalid pattern: {e}\n"), 2),
    };

    let target = match resolve_arg(session, file_raw) {
        Ok(p) => p,
        Err(e) => return CommandResult::error(format!("grep: {e}\n"), 2),
    };
    let bytes = match resolver.read_file(target.as_str()) {
        Ok(b) => b,
        Err(e) => return CommandResult::error(format!("grep: {file_raw}: {e}\n"), 2),
    };
    let text = String::from_utf8_lossy(&bytes);

    let mut stdout = String::new();
    let mut matched_any = false;
    for (i, line) in text.lines().enumerate() {
        if re.is_match(line) != invert {
            matched_any = true;
            if show_line_numbers {
                stdout.push_str(&format!("{}:", i + 1));
            }
            stdout.push_str(line);
            stdout.push('\n');
        }
    }

    CommandResult {
        stdout,
        stderr: String::new(),
        exit_code: if matched_any { 0 } else { 1 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::dispatch;
    use crate::parser::{Redirection, RedirectionKind};
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

    fn write_file(
        session: &mut TerminalSession,
        resolver: &LayeredResolver,
        path: &str,
        content: &str,
    ) {
        let r = dispatch(
            "echo",
            &[Arg(content.to_string())],
            &[Redirection {
                kind: RedirectionKind::Truncate,
                target: path.to_string(),
            }],
            session,
            resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
    }

    #[test]
    fn wc_counts_lines_words_bytes_of_a_real_file() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        // `write_file` goes through `echo`, which always appends its own
        // trailing newline (`handlers::mod::cmd_echo`) — content already
        // ending in `\n` therefore ends up with two lines' worth of
        // newline bytes, hence 3 lines total below.
        write_file(&mut session, &resolver, "a.txt", "one two\nthree\n");

        let r = dispatch("wc", &args(&["-l", "a.txt"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(r.stdout.trim(), "3");
    }

    #[test]
    fn sort_orders_lines_via_the_real_uutils_binary() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        write_file(&mut session, &resolver, "a.txt", "banana\napple\ncherry");

        let r = dispatch("sort", &args(&["a.txt"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(r.stdout, "apple\nbanana\ncherry\n");
    }

    #[test]
    fn uniq_collapses_adjacent_duplicate_lines() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        write_file(&mut session, &resolver, "a.txt", "a\na\nb\na");

        let r = dispatch("uniq", &args(&["a.txt"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(r.stdout, "a\nb\na\n");
    }

    #[test]
    fn cut_extracts_the_requested_field() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        write_file(&mut session, &resolver, "a.txt", "a,b,c\nd,e,f");

        let r = dispatch(
            "cut",
            &args(&["-d,", "-f2", "a.txt"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(r.stdout, "b\ne\n");
    }

    #[test]
    fn head_limits_output_to_the_requested_line_count() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        write_file(&mut session, &resolver, "a.txt", "1\n2\n3\n4\n5");

        let r = dispatch(
            "head",
            &args(&["-n", "2", "a.txt"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(r.stdout, "1\n2\n");
    }

    #[test]
    fn tail_reports_the_last_lines() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        write_file(&mut session, &resolver, "a.txt", "1\n2\n3\n4\n5");

        let r = dispatch(
            "tail",
            &args(&["-n", "2", "a.txt"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(r.stdout, "4\n5\n");
    }

    #[test]
    fn tail_follow_is_refused_up_front() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        write_file(&mut session, &resolver, "a.txt", "1\n2");

        let r = dispatch(
            "tail",
            &args(&["-f", "a.txt"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 1);
        assert!(r.stderr.contains("follow"));
    }

    #[test]
    fn date_prints_a_nonempty_line() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("date", &[], &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(!r.stdout.trim().is_empty());
    }

    #[test]
    fn date_set_is_refused_up_front() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch(
            "date",
            &args(&["-s", "2020-01-01"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn grep_finds_matching_lines() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        write_file(&mut session, &resolver, "a.txt", "apple\nbanana\navocado");

        let r = dispatch(
            "grep",
            &args(&["^a", "a.txt"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(r.stdout, "apple\navocado\n");
    }

    #[test]
    fn grep_case_insensitive_flag_matches_regardless_of_case() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        write_file(&mut session, &resolver, "a.txt", "Apple\nbanana");

        let r = dispatch(
            "grep",
            &args(&["-i", "apple", "a.txt"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(r.stdout, "Apple\n");
    }

    #[test]
    fn grep_with_no_matches_exits_nonzero() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        write_file(&mut session, &resolver, "a.txt", "banana");

        let r = dispatch(
            "grep",
            &args(&["zzz", "a.txt"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 1);
        assert_eq!(r.stdout, "");
    }

    #[test]
    fn grep_invert_flag_prints_non_matching_lines() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        write_file(&mut session, &resolver, "a.txt", "apple\nbanana\navocado");

        let r = dispatch(
            "grep",
            &args(&["-v", "^a", "a.txt"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(r.stdout, "banana\n");
    }
}

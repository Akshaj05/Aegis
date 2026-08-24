// Typed command handlers and the dispatch table that routes a parsed
// command name to its handler, applying output redirection afterward.

mod coreutils_proc;
mod fs_ext;
mod info;
mod pkg;
mod text_filters;

use crate::fs_abstraction::SandboxPath;
use crate::parser::{Arg, Redirection, RedirectionKind};
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

pub fn dispatch(
    name: &str,
    args: &[Arg],
    redirections: &[Redirection],
    session: &mut TerminalSession,
    resolver: &LayeredResolver,
) -> CommandResult {
    let mut result = dispatch_command(name, args, session, resolver);
    apply_redirections(&mut result, redirections, session, resolver);
    result
}

fn dispatch_command(
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
        "rmdir" => fs_ext::cmd_rmdir(session, resolver, args),
        "cp" => fs_ext::cmd_cp(session, resolver, args),
        "mv" => fs_ext::cmd_mv(session, resolver, args),
        "chmod" => fs_ext::cmd_chmod(session, resolver, args),
        "chown" => fs_ext::cmd_chown(session, resolver, args),
        "find" => fs_ext::cmd_find(session, resolver, args),
        "du" => fs_ext::cmd_du(session, resolver, args),
        "truncate" => fs_ext::cmd_truncate(session, resolver, args),
        "shred" => fs_ext::cmd_shred(session, resolver, args),
        "safeshell-pkg" => pkg::cmd_safeshell_pkg(session, args),
        "df" => fs_ext::cmd_df(resolver),
        "wc" => text_filters::cmd_wc(session, resolver, args),
        "sort" => text_filters::cmd_sort(session, resolver, args),
        "uniq" => text_filters::cmd_uniq(session, resolver, args),
        "cut" => text_filters::cmd_cut(session, resolver, args),
        "head" => text_filters::cmd_head(session, resolver, args),
        "tail" => text_filters::cmd_tail(session, resolver, args),
        "date" => text_filters::cmd_date(args),
        "grep" => text_filters::cmd_grep(session, resolver, args),
        "env" => info::cmd_env(session),
        "printenv" => info::cmd_printenv(session, args),
        "whoami" => info::cmd_whoami(),
        "id" => info::cmd_id(),
        "uname" => info::cmd_uname(args),
        "sleep" => info::cmd_sleep(args),
        _ => CommandResult::error(format!("{name}: command not found"), 127),
    }
}

fn apply_redirections(
    result: &mut CommandResult,
    redirections: &[Redirection],
    session: &TerminalSession,
    resolver: &LayeredResolver,
) {
    for redir in redirections {
        match redir.kind {
            RedirectionKind::Input => {
                *result = CommandResult::error(
                    "SafeShell does not support input (`<`) redirection: no handler reads stdin\n",
                    1,
                );
                return;
            }
            RedirectionKind::Truncate | RedirectionKind::Append => {
                let target = match resolve_arg(session, &redir.target) {
                    Ok(p) => p,
                    Err(e) => {
                        *result = CommandResult::error(format!("{e}\n"), 1);
                        return;
                    }
                };
                let mut contents = if redir.kind == RedirectionKind::Append {
                    resolver.read_file(target.as_str()).unwrap_or_default()
                } else {
                    Vec::new()
                };
                contents.extend_from_slice(result.stdout.as_bytes());
                if let Err(e) = resolver.write_file(target.as_str(), &contents) {
                    *result = CommandResult::error(format!("{}: {e}\n", redir.target), 1);
                    return;
                }
                result.stdout.clear();
            }
        }
    }
}

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
        None => "/",
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

        let r = dispatch("mkdir", &args(&["project"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("ls", &[], &[], &mut session, &resolver);
        assert_eq!(r, CommandResult::ok("project\n"));

        let r = dispatch("cd", &args(&["project"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = cmd_pwd(&session);
        assert_eq!(r, CommandResult::ok("/project\n"));
    }

    #[test]
    fn cd_into_nonexistent_directory_fails_and_does_not_move_cwd() {
        let (_tmp, resolver) = resolver();
        let mut session = TerminalSession::new();

        let r = dispatch("cd", &args(&["nowhere"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
        assert!(session.cwd().is_root());
    }

    #[test]
    fn cd_dotdot_from_root_stays_at_root() {
        let (_tmp, resolver) = resolver();
        let mut session = TerminalSession::new();

        let r = dispatch("cd", &args(&[".."]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(session.cwd().is_root());
    }

    #[test]
    fn touch_creates_empty_file_then_cat_reads_it() {
        let (_tmp, resolver) = resolver();
        let mut session = TerminalSession::new();

        let r = dispatch("touch", &args(&["a.txt"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("cat", &args(&["a.txt"]), &[], &mut session, &resolver);
        assert_eq!(r, CommandResult::ok(""));
    }

    #[test]
    fn cat_missing_file_reports_error_and_nonzero_exit() {
        let (_tmp, resolver) = resolver();
        let mut session = TerminalSession::new();

        let r = dispatch("cat", &args(&["missing.txt"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
        assert!(r.stderr.contains("missing.txt"));
    }

    #[test]
    fn echo_joins_args_with_spaces() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch(
            "echo",
            &args(&["hello", "world"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r, CommandResult::ok("hello world\n"));
    }

    #[test]
    fn unknown_command_returns_exit_127() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("frobnicate", &[], &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 127);
    }

    #[test]
    fn mkdir_missing_operand_is_an_error() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("mkdir", &[], &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn mkdir_root_is_rejected_cleanly() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("mkdir", &args(&["/"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn rm_removes_a_file_created_earlier_in_the_same_layer() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        let r = dispatch("touch", &args(&["a.txt"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("rm", &args(&["a.txt"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("cat", &args(&["a.txt"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn rm_without_recursive_flag_refuses_a_directory() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        let r = dispatch("mkdir", &args(&["project"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("rm", &args(&["project"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
        assert!(r.stderr.contains("project"));
    }

    #[test]
    fn rm_recursive_removes_a_directory_and_its_contents() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("mkdir", &args(&["project"]), &[], &mut session, &resolver);
        dispatch(
            "touch",
            &args(&["project/file.txt"]),
            &[],
            &mut session,
            &resolver,
        );

        let r = dispatch(
            "rm",
            &args(&["-r", "project"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("ls", &[], &[], &mut session, &resolver);
        assert_eq!(r, CommandResult::ok(""));
    }

    #[test]
    fn rm_dash_rf_combined_flag_is_recognized() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("mkdir", &args(&["project"]), &[], &mut session, &resolver);
        let r = dispatch(
            "rm",
            &args(&["-rf", "project"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
    }

    #[test]
    fn rm_missing_target_is_an_error() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        let r = dispatch("rm", &args(&["missing.txt"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
        assert!(r.stderr.contains("missing.txt"));
    }

    #[test]
    fn rm_force_on_a_missing_target_is_silent_and_succeeds() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        let r = dispatch(
            "rm",
            &args(&["-f", "missing.txt"]),
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(r.stderr.is_empty());
    }

    #[test]
    fn rm_missing_operand_without_force_is_an_error() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        let r = dispatch("rm", &[], &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn rm_then_recreating_the_same_name_succeeds_and_is_visible() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("touch", &args(&["a.txt"]), &[], &mut session, &resolver);
        dispatch("rm", &args(&["a.txt"]), &[], &mut session, &resolver);
        let r = dispatch("touch", &args(&["a.txt"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("cat", &args(&["a.txt"]), &[], &mut session, &resolver);
        assert_eq!(r, CommandResult::ok(""));
    }

    #[test]
    fn rm_star_glob_removes_every_matching_file_in_the_directory() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("mkdir", &args(&["d"]), &[], &mut session, &resolver);
        dispatch("touch", &args(&["d/a.txt"]), &[], &mut session, &resolver);
        dispatch("touch", &args(&["d/b.txt"]), &[], &mut session, &resolver);
        dispatch(
            "touch",
            &args(&["d/keep.log"]),
            &[],
            &mut session,
            &resolver,
        );

        let r = dispatch("rm", &args(&["d/*.txt"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("ls", &args(&["d"]), &[], &mut session, &resolver);
        assert_eq!(r, CommandResult::ok("keep.log\n"));
    }

    #[test]
    fn rm_rf_star_removes_every_entry_including_directories() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("mkdir", &args(&["d"]), &[], &mut session, &resolver);
        dispatch("mkdir", &args(&["d/sub"]), &[], &mut session, &resolver);
        dispatch(
            "touch",
            &args(&["d/sub/f.txt"]),
            &[],
            &mut session,
            &resolver,
        );
        dispatch("touch", &args(&["d/a.txt"]), &[], &mut session, &resolver);

        let r = dispatch("rm", &args(&["-rf", "d/*"]), &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        let r = dispatch("ls", &args(&["d"]), &[], &mut session, &resolver);
        assert_eq!(r, CommandResult::ok(""));
    }

    #[test]
    fn rm_star_with_no_matches_and_force_is_a_silent_no_op() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();

        dispatch("mkdir", &args(&["d"]), &[], &mut session, &resolver);

        let r = dispatch("rm", &args(&["-f", "d/*"]), &[], &mut session, &resolver);
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

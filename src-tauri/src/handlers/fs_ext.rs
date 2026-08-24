//! Filesystem-structural commands (`rmdir`, `cp`, `mv`, `chmod`, `chown`,
//! `find`, `du`, `df`) that need real path traversal/mutation rather than
//! pure byte transformation.
//!
//! These **cannot** be delegated to uutils' own `uu_cp`/`uu_mv`/etc. crates
//! — those call `std::fs`/libc directly against real OS paths, with no way
//! to redirect that through [`LayeredResolver`]'s `openat2`+
//! `RESOLVE_BENEATH` containment or its layered/whiteout read-through-stack
//! model (see `handlers/mod.rs`'s module doc for the fuller argument).
//! Every path-touching operation here goes through `LayeredResolver`
//! exclusively, same as the handlers in `mod.rs` — this module just adds
//! more of them, following the same pattern (`cmd_rm` for deletion,
//! `cmd_mkdir`/`cmd_touch` for the copy-up-aware creation logic that
//! [`copy_into`] and `chmod`/`chown`'s "ensure a real top-layer copy first"
//! step both build on).

use std::io;

use crate::fs_abstraction::SandboxPath;
use crate::parser::Arg;
use crate::sandbox::worker::protocol::FileKind;
use crate::session::TerminalSession;
use crate::simulation::resolver::LayeredResolver;

use super::{glob_match, resolve_arg, CommandResult};

fn short_flags(args: &[Arg]) -> (Vec<char>, Vec<&str>) {
    let mut flags = Vec::new();
    let mut operands = Vec::new();
    for arg in args {
        let s = arg.as_str();
        if s.len() > 1 && s.starts_with('-') && !s.starts_with("--") {
            flags.extend(s[1..].chars());
        } else {
            operands.push(s);
        }
    }
    (flags, operands)
}

/// `rmdir DIR...`: refuses a non-empty directory (real `rmdir`'s
/// `ENOTEMPTY`), checked explicitly here rather than relying on
/// `LayeredResolver::remove`'s own recursion (which would happily remove
/// non-empty content — that's what `-r` is for, and `rmdir` never takes
/// one).
pub fn cmd_rmdir(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    if args.is_empty() {
        return CommandResult::error("rmdir: missing operand\n", 1);
    }
    let mut stderr = String::new();
    let mut exit_code = 0;

    for arg in args {
        let raw = arg.as_str();
        let target = match resolve_arg(session, raw) {
            Ok(p) => p,
            Err(e) => {
                stderr.push_str(&format!("rmdir: {e}\n"));
                exit_code = 1;
                continue;
            }
        };
        let Some(name) = target.file_name() else {
            stderr.push_str("rmdir: cannot remove the sandbox root\n");
            exit_code = 1;
            continue;
        };
        let parent = target.parent().unwrap_or_else(SandboxPath::root);

        match resolver.stat(target.as_str()) {
            Ok(info) if info.kind != FileKind::Directory => {
                stderr.push_str(&format!(
                    "rmdir: failed to remove '{raw}': Not a directory\n"
                ));
                exit_code = 1;
                continue;
            }
            Err(e) => {
                stderr.push_str(&format!("rmdir: failed to remove '{raw}': {e}\n"));
                exit_code = 1;
                continue;
            }
            Ok(_) => {}
        }
        match resolver.read_dir(target.as_str()) {
            Ok(entries) if !entries.is_empty() => {
                stderr.push_str(&format!(
                    "rmdir: failed to remove '{raw}': Directory not empty\n"
                ));
                exit_code = 1;
                continue;
            }
            Err(e) => {
                stderr.push_str(&format!("rmdir: failed to remove '{raw}': {e}\n"));
                exit_code = 1;
                continue;
            }
            Ok(_) => {}
        }
        // Already proven empty above; `remove`'s own directory check just
        // needs `recursive = true` to be allowed to touch a directory at
        // all (§ handlers/mod.rs's `cmd_rm` doc — same gate, no actual
        // recursion happens against an empty directory).
        if let Err(e) = resolver.remove(parent.as_str(), name, true) {
            stderr.push_str(&format!("rmdir: failed to remove '{raw}': {e}\n"));
            exit_code = 1;
        }
    }

    CommandResult {
        stdout: String::new(),
        stderr,
        exit_code,
    }
}

fn copy_into(
    resolver: &LayeredResolver,
    src: &SandboxPath,
    dest: &SandboxPath,
    recursive: bool,
) -> io::Result<()> {
    let info = resolver.stat(src.as_str())?;
    if info.kind == FileKind::Directory {
        if !recursive {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "omitting directory (not -r)",
            ));
        }
        let already_dir = resolver
            .stat(dest.as_str())
            .map(|i| i.kind == FileKind::Directory)
            .unwrap_or(false);
        if !already_dir {
            let Some(name) = dest.file_name() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot copy onto the sandbox root",
                ));
            };
            let parent = dest.parent().unwrap_or_else(SandboxPath::root);
            resolver.mkdir(parent.as_str(), name)?;
        }
        for entry in resolver.read_dir(src.as_str())? {
            let child_src = src
                .join(&entry)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let child_dest = dest
                .join(&entry)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            copy_into(resolver, &child_src, &child_dest, recursive)?;
        }
        Ok(())
    } else {
        let contents = resolver.read_file(src.as_str())?;
        resolver.write_file(dest.as_str(), &contents)
    }
}

/// Resolves the usual `cmd SRC... DEST` shape shared by `cp`/`mv`: the last
/// operand is the destination; if more than one source is given, the
/// destination must already be a directory (real `cp`/`mv`'s
/// `ENOTDIR`-shaped usage error otherwise).
fn resolve_sources_and_dest<'a>(
    session: &TerminalSession,
    operands: &[&'a str],
) -> Result<(Vec<&'a str>, SandboxPath, bool), String> {
    if operands.len() < 2 {
        return Err("missing file operand".to_string());
    }
    let dest_raw = operands[operands.len() - 1];
    let sources = operands[..operands.len() - 1].to_vec();
    let dest = resolve_arg(session, dest_raw)?;
    let multi = sources.len() > 1;
    Ok((sources, dest, multi))
}

/// `cp [-r|-R] SRC... DEST`.
pub fn cmd_cp(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    let (flags, operands) = short_flags(args);
    let recursive = flags.iter().any(|&c| c == 'r' || c == 'R');

    let (sources, dest, multi) = match resolve_sources_and_dest(session, &operands) {
        Ok(v) => v,
        Err(e) => return CommandResult::error(format!("cp: {e}\n"), 1),
    };
    let dest_is_dir = resolver
        .stat(dest.as_str())
        .map(|i| i.kind == FileKind::Directory)
        .unwrap_or(false);
    if multi && !dest_is_dir {
        return CommandResult::error(
            format!("cp: target '{}' is not a directory\n", dest.as_str()),
            1,
        );
    }

    let mut stderr = String::new();
    let mut exit_code = 0;
    for src_raw in sources {
        let src = match resolve_arg(session, src_raw) {
            Ok(p) => p,
            Err(e) => {
                stderr.push_str(&format!("cp: {e}\n"));
                exit_code = 1;
                continue;
            }
        };
        let final_dest = if dest_is_dir {
            let Some(name) = src.file_name() else {
                stderr.push_str("cp: cannot copy the sandbox root\n");
                exit_code = 1;
                continue;
            };
            match dest.join(name) {
                Ok(p) => p,
                Err(e) => {
                    stderr.push_str(&format!("cp: {e}\n"));
                    exit_code = 1;
                    continue;
                }
            }
        } else {
            dest.clone()
        };
        if let Err(e) = copy_into(resolver, &src, &final_dest, recursive) {
            stderr.push_str(&format!(
                "cp: cannot copy '{src_raw}' to '{}': {e}\n",
                final_dest.as_str()
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

/// `mv SRC... DEST`, implemented as copy-then-remove against the *same*
/// `LayeredResolver` primitives `cp`/`rm` already use, rather than a new
/// cross-layer rename primitive — real `mv`'s atomic-rename fast path is a
/// same-filesystem optimization with no observable difference here (only
/// the final layered/verified state matters to SafeShell's diff/
/// verification machinery, never the syscall sequence that produced it).
/// Always copies recursively when the source is a directory — unlike
/// `cp`, `mv` has no `-r` flag; moving a directory is always allowed.
pub fn cmd_mv(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    let operands: Vec<&str> = args.iter().map(Arg::as_str).collect();
    let (sources, dest, multi) = match resolve_sources_and_dest(session, &operands) {
        Ok(v) => v,
        Err(e) => return CommandResult::error(format!("mv: {e}\n"), 1),
    };
    let dest_is_dir = resolver
        .stat(dest.as_str())
        .map(|i| i.kind == FileKind::Directory)
        .unwrap_or(false);
    if multi && !dest_is_dir {
        return CommandResult::error(
            format!("mv: target '{}' is not a directory\n", dest.as_str()),
            1,
        );
    }

    let mut stderr = String::new();
    let mut exit_code = 0;
    for src_raw in sources {
        let src = match resolve_arg(session, src_raw) {
            Ok(p) => p,
            Err(e) => {
                stderr.push_str(&format!("mv: {e}\n"));
                exit_code = 1;
                continue;
            }
        };
        let final_dest = if dest_is_dir {
            let Some(name) = src.file_name() else {
                stderr.push_str("mv: cannot move the sandbox root\n");
                exit_code = 1;
                continue;
            };
            match dest.join(name) {
                Ok(p) => p,
                Err(e) => {
                    stderr.push_str(&format!("mv: {e}\n"));
                    exit_code = 1;
                    continue;
                }
            }
        } else {
            dest.clone()
        };

        let result = (|| -> io::Result<()> {
            let info = resolver.stat(src.as_str())?;
            copy_into(resolver, &src, &final_dest, true)?;
            let Some(name) = src.file_name() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot move the sandbox root",
                ));
            };
            let parent = src.parent().unwrap_or_else(SandboxPath::root);
            resolver.remove(parent.as_str(), name, info.kind == FileKind::Directory)
        })();
        if let Err(e) = result {
            stderr.push_str(&format!(
                "mv: cannot move '{src_raw}' to '{}': {e}\n",
                final_dest.as_str()
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

/// `chmod MODE FILE...` — octal modes only (e.g. `755`, `644`); real
/// `chmod`'s symbolic form (`u+x`, `go-w`, ...) is not implemented (a
/// documented divergence, not a security gap). `-R` recurses into
/// directories.
pub fn cmd_chmod(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    let (flags, operands) = short_flags(args);
    let recursive = flags.contains(&'R');

    if operands.len() < 2 {
        return CommandResult::error("chmod: missing operand\n", 1);
    }
    let mode_str = operands[0];
    let Ok(mode) = u32::from_str_radix(mode_str, 8) else {
        return CommandResult::error(
            format!(
                "chmod: invalid mode: '{mode_str}' (only octal modes like 755 are supported)\n"
            ),
            1,
        );
    };

    let mut stderr = String::new();
    let mut exit_code = 0;
    for raw in &operands[1..] {
        let target = match resolve_arg(session, raw) {
            Ok(p) => p,
            Err(e) => {
                stderr.push_str(&format!("chmod: {e}\n"));
                exit_code = 1;
                continue;
            }
        };
        if let Err(e) = chmod_recursive(resolver, &target, mode, recursive) {
            stderr.push_str(&format!("chmod: changing permissions of '{raw}': {e}\n"));
            exit_code = 1;
        }
    }

    CommandResult {
        stdout: String::new(),
        stderr,
        exit_code,
    }
}

fn chmod_recursive(
    resolver: &LayeredResolver,
    target: &SandboxPath,
    mode: u32,
    recursive: bool,
) -> io::Result<()> {
    let info = resolver.stat(target.as_str())?;
    resolver.chmod(target.as_str(), mode)?;
    if recursive && info.kind == FileKind::Directory {
        for entry in resolver.read_dir(target.as_str())? {
            let child = target
                .join(&entry)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            chmod_recursive(resolver, &child, mode, recursive)?;
        }
    }
    Ok(())
}

/// `chown OWNER[:GROUP] FILE...` — numeric UID[:GID] only; SafeShell has no
/// simulated user/group database to resolve a symbolic name against (a
/// documented divergence). A rootless process can only ever `chown` to its
/// own uid — attempting any other target surfaces the real `EPERM`, not a
/// SafeShell-specific restriction. `-R` recurses into directories.
pub fn cmd_chown(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    let (flags, operands) = short_flags(args);
    let recursive = flags.contains(&'R');

    if operands.len() < 2 {
        return CommandResult::error("chown: missing operand\n", 1);
    }
    let spec = operands[0];
    let (uid_str, gid_str) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let uid = if uid_str.is_empty() {
        None
    } else {
        match uid_str.parse::<u32>() {
            Ok(v) => Some(v),
            Err(_) => {
                return CommandResult::error(
                    format!(
                        "chown: invalid user: '{spec}' (only numeric uid[:gid] is supported)\n"
                    ),
                    1,
                )
            }
        }
    };
    let gid = match gid_str {
        None | Some("") => None,
        Some(g) => match g.parse::<u32>() {
            Ok(v) => Some(v),
            Err(_) => {
                return CommandResult::error(
                    format!(
                        "chown: invalid group: '{spec}' (only numeric uid[:gid] is supported)\n"
                    ),
                    1,
                )
            }
        },
    };

    let mut stderr = String::new();
    let mut exit_code = 0;
    for raw in &operands[1..] {
        let target = match resolve_arg(session, raw) {
            Ok(p) => p,
            Err(e) => {
                stderr.push_str(&format!("chown: {e}\n"));
                exit_code = 1;
                continue;
            }
        };
        if let Err(e) = chown_recursive(resolver, &target, uid, gid, recursive) {
            stderr.push_str(&format!("chown: changing ownership of '{raw}': {e}\n"));
            exit_code = 1;
        }
    }

    CommandResult {
        stdout: String::new(),
        stderr,
        exit_code,
    }
}

fn chown_recursive(
    resolver: &LayeredResolver,
    target: &SandboxPath,
    uid: Option<u32>,
    gid: Option<u32>,
    recursive: bool,
) -> io::Result<()> {
    let info = resolver.stat(target.as_str())?;
    resolver.chown(target.as_str(), uid, gid)?;
    if recursive && info.kind == FileKind::Directory {
        for entry in resolver.read_dir(target.as_str())? {
            let child = target
                .join(&entry)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            chown_recursive(resolver, &child, uid, gid, recursive)?;
        }
    }
    Ok(())
}

/// `find [PATH] [-name PATTERN] [-type f|d]` — a deliberate subset of real
/// `find`'s predicate language (documented in
/// `policies/supported_commands.toml`'s `partially_supported.divergences`).
/// `PATTERN` uses the same `*`-only glob syntax as `rm`'s (see
/// `handlers/mod.rs::glob_match`).
pub fn cmd_find(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    let items: Vec<&str> = args.iter().map(Arg::as_str).collect();
    let mut path_raw = ".";
    let mut name_pattern: Option<&str> = None;
    let mut type_filter: Option<char> = None;
    let mut path_taken = false;

    let mut i = 0;
    while i < items.len() {
        match items[i] {
            "-name" => {
                i += 1;
                if i < items.len() {
                    name_pattern = Some(items[i]);
                }
            }
            "-type" => {
                i += 1;
                if i < items.len() {
                    type_filter = items[i].chars().next();
                }
            }
            other if !path_taken && !other.starts_with('-') => {
                path_raw = other;
                path_taken = true;
            }
            _ => {}
        }
        i += 1;
    }

    let start = match resolve_arg(session, path_raw) {
        Ok(p) => p,
        Err(e) => return CommandResult::error(format!("find: {e}\n"), 1),
    };
    let mut results = Vec::new();
    if let Err(e) = find_walk(resolver, &start, name_pattern, type_filter, &mut results) {
        return CommandResult::error(format!("find: '{path_raw}': {e}\n"), 1);
    }
    results.sort();
    CommandResult::ok(if results.is_empty() {
        String::new()
    } else {
        format!("{}\n", results.join("\n"))
    })
}

fn find_walk(
    resolver: &LayeredResolver,
    path: &SandboxPath,
    name_pattern: Option<&str>,
    type_filter: Option<char>,
    out: &mut Vec<String>,
) -> io::Result<()> {
    let info = resolver.stat(path.as_str())?;
    let leaf = path.file_name().unwrap_or("/");
    let matches_name = name_pattern.map(|p| glob_match(p, leaf)).unwrap_or(true);
    let matches_type = type_filter
        .map(|t| match t {
            'f' => info.kind == FileKind::Regular,
            'd' => info.kind == FileKind::Directory,
            _ => true,
        })
        .unwrap_or(true);
    if matches_name && matches_type {
        out.push(path.as_str().to_string());
    }
    if info.kind == FileKind::Directory {
        for entry in resolver.read_dir(path.as_str())? {
            let child = path
                .join(&entry)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            find_walk(resolver, &child, name_pattern, type_filter, out)?;
        }
    }
    Ok(())
}

fn du_walk(resolver: &LayeredResolver, path: &SandboxPath) -> io::Result<u64> {
    let info = resolver.stat(path.as_str())?;
    if info.kind != FileKind::Directory {
        return Ok(info.len);
    }
    let mut total = 0u64;
    for entry in resolver.read_dir(path.as_str())? {
        let child = path
            .join(&entry)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        total += du_walk(resolver, &child)?;
    }
    Ok(total)
}

/// `du [-s] PATH...` — always reports a single recursive total per target
/// (i.e. always behaves as if `-s` were given); real `du`'s default
/// per-subdirectory breakdown is not implemented (documented divergence,
/// not a security gap — the aggregate byte count is exact either way).
pub fn cmd_du(
    session: &TerminalSession,
    resolver: &LayeredResolver,
    args: &[Arg],
) -> CommandResult {
    let (_flags, operands) = short_flags(args);
    let targets: Vec<&str> = if operands.is_empty() {
        vec!["."]
    } else {
        operands
    };

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = 0;
    for raw in targets {
        let target = match resolve_arg(session, raw) {
            Ok(p) => p,
            Err(e) => {
                stderr.push_str(&format!("du: {e}\n"));
                exit_code = 1;
                continue;
            }
        };
        match du_walk(resolver, &target) {
            Ok(total) => stdout.push_str(&format!("{total}\t{raw}\n")),
            Err(e) => {
                stderr.push_str(&format!("du: cannot access '{raw}': {e}\n"));
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

/// `df` — SafeShell has no real mounted filesystem/device backing the
/// simulated tree to report block-device statistics for (the copy-up
/// backend is plain host directories; even OverlayFS mode has no
/// meaningful separate capacity of its own). Rather than fabricate a
/// capacity/available number SafeShell doesn't actually know (§25:
/// "never claim... perfect simulation"), this reports only the one real,
/// derivable number — total bytes used across the whole simulated tree —
/// against a single synthetic `safeshell-sim` entry, with capacity/
/// available/use% explicitly marked unknown (`-`) rather than invented.
pub fn cmd_df(resolver: &LayeredResolver) -> CommandResult {
    let used = du_walk(resolver, &SandboxPath::root()).unwrap_or(0);
    let stdout = format!(
        "Filesystem       1K-blocks  Used  Available  Use%  Mounted on\n\
         safeshell-sim            -  {used}          -     -  /\n"
    );
    CommandResult::ok(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::dispatch;
    use crate::parser::Arg as ParserArg;
    use crate::snapshot::backend::MountedView;

    fn resolver() -> (tempfile::TempDir, LayeredResolver) {
        let tmp = tempfile::tempdir().unwrap();
        let view = MountedView {
            layers: vec![tmp.path().to_path_buf()],
        };
        (tmp, LayeredResolver::from_mounted_view(&view).unwrap())
    }

    fn args(words: &[&str]) -> Vec<ParserArg> {
        words.iter().map(|w| ParserArg(w.to_string())).collect()
    }

    fn run(
        name: &str,
        a: &[&str],
        session: &mut TerminalSession,
        resolver: &LayeredResolver,
    ) -> CommandResult {
        dispatch(name, &args(a), &[], session, resolver)
    }

    #[test]
    fn rmdir_removes_an_empty_directory() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("mkdir", &["d"], &mut session, &resolver);
        let r = run("rmdir", &["d"], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(
            run("ls", &[], &mut session, &resolver),
            CommandResult::ok("")
        );
    }

    #[test]
    fn rmdir_refuses_a_non_empty_directory() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("mkdir", &["d"], &mut session, &resolver);
        run("touch", &["d/f.txt"], &mut session, &resolver);
        let r = run("rmdir", &["d"], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
        assert!(r.stderr.contains("not empty"));
    }

    #[test]
    fn cp_copies_a_file_with_content() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("mkdir", &["d"], &mut session, &resolver);
        let echo = dispatch(
            "echo",
            &args(&["hello"]),
            &[crate::parser::Redirection {
                kind: crate::parser::RedirectionKind::Truncate,
                target: "d/a.txt".to_string(),
            }],
            &mut session,
            &resolver,
        );
        assert_eq!(echo.exit_code, 0, "stderr: {}", echo.stderr);

        let r = run("cp", &["d/a.txt", "d/b.txt"], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(
            run("cat", &["d/b.txt"], &mut session, &resolver),
            CommandResult::ok("hello\n")
        );
        // original still exists — cp, not mv
        assert_eq!(
            run("cat", &["d/a.txt"], &mut session, &resolver),
            CommandResult::ok("hello\n")
        );
    }

    #[test]
    fn cp_recursive_copies_a_directory_tree() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("mkdir", &["src"], &mut session, &resolver);
        run("mkdir", &["src/sub"], &mut session, &resolver);
        run("touch", &["src/sub/f.txt"], &mut session, &resolver);

        let r = run("cp", &["-r", "src", "dest"], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(
            run("ls", &["dest/sub"], &mut session, &resolver),
            CommandResult::ok("f.txt\n")
        );
    }

    #[test]
    fn cp_without_recursive_refuses_a_directory() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("mkdir", &["src"], &mut session, &resolver);
        let r = run("cp", &["src", "dest"], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn mv_moves_a_file_and_removes_the_source() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("touch", &["a.txt"], &mut session, &resolver);

        let r = run("mv", &["a.txt", "b.txt"], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(run("cat", &["a.txt"], &mut session, &resolver).exit_code, 1);
        assert_eq!(
            run("cat", &["b.txt"], &mut session, &resolver),
            CommandResult::ok("")
        );
    }

    #[test]
    fn mv_moves_a_directory_tree() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("mkdir", &["src"], &mut session, &resolver);
        run("touch", &["src/f.txt"], &mut session, &resolver);

        let r = run("mv", &["src", "dest"], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(
            run("ls", &["dest"], &mut session, &resolver),
            CommandResult::ok("f.txt\n")
        );
        assert_eq!(run("ls", &["src"], &mut session, &resolver).exit_code, 1);
    }

    #[test]
    fn chmod_changes_the_real_mode_bits() {
        let mut session = TerminalSession::new();
        let (tmp, resolver) = resolver();
        run("touch", &["a.txt"], &mut session, &resolver);

        let r = run("chmod", &["600", "a.txt"], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(tmp.path().join("a.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn chmod_recursive_applies_to_directory_contents() {
        let mut session = TerminalSession::new();
        let (tmp, resolver) = resolver();
        run("mkdir", &["d"], &mut session, &resolver);
        run("touch", &["d/f.txt"], &mut session, &resolver);

        let r = run("chmod", &["-R", "700", "d"], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(tmp.path().join("d/f.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn chmod_rejects_a_non_octal_mode() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("touch", &["a.txt"], &mut session, &resolver);
        let r = run("chmod", &["u+x", "a.txt"], &mut session, &resolver);
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn chown_to_the_current_uid_succeeds() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("touch", &["a.txt"], &mut session, &resolver);
        let uid = nix::unistd::getuid().as_raw();
        let r = run(
            "chown",
            &[&uid.to_string(), "a.txt"],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
    }

    #[test]
    fn chown_to_a_different_uid_fails_rootless_with_eperm() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("touch", &["a.txt"], &mut session, &resolver);
        if nix::unistd::getuid().is_root() {
            // Root can chown to anyone; this test only proves rootless EPERM.
            return;
        }
        let other_uid = nix::unistd::getuid().as_raw() + 1;
        let r = run(
            "chown",
            &[&other_uid.to_string(), "a.txt"],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn find_matches_by_name_pattern_recursively() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("mkdir", &["d"], &mut session, &resolver);
        run("mkdir", &["d/sub"], &mut session, &resolver);
        run("touch", &["d/a.txt"], &mut session, &resolver);
        run("touch", &["d/sub/b.txt"], &mut session, &resolver);
        run("touch", &["d/keep.log"], &mut session, &resolver);

        let r = run("find", &["d", "-name", "*.txt"], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(r.stdout.contains("d/a.txt"));
        assert!(r.stdout.contains("d/sub/b.txt"));
        assert!(!r.stdout.contains("keep.log"));
    }

    #[test]
    fn du_reports_the_recursive_byte_total() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        run("mkdir", &["d"], &mut session, &resolver);
        dispatch(
            "echo",
            &args(&["hello"]),
            &[crate::parser::Redirection {
                kind: crate::parser::RedirectionKind::Truncate,
                target: "d/a.txt".to_string(),
            }],
            &mut session,
            &resolver,
        );

        let r = run("du", &["d"], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(r.stdout.contains('6')); // "hello\n" is 6 bytes
    }

    #[test]
    fn df_reports_a_synthetic_entry_without_fabricating_capacity() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = run("df", &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(r.stdout.contains("safeshell-sim"));
    }
}

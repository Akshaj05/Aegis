// Pure informational command handlers: env, printenv, whoami, id, uname,
// and sleep.

use std::collections::BTreeMap;

use crate::parser::Arg;
use crate::session::TerminalSession;

use super::CommandResult;

pub fn cmd_env(session: &TerminalSession) -> CommandResult {
    let sorted: BTreeMap<&String, &String> = session.env().iter().collect();
    let stdout: String = sorted
        .into_iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect();
    CommandResult::ok(stdout)
}

pub fn cmd_printenv(session: &TerminalSession, args: &[Arg]) -> CommandResult {
    if args.is_empty() {
        return cmd_env(session);
    }
    let mut stdout = String::new();
    let mut exit_code = 0;
    for arg in args {
        match session.env().get(arg.as_str()) {
            Some(v) => stdout.push_str(&format!("{v}\n")),
            None => exit_code = 1,
        }
    }
    CommandResult {
        stdout,
        stderr: String::new(),
        exit_code,
    }
}

pub fn cmd_whoami() -> CommandResult {
    let uid = nix::unistd::getuid();
    let name = nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string());
    CommandResult::ok(format!("{name}\n"))
}

pub fn cmd_id() -> CommandResult {
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();
    let uname = nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string());
    let gname = nix::unistd::Group::from_gid(gid)
        .ok()
        .flatten()
        .map(|g| g.name)
        .unwrap_or_else(|| gid.to_string());
    CommandResult::ok(format!(
        "uid={}({uname}) gid={}({gname})\n",
        uid.as_raw(),
        gid.as_raw()
    ))
}

pub fn cmd_uname(args: &[Arg]) -> CommandResult {
    let info = match nix::sys::utsname::uname() {
        Ok(i) => i,
        Err(e) => return CommandResult::error(format!("uname: {e}\n"), 1),
    };
    let sysname = info.sysname().to_string_lossy();
    let nodename = info.nodename().to_string_lossy();
    let release = info.release().to_string_lossy();
    let machine = info.machine().to_string_lossy();

    let flags: Vec<&str> = args.iter().map(Arg::as_str).collect();
    let stdout = if flags.contains(&"-a") {
        format!("{sysname} {nodename} {release} {machine}\n")
    } else if flags.contains(&"-s") || flags.is_empty() {
        format!("{sysname}\n")
    } else if flags.contains(&"-n") {
        format!("{nodename}\n")
    } else if flags.contains(&"-r") {
        format!("{release}\n")
    } else if flags.contains(&"-m") {
        format!("{machine}\n")
    } else {
        format!("{sysname}\n")
    };
    CommandResult::ok(stdout)
}

pub fn cmd_sleep(args: &[Arg]) -> CommandResult {
    let Some(arg) = args.first() else {
        return CommandResult::error("sleep: missing operand\n", 1);
    };
    let Ok(secs) = arg.as_str().parse::<f64>() else {
        return CommandResult::error(
            format!("sleep: invalid time interval '{}'\n", arg.as_str()),
            1,
        );
    };
    if secs.is_sign_negative() || !secs.is_finite() {
        return CommandResult::error(
            format!("sleep: invalid time interval '{}'\n", arg.as_str()),
            1,
        );
    }
    std::thread::sleep(std::time::Duration::from_secs_f64(secs));
    CommandResult::ok("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::dispatch;
    use crate::simulation::resolver::LayeredResolver;
    use crate::snapshot::backend::MountedView;

    fn resolver() -> (tempfile::TempDir, LayeredResolver) {
        let tmp = tempfile::tempdir().unwrap();
        let view = MountedView {
            layers: vec![tmp.path().to_path_buf()],
        };
        (tmp, LayeredResolver::from_mounted_view(&view).unwrap())
    }

    #[test]
    fn env_lists_the_session_environment_sorted() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("env", &[], &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(r.stdout.contains("HOME="));
    }

    #[test]
    fn printenv_with_a_name_prints_just_that_value() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let home = session.env().get("HOME").cloned().unwrap_or_default();
        let r = dispatch(
            "printenv",
            &[Arg("HOME".to_string())],
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r, CommandResult::ok(format!("{home}\n")));
    }

    #[test]
    fn printenv_with_an_unset_name_fails() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch(
            "printenv",
            &[Arg("SAFESHELL_DEFINITELY_UNSET_VAR".to_string())],
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn whoami_reports_a_nonempty_name() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("whoami", &[], &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(!r.stdout.trim().is_empty());
    }

    #[test]
    fn id_reports_uid_and_gid() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("id", &[], &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(r.stdout.starts_with("uid="));
    }

    #[test]
    fn uname_reports_a_kernel_name() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch("uname", &[], &[], &mut session, &resolver);
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(r.stdout.trim(), "Linux");
    }

    #[test]
    fn sleep_actually_waits_approximately_the_requested_duration() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let start = std::time::Instant::now();
        let r = dispatch(
            "sleep",
            &[Arg("0.05".to_string())],
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0);
        assert!(start.elapsed() >= std::time::Duration::from_millis(40));
    }

    #[test]
    fn sleep_rejects_a_negative_interval() {
        let mut session = TerminalSession::new();
        let (_tmp, resolver) = resolver();
        let r = dispatch(
            "sleep",
            &[Arg("-1".to_string())],
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 1);
    }
}

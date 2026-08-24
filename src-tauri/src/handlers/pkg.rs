//! `safeshell-pkg {list|install|remove}` — SafeShell's mock package
//! manager. `policies/supported_commands.toml` already declared this
//! command's divergence ("Operates against local metadata fixtures only;
//! no network installation.") long before any handler existed; this
//! module is that handler.
//!
//! State lives on [`TerminalSession::packages`], seeded once per session
//! from `simulated-root-image/mock-package-db.json`
//! (`orchestrator::create_session`) and mutated in-memory only — there is
//! no real on-disk package format to install/remove, matching the "mock"
//! framing the seed file's own `_comment` field already used. Because
//! it's session state rather than simulated filesystem content, a
//! `safeshell-pkg` transaction's predicted/actual diff is always empty —
//! expected, not a bug: the diff engine (`simulation::diff`) only tracks
//! filesystem changes, and this command makes none.
//!
//! `remove`'s destructiveness is enforced entirely by `policy::risk`
//! (§20.4's toolchain-critical-package escalation to High, plus the
//! blanket "partially-supported divergence -> at least Medium" rule every
//! `safeshell-pkg` invocation gets regardless of subcommand) — this
//! handler itself never refuses removing an essential package
//! (`DANGEROUS != DENIED`, docs/CLAUDE.md invariant #1); it just reports
//! plainly what it did.

use crate::mock_packages::MockPackage;
use crate::parser::Arg;
use crate::session::TerminalSession;

use super::CommandResult;

pub fn cmd_safeshell_pkg(session: &mut TerminalSession, args: &[Arg]) -> CommandResult {
    match args.first().map(Arg::as_str) {
        Some("list") => cmd_list(session),
        Some("install") => cmd_install(session, &args[1..]),
        Some("remove") => cmd_remove(session, &args[1..]),
        Some(other) => CommandResult::error(
            format!("safeshell-pkg: unknown subcommand '{other}' (expected list|install|remove)\n"),
            1,
        ),
        None => CommandResult::error(
            "safeshell-pkg: missing subcommand (expected list|install|remove)\n",
            1,
        ),
    }
}

fn cmd_list(session: &TerminalSession) -> CommandResult {
    let mut packages: Vec<&MockPackage> = session.packages.iter().collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    let stdout: String = packages
        .into_iter()
        .map(|p| {
            format!(
                "{}  {}{}\n",
                p.name,
                p.version,
                if p.essential { "  [essential]" } else { "" }
            )
        })
        .collect();
    CommandResult::ok(stdout)
}

fn cmd_install(session: &mut TerminalSession, args: &[Arg]) -> CommandResult {
    let Some(name) = args.first().map(Arg::as_str) else {
        return CommandResult::error("safeshell-pkg install: missing package name\n", 1);
    };
    let version = args.get(1).map(Arg::as_str).unwrap_or("1.0.0");
    if session.packages.iter().any(|p| p.name == name) {
        return CommandResult::error(
            format!("safeshell-pkg install: '{name}' is already installed\n"),
            1,
        );
    }
    session.packages.push(MockPackage {
        name: name.to_string(),
        version: version.to_string(),
        essential: false,
    });
    CommandResult::ok(format!("installed {name} {version}\n"))
}

fn cmd_remove(session: &mut TerminalSession, args: &[Arg]) -> CommandResult {
    let Some(name) = args.first().map(Arg::as_str) else {
        return CommandResult::error("safeshell-pkg remove: missing package name\n", 1);
    };
    let Some(index) = session.packages.iter().position(|p| p.name == name) else {
        return CommandResult::error(
            format!("safeshell-pkg remove: '{name}' is not installed\n"),
            1,
        );
    };
    let removed = session.packages.remove(index);
    let note = if removed.essential {
        " — this package was marked essential; the simulated toolchain may now be broken\n"
    } else {
        "\n"
    };
    CommandResult::ok(format!(
        "removed {} {}{note}",
        removed.name, removed.version
    ))
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

    fn session_with(packages: Vec<MockPackage>) -> TerminalSession {
        let mut session = TerminalSession::new();
        session.packages = packages;
        session
    }

    fn pkg(name: &str, essential: bool) -> MockPackage {
        MockPackage {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            essential,
        }
    }

    #[test]
    fn list_reports_seeded_packages() {
        let mut session = session_with(vec![pkg("curl", false), pkg("safeshell-toolchain", true)]);
        let (_tmp, resolver) = resolver();
        let r = dispatch(
            "safeshell-pkg",
            &[Arg("list".into())],
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(r.stdout.contains("curl"));
        assert!(r.stdout.contains("safeshell-toolchain"));
        assert!(r.stdout.contains("[essential]"));
    }

    #[test]
    fn remove_deletes_a_non_essential_package() {
        let mut session = session_with(vec![pkg("curl", false)]);
        let (_tmp, resolver) = resolver();
        let r = dispatch(
            "safeshell-pkg",
            &[Arg("remove".into()), Arg("curl".into())],
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(session.packages.is_empty());
    }

    #[test]
    fn remove_still_succeeds_for_an_essential_package_and_says_so() {
        // DANGEROUS != DENIED (invariant #1): the handler never refuses
        // this — policy risk classification is what gates it.
        let mut session = session_with(vec![pkg("safeshell-toolchain", true)]);
        let (_tmp, resolver) = resolver();
        let r = dispatch(
            "safeshell-pkg",
            &[Arg("remove".into()), Arg("safeshell-toolchain".into())],
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert!(session.packages.is_empty());
        assert!(r.stdout.contains("essential"));
    }

    #[test]
    fn remove_of_an_unknown_package_is_an_error() {
        let mut session = session_with(vec![]);
        let (_tmp, resolver) = resolver();
        let r = dispatch(
            "safeshell-pkg",
            &[Arg("remove".into()), Arg("nope".into())],
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 1);
    }

    #[test]
    fn install_adds_a_new_package() {
        let mut session = session_with(vec![]);
        let (_tmp, resolver) = resolver();
        let r = dispatch(
            "safeshell-pkg",
            &[Arg("install".into()), Arg("jq".into()), Arg("1.7".into())],
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
        assert_eq!(session.packages.len(), 1);
        assert_eq!(session.packages[0].name, "jq");
        assert_eq!(session.packages[0].version, "1.7");
        assert!(!session.packages[0].essential);
    }

    #[test]
    fn install_of_an_already_installed_package_is_an_error() {
        let mut session = session_with(vec![pkg("curl", false)]);
        let (_tmp, resolver) = resolver();
        let r = dispatch(
            "safeshell-pkg",
            &[Arg("install".into()), Arg("curl".into())],
            &[],
            &mut session,
            &resolver,
        );
        assert_eq!(r.exit_code, 1);
    }
}

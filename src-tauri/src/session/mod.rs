//! Per-tab terminal session state: cwd, environment, history. See
//! `docs/architecture.md` §17.1, §17.3.
//!
//! This module owns no filesystem I/O and no sandbox handle yet — `handlers/`
//! runs against a [`crate::simulation::resolver::LayeredResolver`] built
//! per-command from the session's layer stack, not stored on
//! `TerminalSession` itself. `TerminalSession` still needs extending with
//! the session's real sandbox handle and persistent layer stack (today
//! there is no `Session`-level owner of a `snapshot::backend::LayerStack`
//! — each simulation pass in `simulation::manager` currently takes one as
//! a parameter rather than a session owning one long-term), once the
//! Transaction Manager (Build order phase 5, done) is wired end-to-end
//! with a real session lifecycle rather than exercised directly in tests.

use std::collections::HashMap;

use ulid::Ulid;

use crate::fs_abstraction::SandboxPath;
use crate::mock_packages::MockPackage;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(Ulid);

impl SessionId {
    pub fn new() -> Self {
        SessionId(Ulid::new())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sess_{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct TerminalSession {
    pub id: SessionId,
    cwd: SandboxPath,
    env: HashMap<String, String>,
    history: Vec<String>,
    pub last_exit_status: i32,
    /// The session's mock package list — `handlers::pkg`'s `safeshell-pkg`
    /// state. Seeded once at session creation from
    /// `simulated-root-image/mock-package-db.json`
    /// (`orchestrator::create_session`), then mutated only by real
    /// execution, never by simulation — `orchestrator::submit_command`
    /// clones the whole `TerminalSession` for its simulation pass (see
    /// that module's doc comment on why `cd`'s `cwd` mutation needed the
    /// same treatment), so this field inherits that isolation for free.
    pub packages: Vec<MockPackage>,
}

impl TerminalSession {
    /// Seeds realistic default environment variables per §17.3
    /// (`HOME`, `USER`, `SHELL`, `LANG`, `PWD`).
    pub fn new() -> Self {
        let mut env = HashMap::new();
        env.insert("HOME".to_string(), "/home/user".to_string());
        env.insert("USER".to_string(), "user".to_string());
        env.insert("SHELL".to_string(), "/bin/safeshell".to_string());
        env.insert("LANG".to_string(), "en_US.UTF-8".to_string());
        env.insert("PWD".to_string(), "/".to_string());
        // PATH exists for realism (`echo $PATH`, `which`) — it does not
        // drive command dispatch (§17.3); dispatch is a typed name->handler
        // map built in `handlers/`.
        env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());

        TerminalSession {
            id: SessionId::new(),
            cwd: SandboxPath::root(),
            env,
            history: Vec::new(),
            last_exit_status: 0,
            packages: Vec::new(),
        }
    }

    pub fn cwd(&self) -> &SandboxPath {
        &self.cwd
    }

    /// Sets the session's current directory. Callers (the `cd` handler) are
    /// responsible for validating the target exists and is a directory
    /// before calling this — this method only updates session state and
    /// keeps `PWD` consistent with `cwd`, matching real shell behavior.
    pub fn set_cwd(&mut self, path: SandboxPath) {
        self.env.insert("PWD".to_string(), path.to_string());
        self.cwd = path;
    }

    pub fn env(&self) -> &HashMap<String, String> {
        &self.env
    }

    pub fn export(&mut self, key: String, value: String) {
        self.env.insert(key, value);
    }

    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.env.get(key).map(String::as_str)
    }

    pub fn record_history(&mut self, line: String) {
        self.history.push(line);
    }

    pub fn history(&self) -> &[String] {
        &self.history
    }
}

impl Default for TerminalSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_seeds_default_env() {
        let s = TerminalSession::new();
        assert_eq!(s.get_env("HOME"), Some("/home/user"));
        assert_eq!(s.get_env("PWD"), Some("/"));
        assert!(s.cwd().is_root());
    }

    #[test]
    fn set_cwd_updates_pwd_env() {
        let mut s = TerminalSession::new();
        let target = SandboxPath::parse("project/build").unwrap();
        s.set_cwd(target.clone());
        assert_eq!(s.cwd(), &target);
        assert_eq!(s.get_env("PWD"), Some("/project/build"));
    }

    #[test]
    fn export_and_history() {
        let mut s = TerminalSession::new();
        s.export("FOO".to_string(), "bar".to_string());
        assert_eq!(s.get_env("FOO"), Some("bar"));
        s.record_history("ls -la".to_string());
        assert_eq!(s.history(), &["ls -la".to_string()]);
    }
}

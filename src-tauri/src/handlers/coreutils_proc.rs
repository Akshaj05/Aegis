// Spawns and drives the sidecar subprocess binaries used to run the
// stdin/stdout-only coreutils filter tier (wc, sort, uniq, cut, head,
// tail, date).

use std::io::Write;
use std::process::{Command, Stdio};

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
    if dir.file_name().is_some_and(|f| f == "deps") {
        dir.pop();
    }
    Ok(dir.join(format!("safeshell-{name}")))
}

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

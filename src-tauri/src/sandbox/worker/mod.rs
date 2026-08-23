//! Sandbox worker process + typed request protocol. See
//! `docs/architecture.md` §8, §25.2.
//!
//! This pass implements the protocol, transport, resolver, dispatch, and
//! request loop in full — and verifies all of it for real against a plain
//! host directory, including proving `RESOLVE_BENEATH` actually refuses
//! `..`/absolute-path escape attempts on this kernel (see
//! `resolver.rs`'s tests). What it does **not** yet do is run any of this
//! inside an actual namespaced, `pivot_root`ed process: [`run_loop`] takes
//! an already-open root directory and an already-connected `UnixStream`,
//! and doesn't care how either came to exist. Wiring a real
//! `NamespaceSandboxBackend` that forks, enters namespaces, `pivot_root`s,
//! applies seccomp/Landlock/cgroups, and then calls [`run_loop`] in the
//! child is the next slice of Build order phase 2 — deferred because this
//! dev environment can't get past `unshare(CLONE_NEWUSER)`'s follow-up
//! `setgroups` write (see `syscalls.rs`'s "Honesty note"), so building it
//! now would mean shipping more code whose success path is unverified
//! here, on top of the (already partly unverified) namespace-entry
//! sequence — better to keep this pass's deliverable entirely
//! real-tested and take that risk on deliberately, in its own change.

pub mod dispatch;
pub mod protocol;
pub mod resolver;
pub mod transport;

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use protocol::WorkerRequest;
use resolver::RootResolver;

/// Runs the worker's request/response loop: receive a `WorkerRequest`,
/// dispatch it against `resolver`, send the `WorkerResponse`, repeat until
/// the peer closes the connection (a clean end of the session, not an
/// error — `recv_message` returning `UnexpectedEof` on a closed stream is
/// exactly that).
pub fn run_loop(resolver: &RootResolver, stream: &mut UnixStream) -> io::Result<()> {
    loop {
        let request: WorkerRequest = match transport::recv_message(stream) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let response = dispatch::dispatch(resolver, request);
        transport::send_message(stream, &response)?;
    }
}

/// Convenience wrapper combining [`RootResolver::open`] and [`run_loop`],
/// for callers (tests here, the real namespace backend later) that just
/// want "serve this root over this connection."
pub fn serve(root_path: &Path, stream: &mut UnixStream) -> io::Result<()> {
    let resolver = RootResolver::open(root_path)?;
    run_loop(&resolver, stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{FileKind, StatInfo, WorkerResponse};

    #[test]
    fn full_loop_serves_multiple_requests_over_one_connection() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
        let root = tmp.path().to_path_buf();

        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || serve(&root, &mut server));

        transport::send_message(
            &client,
            &WorkerRequest::ReadFile {
                rel_path: "a.txt".into(),
            },
        )
        .unwrap();
        let response: WorkerResponse = transport::recv_message(&client).unwrap();
        assert_eq!(response, WorkerResponse::FileContents(b"hello".to_vec()));

        transport::send_message(
            &client,
            &WorkerRequest::Mkdir {
                parent_rel: "".into(),
                name: "project".into(),
            },
        )
        .unwrap();
        let response: WorkerResponse = transport::recv_message(&client).unwrap();
        assert_eq!(response, WorkerResponse::Ok);

        transport::send_message(
            &client,
            &WorkerRequest::Stat {
                rel_path: "project".into(),
            },
        )
        .unwrap();
        let response: WorkerResponse = transport::recv_message(&client).unwrap();
        // A directory's `st_size` is filesystem-dependent (e.g. the block
        // size, not "0" or "number of entries") — only `kind` is asserted.
        match response {
            WorkerResponse::Stat(StatInfo {
                kind: FileKind::Directory,
                ..
            }) => {}
            other => panic!("expected a Directory stat response, got {other:?}"),
        }

        // Dropping the client end closes the connection; the worker loop
        // must return cleanly (Ok), not error, on a peer disconnect.
        drop(client);
        worker
            .join()
            .unwrap()
            .expect("worker loop should exit cleanly on peer disconnect");
    }

    #[test]
    fn full_loop_reports_an_escape_attempt_as_an_error_response_and_keeps_serving() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
        let root = tmp.path().to_path_buf();

        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || serve(&root, &mut server));

        transport::send_message(
            &client,
            &WorkerRequest::ReadFile {
                rel_path: "../../../etc/passwd".into(),
            },
        )
        .unwrap();
        let response: WorkerResponse = transport::recv_message(&client).unwrap();
        assert!(matches!(response, WorkerResponse::Error { .. }));

        // The connection must still be usable after an error response —
        // one bad request shouldn't tear down the worker's loop.
        transport::send_message(
            &client,
            &WorkerRequest::ReadFile {
                rel_path: "a.txt".into(),
            },
        )
        .unwrap();
        let response: WorkerResponse = transport::recv_message(&client).unwrap();
        assert_eq!(response, WorkerResponse::FileContents(b"hello".to_vec()));

        drop(client);
        worker
            .join()
            .unwrap()
            .expect("worker loop should exit cleanly on peer disconnect");
    }
}

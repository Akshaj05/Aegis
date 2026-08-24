// Sandbox worker process and typed request protocol: runs the
// request/response loop that serves resolver operations over a
// connected stream.

pub mod dispatch;
pub mod protocol;
pub mod resolver;
pub mod transport;

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use protocol::WorkerRequest;
use resolver::RootResolver;

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
        match response {
            WorkerResponse::Stat(StatInfo {
                kind: FileKind::Directory,
                ..
            }) => {}
            other => panic!("expected a Directory stat response, got {other:?}"),
        }

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

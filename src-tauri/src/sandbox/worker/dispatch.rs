//! Translates a `WorkerRequest` into `RootResolver` calls and builds the
//! matching `WorkerResponse`. Kept separate from `resolver.rs` (which
//! knows nothing about the wire protocol) and from `mod.rs`'s request loop
//! (which knows nothing about individual operations), so each can be
//! tested independently.

use crate::sandbox::worker::protocol::{WorkerRequest, WorkerResponse};
use crate::sandbox::worker::resolver::RootResolver;

pub fn dispatch(resolver: &RootResolver, request: WorkerRequest) -> WorkerResponse {
    let result = match request {
        WorkerRequest::Mkdir { parent_rel, name } => resolver
            .mkdir(&parent_rel, &name)
            .map(|()| WorkerResponse::Ok),
        WorkerRequest::Touch { rel_path } => resolver.touch(&rel_path).map(|()| WorkerResponse::Ok),
        WorkerRequest::ReadDir { rel_path } => {
            resolver.read_dir(&rel_path).map(WorkerResponse::DirEntries)
        }
        WorkerRequest::ReadFile { rel_path } => resolver
            .read_file(&rel_path)
            .map(WorkerResponse::FileContents),
        WorkerRequest::Stat { rel_path } => resolver.stat(&rel_path).map(WorkerResponse::Stat),
    };

    result.unwrap_or_else(|e| WorkerResponse::Error {
        message: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::worker::protocol::{FileKind, StatInfo};

    fn resolver_over_tempdir() -> (tempfile::TempDir, RootResolver) {
        let tmp = tempfile::tempdir().unwrap();
        let resolver = RootResolver::open(tmp.path()).unwrap();
        (tmp, resolver)
    }

    #[test]
    fn mkdir_request_creates_a_directory() {
        let (tmp, resolver) = resolver_over_tempdir();
        let response = dispatch(
            &resolver,
            WorkerRequest::Mkdir {
                parent_rel: "".into(),
                name: "project".into(),
            },
        );
        assert_eq!(response, WorkerResponse::Ok);
        assert!(tmp.path().join("project").is_dir());
    }

    #[test]
    fn touch_request_creates_a_file() {
        let (tmp, resolver) = resolver_over_tempdir();
        let response = dispatch(
            &resolver,
            WorkerRequest::Touch {
                rel_path: "a.txt".into(),
            },
        );
        assert_eq!(response, WorkerResponse::Ok);
        assert!(tmp.path().join("a.txt").is_file());
    }

    #[test]
    fn read_file_request_returns_contents() {
        let (tmp, resolver) = resolver_over_tempdir();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
        let response = dispatch(
            &resolver,
            WorkerRequest::ReadFile {
                rel_path: "a.txt".into(),
            },
        );
        assert_eq!(response, WorkerResponse::FileContents(b"hello".to_vec()));
    }

    #[test]
    fn read_dir_request_lists_entries() {
        let (tmp, resolver) = resolver_over_tempdir();
        std::fs::write(tmp.path().join("a.txt"), b"").unwrap();
        let response = dispatch(
            &resolver,
            WorkerRequest::ReadDir {
                rel_path: "".into(),
            },
        );
        assert_eq!(
            response,
            WorkerResponse::DirEntries(vec!["a.txt".to_string()])
        );
    }

    #[test]
    fn stat_request_reports_kind_and_len() {
        let (tmp, resolver) = resolver_over_tempdir();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
        let response = dispatch(
            &resolver,
            WorkerRequest::Stat {
                rel_path: "a.txt".into(),
            },
        );
        assert_eq!(
            response,
            WorkerResponse::Stat(StatInfo {
                kind: FileKind::Regular,
                len: 5
            })
        );
    }

    #[test]
    fn a_failed_operation_becomes_an_error_response_not_a_panic() {
        let (_tmp, resolver) = resolver_over_tempdir();
        let response = dispatch(
            &resolver,
            WorkerRequest::ReadFile {
                rel_path: "does-not-exist".into(),
            },
        );
        assert!(matches!(response, WorkerResponse::Error { .. }));
    }

    #[test]
    fn an_escape_attempt_becomes_an_error_response_not_a_panic() {
        let (_tmp, resolver) = resolver_over_tempdir();
        let response = dispatch(
            &resolver,
            WorkerRequest::ReadFile {
                rel_path: "../../../etc/passwd".into(),
            },
        );
        assert!(matches!(response, WorkerResponse::Error { .. }));
    }
}

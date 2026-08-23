//! Typed request/response protocol between the host-side core and the
//! sandbox worker. See `docs/architecture.md` §25.2: "Requests carry
//! enumerated operation descriptors... No shell strings, no host absolute
//! paths, no free-form path blobs."
//!
//! `rel_path`/`parent_rel`/`name` fields are `String`, not `SandboxPath` —
//! this crate boundary is exactly where an already-validated `SandboxPath`
//! gets serialized to cross the wire, and the worker must **not** assume
//! the sender validated anything (§25.1: string validation is a redundant
//! second check, never the primary control). The worker re-derives safety
//! from `openat2`/`RESOLVE_BENEATH` resolution in `resolver.rs`, not from
//! trusting these strings.
//!
//! `Mkdir` splits `parent_rel`/`name` rather than taking one whole relative
//! path, because directory creation goes through `mkdirat(2)`, which has no
//! `RESOLVE_BENEATH`-equivalent resolve-flags parameter (unlike `openat2`).
//! The resolver first resolves `parent_rel` through `openat2`+`RESOLVE_BENEATH`
//! (the real containment control), then calls `mkdirat` against that
//! already-confirmed-beneath-root directory fd using `name` as a single
//! path component — `name` must contain no `/` and must not be `.`/`..`,
//! or `mkdirat` would resolve it relative to that fd with no
//! `RESOLVE_BENEATH` protection at all. `resolver.rs` enforces that; this
//! module just carries the data.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkerRequest {
    Mkdir { parent_rel: String, name: String },
    Touch { rel_path: String },
    ReadDir { rel_path: String },
    ReadFile { rel_path: String },
    Stat { rel_path: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatInfo {
    pub kind: FileKind,
    pub len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkerResponse {
    Ok,
    DirEntries(Vec<String>),
    FileContents(Vec<u8>),
    Stat(StatInfo),
    Error { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(value: T) {
        let json = serde_json::to_vec(&value).unwrap();
        let decoded: T = serde_json::from_slice(&json).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn every_request_variant_round_trips() {
        roundtrip(WorkerRequest::Mkdir {
            parent_rel: "a".into(),
            name: "b".into(),
        });
        roundtrip(WorkerRequest::Touch {
            rel_path: "a/b".into(),
        });
        roundtrip(WorkerRequest::ReadDir {
            rel_path: "a".into(),
        });
        roundtrip(WorkerRequest::ReadFile {
            rel_path: "a/b".into(),
        });
        roundtrip(WorkerRequest::Stat {
            rel_path: "a/b".into(),
        });
    }

    #[test]
    fn every_response_variant_round_trips() {
        roundtrip(WorkerResponse::Ok);
        roundtrip(WorkerResponse::DirEntries(vec!["a".into(), "b".into()]));
        roundtrip(WorkerResponse::FileContents(vec![1, 2, 3]));
        roundtrip(WorkerResponse::Stat(StatInfo {
            kind: FileKind::Directory,
            len: 0,
        }));
        roundtrip(WorkerResponse::Error {
            message: "boom".into(),
        });
    }
}

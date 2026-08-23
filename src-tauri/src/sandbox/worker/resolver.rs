//! Resolves `WorkerRequest` paths against a retained root directory fd
//! using `openat2`+`RESOLVE_BENEATH` (§25.2) — the actual containment
//! control for filesystem access, independent of whatever string
//! validation happened upstream. No `unsafe` here: every raw syscall goes
//! through `sandbox/syscalls.rs`'s `openat2_raw`/`mkdirat_raw`.
//!
//! This module doesn't care how `root_fd` came to exist — opened from a
//! plain host directory (this pass, and its own tests) or from `/` inside
//! a `pivot_root`ed sandboxed process (the namespace-backend work, not yet
//! built) behave identically from here down. That's deliberate: it's what
//! lets the resolution logic — the actual security-critical half of this
//! component — be fully tested now, against a plain directory, without
//! waiting on namespace support this dev environment doesn't have.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use crate::sandbox::syscalls::{mkdirat_raw, openat2_raw, unlinkat_raw};
use crate::sandbox::worker::protocol::{FileKind, StatInfo};

/// Marks a deletion of `<name>` at this layer: a plain, empty sidecar
/// file named `.wh.<name>`, placed alongside where `<name>` would live.
/// The convention itself (not the mechanism) is borrowed from AUFS/
/// legacy Docker union filesystems — appropriate here for the same
/// reason it was there: this backend has no access to a real kernel
/// overlay's char-device whiteout primitive (`copyup`/host-directory
/// layers are plain POSIX directories), so "deleted" needs a real,
/// ordinary file this layer's owner can create, that a merged read can
/// recognize and never show to the user as content of its own.
/// `simulation::resolver::LayeredResolver` is what actually interprets
/// this marker across a layer stack; this module only creates/detects it
/// within one layer.
pub const WHITEOUT_PREFIX: &str = ".wh.";

fn child_path(parent_rel: &str, name: &str) -> String {
    if parent_rel.is_empty() {
        name.to_string()
    } else {
        format!("{parent_rel}/{name}")
    }
}

/// `RESOLVE_NO_MAGICLINKS` blocks `/proc/*/fd/N`-style magic-link
/// traversal in addition to `RESOLVE_BENEATH`'s ordinary path-escape
/// refusal (§25.2's exact wording: "`openat2(2)` with `RESOLVE_BENEATH`
/// (and `RESOLVE_NO_MAGICLINKS`)").
const CONTAINED_RESOLVE: u64 = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS;

pub struct RootResolver {
    root_fd: OwnedFd,
}

impl RootResolver {
    /// Opens `root_path` as the resolution root. `root_path` is
    /// SafeShell's own configuration (the sandbox root, however it came to
    /// exist), never user command input — see `fs_abstraction::HostManagedPath`
    /// for the equivalent host-side rule.
    pub fn open(root_path: &Path) -> io::Result<Self> {
        let file = File::open(root_path)?;
        Ok(RootResolver {
            root_fd: file.into(),
        })
    }

    /// Converts a relative-path string to the `CString` `openat2` expects.
    /// An empty string means "the root itself" (matching
    /// `SandboxPath::root()`'s empty-string representation) — `openat2`
    /// has no "empty path means self" behavior without the separate
    /// `AT_EMPTY_PATH` flag, so this maps `""` to `"."` instead, which
    /// means the same thing to the kernel's path resolver without needing
    /// that flag.
    fn to_cstring(rel_path: &str) -> io::Result<CString> {
        let effective = if rel_path.is_empty() { "." } else { rel_path };
        CString::new(effective).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    /// Opens `rel_path` read-only, beneath the root. Used for `ReadFile`
    /// and `Stat`.
    fn open_read(&self, rel_path: &str) -> io::Result<OwnedFd> {
        let c_path = Self::to_cstring(rel_path)?;
        openat2_raw(
            self.root_fd.as_raw_fd(),
            &c_path,
            libc::O_RDONLY,
            CONTAINED_RESOLVE,
            0,
        )
    }

    /// Opens `rel_path` as a directory, beneath the root. Used for
    /// `ReadDir` and as the parent-resolution step for `Mkdir`.
    fn open_dir(&self, rel_path: &str) -> io::Result<OwnedFd> {
        let c_path = Self::to_cstring(rel_path)?;
        openat2_raw(
            self.root_fd.as_raw_fd(),
            &c_path,
            libc::O_RDONLY | libc::O_DIRECTORY,
            CONTAINED_RESOLVE,
            0,
        )
    }

    pub fn touch(&self, rel_path: &str) -> io::Result<()> {
        let c_path = Self::to_cstring(rel_path)?;
        // O_CREAT without O_EXCL/O_TRUNC: creates the file if missing,
        // opens (without truncating) if it already exists — matching
        // `touch`'s "don't destroy existing content" contract, though not
        // yet its mtime-update behavior (documented gap, not this pass's
        // scope).
        openat2_raw(
            self.root_fd.as_raw_fd(),
            &c_path,
            libc::O_CREAT | libc::O_WRONLY,
            CONTAINED_RESOLVE,
            0o644,
        )
        .map(|_fd| ())
    }

    /// Creates `rel_path` with exactly `contents`, truncating if it
    /// already exists in *this* layer. Used by
    /// `simulation::resolver::LayeredResolver` to copy a file's content up
    /// from a lower layer into the writable top layer before modifying it
    /// — the userspace equivalent of what a kernel union filesystem's
    /// copy-up does automatically. Not used by the single-layer
    /// `sandbox/worker` request dispatch, which has no lower layers to
    /// copy up from.
    pub fn write_new_file(&self, rel_path: &str, contents: &[u8]) -> io::Result<()> {
        let c_path = Self::to_cstring(rel_path)?;
        let fd = openat2_raw(
            self.root_fd.as_raw_fd(),
            &c_path,
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            CONTAINED_RESOLVE,
            0o644,
        )?;
        let mut file = File::from(fd);
        std::io::Write::write_all(&mut file, contents)
    }

    /// `name` must be a single path component — see
    /// `sandbox/worker/protocol.rs`'s doc comment for why `mkdirat` can't
    /// be given a multi-component or `..`-containing name safely.
    pub fn mkdir(&self, parent_rel: &str, name: &str) -> io::Result<()> {
        if !is_single_safe_component(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("mkdir name must be a single path component, got {name:?}"),
            ));
        }
        let parent_fd = self.open_dir(parent_rel)?;
        let c_name = Self::to_cstring(name)?;
        mkdirat_raw(parent_fd.as_raw_fd(), &c_name, 0o755)
    }

    /// Removes a real file (not a directory) that exists in *this* layer.
    /// `rm`'s handler, and `LayeredResolver::remove`, are the only
    /// callers — see that method's doc comment for why removing a name
    /// that only exists in a *lower* layer is a whiteout
    /// ([`create_whiteout`](Self::create_whiteout)), not this.
    pub fn remove_file(&self, parent_rel: &str, name: &str) -> io::Result<()> {
        if !is_single_safe_component(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("remove name must be a single path component, got {name:?}"),
            ));
        }
        let parent_fd = self.open_dir(parent_rel)?;
        let c_name = Self::to_cstring(name)?;
        unlinkat_raw(parent_fd.as_raw_fd(), &c_name, false)
    }

    /// Recursively removes a real directory tree that exists in *this*
    /// layer — every entry within it, bottom-up, then the now-empty
    /// directory itself (`unlinkat`'s `AT_REMOVEDIR` only accepts an
    /// empty directory, per `unlinkat(2)`). Only ever needs to see this
    /// one layer's own real content: a lower layer's content behind a
    /// deleted directory is hidden by a single whiteout at the parent
    /// (see [`create_whiteout`](Self::create_whiteout)'s doc comment),
    /// never walked or removed entry-by-entry.
    pub fn remove_dir_recursive(&self, parent_rel: &str, name: &str) -> io::Result<()> {
        if !is_single_safe_component(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("remove name must be a single path component, got {name:?}"),
            ));
        }
        let dir_rel = child_path(parent_rel, name);
        for entry_name in self.read_dir(&dir_rel)? {
            let entry_info = self.stat(&child_path(&dir_rel, &entry_name))?;
            if entry_info.kind == FileKind::Directory {
                self.remove_dir_recursive(&dir_rel, &entry_name)?;
            } else {
                self.remove_file(&dir_rel, &entry_name)?;
            }
        }
        let parent_fd = self.open_dir(parent_rel)?;
        let c_name = Self::to_cstring(name)?;
        unlinkat_raw(parent_fd.as_raw_fd(), &c_name, true)
    }

    /// Records that `<name>` (a file or a whole directory subtree) is
    /// deleted as of this layer, for a name that also exists in some
    /// *lower* layer — that lower content is real, checkpointed, and
    /// possibly shared, so it can't be removed for real; a sidecar
    /// marker (see [`WHITEOUT_PREFIX`]) is what makes a merged read
    /// treat it as gone instead. `simulation::resolver::LayeredResolver::remove`
    /// is the only caller, and always removes any real same-layer copy
    /// of `<name>` first — creating a whiteout is never a substitute for
    /// that, only for hiding what's underneath.
    pub fn create_whiteout(&self, parent_rel: &str, name: &str) -> io::Result<()> {
        if !is_single_safe_component(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("whiteout name must be a single path component, got {name:?}"),
            ));
        }
        let marker_rel = child_path(parent_rel, &format!("{WHITEOUT_PREFIX}{name}"));
        self.touch(&marker_rel)
    }

    /// Whether this layer records `<name>` as deleted. See
    /// [`create_whiteout`](Self::create_whiteout).
    pub fn has_whiteout(&self, parent_rel: &str, name: &str) -> bool {
        let marker_rel = child_path(parent_rel, &format!("{WHITEOUT_PREFIX}{name}"));
        self.stat(&marker_rel).is_ok()
    }

    pub fn read_file(&self, rel_path: &str) -> io::Result<Vec<u8>> {
        let fd = self.open_read(rel_path)?;
        let mut file = File::from(fd);
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut contents)?;
        Ok(contents)
    }

    pub fn read_dir(&self, rel_path: &str) -> io::Result<Vec<String>> {
        let fd = self.open_dir(rel_path)?;
        // Reading directory entries from an already-open fd (rather than a
        // path) has no direct std API; re-addressing it via its own
        // `/proc/self/fd/N` magic link is the standard safe technique —
        // this refers to exactly the fd we already hold (not a fresh path
        // resolution that could itself be raced or escape), because the
        // kernel resolves that magic link to the specific open file
        // description, not by re-walking any path string.
        let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
        let mut names: Vec<String> = std::fs::read_dir(&proc_path)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        Ok(names)
    }

    pub fn stat(&self, rel_path: &str) -> io::Result<StatInfo> {
        let fd = self.open_read(rel_path)?;
        let metadata = File::from(fd).metadata()?;
        let kind = if metadata.is_dir() {
            FileKind::Directory
        } else if metadata.is_file() {
            FileKind::Regular
        } else if metadata.file_type().is_symlink() {
            FileKind::Symlink
        } else {
            FileKind::Other
        };
        Ok(StatInfo {
            kind,
            len: metadata.len(),
        })
    }
}

fn is_single_safe_component(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('\0') && name != "." && name != ".."
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver_over_tempdir() -> (tempfile::TempDir, RootResolver) {
        let tmp = tempfile::tempdir().unwrap();
        let resolver = RootResolver::open(tmp.path()).unwrap();
        (tmp, resolver)
    }

    #[test]
    fn touch_creates_a_new_file() {
        let (tmp, resolver) = resolver_over_tempdir();
        resolver.touch("a.txt").unwrap();
        assert!(tmp.path().join("a.txt").is_file());
    }

    #[test]
    fn write_new_file_creates_with_given_contents() {
        let (_tmp, resolver) = resolver_over_tempdir();
        resolver.write_new_file("a.txt", b"hello").unwrap();
        assert_eq!(resolver.read_file("a.txt").unwrap(), b"hello");
    }

    #[test]
    fn write_new_file_truncates_an_existing_file() {
        let (_tmp, resolver) = resolver_over_tempdir();
        resolver
            .write_new_file("a.txt", b"first version, quite long")
            .unwrap();
        resolver.write_new_file("a.txt", b"v2").unwrap();
        assert_eq!(resolver.read_file("a.txt").unwrap(), b"v2");
    }

    #[test]
    fn touch_does_not_truncate_an_existing_file() {
        let (tmp, resolver) = resolver_over_tempdir();
        std::fs::write(tmp.path().join("a.txt"), b"keep me").unwrap();
        resolver.touch("a.txt").unwrap();
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("a.txt")).unwrap(),
            "keep me"
        );
    }

    #[test]
    fn mkdir_creates_a_directory_under_an_existing_parent() {
        let (tmp, resolver) = resolver_over_tempdir();
        resolver.mkdir("", "project").unwrap();
        assert!(tmp.path().join("project").is_dir());
    }

    #[test]
    fn remove_file_deletes_a_real_file() {
        let (tmp, resolver) = resolver_over_tempdir();
        std::fs::write(tmp.path().join("a.txt"), b"bye").unwrap();
        resolver.remove_file("", "a.txt").unwrap();
        assert!(!tmp.path().join("a.txt").exists());
    }

    #[test]
    fn remove_dir_recursive_deletes_nested_content() {
        let (tmp, resolver) = resolver_over_tempdir();
        std::fs::create_dir_all(tmp.path().join("project/sub")).unwrap();
        std::fs::write(tmp.path().join("project/a.txt"), b"x").unwrap();
        std::fs::write(tmp.path().join("project/sub/b.txt"), b"y").unwrap();

        resolver.remove_dir_recursive("", "project").unwrap();

        assert!(!tmp.path().join("project").exists());
    }

    #[test]
    fn create_whiteout_and_has_whiteout_round_trip() {
        let (tmp, resolver) = resolver_over_tempdir();
        assert!(!resolver.has_whiteout("", "deleted.txt"));
        resolver.create_whiteout("", "deleted.txt").unwrap();
        assert!(resolver.has_whiteout("", "deleted.txt"));
        assert!(tmp.path().join(".wh.deleted.txt").is_file());
    }

    #[test]
    fn mkdir_rejects_a_multi_component_name() {
        let (_tmp, resolver) = resolver_over_tempdir();
        let result = resolver.mkdir("", "a/b");
        assert!(
            result.is_err(),
            "mkdir must reject a name containing a path separator"
        );
    }

    #[test]
    fn mkdir_rejects_dotdot_as_name() {
        let (_tmp, resolver) = resolver_over_tempdir();
        let result = resolver.mkdir("", "..");
        assert!(result.is_err(), "mkdir must reject `..` as a name");
    }

    #[test]
    fn read_file_returns_written_contents() {
        let (tmp, resolver) = resolver_over_tempdir();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
        let contents = resolver.read_file("a.txt").unwrap();
        assert_eq!(contents, b"hello");
    }

    #[test]
    fn read_dir_lists_entries_sorted() {
        let (tmp, resolver) = resolver_over_tempdir();
        std::fs::write(tmp.path().join("b.txt"), b"").unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"").unwrap();
        let entries = resolver.read_dir("").unwrap();
        assert_eq!(entries, vec!["a.txt".to_string(), "b.txt".to_string()]);
    }

    #[test]
    fn stat_reports_kind_and_len() {
        let (tmp, resolver) = resolver_over_tempdir();
        std::fs::write(tmp.path().join("a.txt"), b"hello").unwrap();
        let info = resolver.stat("a.txt").unwrap();
        assert_eq!(info.kind, FileKind::Regular);
        assert_eq!(info.len, 5);

        std::fs::create_dir(tmp.path().join("d")).unwrap();
        let dir_info = resolver.stat("d").unwrap();
        assert_eq!(dir_info.kind, FileKind::Directory);
    }

    #[test]
    fn read_file_refuses_a_dotdot_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let confined = tmp.path().join("confined");
        std::fs::create_dir(&confined).unwrap();
        std::fs::write(tmp.path().join("secret.txt"), b"top secret").unwrap();

        let resolver = RootResolver::open(&confined).unwrap();
        let result = resolver.read_file("../secret.txt");
        assert!(
            result.is_err(),
            "RESOLVE_BENEATH should have refused this read"
        );
    }

    #[test]
    fn read_file_refuses_an_absolute_path() {
        let (_tmp, resolver) = resolver_over_tempdir();
        let result = resolver.read_file("/etc/passwd");
        assert!(
            result.is_err(),
            "RESOLVE_BENEATH should have refused an absolute path"
        );
    }

    #[test]
    fn mkdir_parent_resolution_refuses_a_dotdot_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let confined = tmp.path().join("confined");
        std::fs::create_dir(&confined).unwrap();

        let resolver = RootResolver::open(&confined).unwrap();
        // Attempting to mkdir a new directory whose *parent* is reached via
        // `..` must fail at parent resolution, before mkdirat is ever
        // called.
        let result = resolver.mkdir("..", "evil");
        assert!(
            result.is_err(),
            "RESOLVE_BENEATH should have refused resolving the `..` parent"
        );
        assert!(!tmp.path().join("evil").exists());
    }
}

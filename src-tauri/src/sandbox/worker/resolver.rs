// Resolves WorkerRequest paths against a retained root directory fd
// using openat2+RESOLVE_BENEATH, containing all filesystem access
// beneath that root.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use crate::sandbox::syscalls::{mkdirat_raw, openat2_raw, unlinkat_raw};
use crate::sandbox::worker::protocol::{FileKind, StatInfo};

pub const WHITEOUT_PREFIX: &str = ".wh.";

fn child_path(parent_rel: &str, name: &str) -> String {
    if parent_rel.is_empty() {
        name.to_string()
    } else {
        format!("{parent_rel}/{name}")
    }
}

const CONTAINED_RESOLVE: u64 = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS;

pub struct RootResolver {
    root_fd: OwnedFd,
}

impl RootResolver {
    pub fn open(root_path: &Path) -> io::Result<Self> {
        let file = File::open(root_path)?;
        Ok(RootResolver {
            root_fd: file.into(),
        })
    }

    fn to_cstring(rel_path: &str) -> io::Result<CString> {
        let effective = if rel_path.is_empty() { "." } else { rel_path };
        CString::new(effective).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

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
        openat2_raw(
            self.root_fd.as_raw_fd(),
            &c_path,
            libc::O_CREAT | libc::O_WRONLY,
            CONTAINED_RESOLVE,
            0o644,
        )
        .map(|_fd| ())
    }

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
        let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
        let mut names: Vec<String> = std::fs::read_dir(&proc_path)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        Ok(names)
    }

    pub fn set_mode(&self, parent_rel: &str, name: &str, mode: u32) -> io::Result<()> {
        if !is_single_safe_component(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("chmod name must be a single path component, got {name:?}"),
            ));
        }
        let parent_fd = self.open_dir(parent_rel)?;
        nix::sys::stat::fchmodat(
            &parent_fd,
            name,
            nix::sys::stat::Mode::from_bits_truncate(mode),
            nix::sys::stat::FchmodatFlags::FollowSymlink,
        )
        .map_err(io::Error::from)
    }

    pub fn set_owner(
        &self,
        parent_rel: &str,
        name: &str,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> io::Result<()> {
        if !is_single_safe_component(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("chown name must be a single path component, got {name:?}"),
            ));
        }
        let parent_fd = self.open_dir(parent_rel)?;
        nix::unistd::fchownat(
            &parent_fd,
            name,
            uid.map(nix::unistd::Uid::from_raw),
            gid.map(nix::unistd::Gid::from_raw),
            nix::fcntl::AtFlags::empty(),
        )
        .map_err(io::Error::from)
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
        let result = resolver.mkdir("..", "evil");
        assert!(
            result.is_err(),
            "RESOLVE_BENEATH should have refused resolving the `..` parent"
        );
        assert!(!tmp.path().join("evil").exists());
    }
}

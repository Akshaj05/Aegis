// LayeredResolver: merged read/write filesystem resolution across an
// ordered stack of layers, with whiteout-based deletion support, built
// on top of sandbox/worker/resolver.rs's per-layer RootResolver.

use std::io;

use crate::sandbox::worker::protocol::{FileKind, StatInfo};
use crate::sandbox::worker::resolver::{RootResolver, WHITEOUT_PREFIX};
use crate::snapshot::backend::MountedView;

fn child_path(parent_rel: &str, name: &str) -> String {
    if parent_rel.is_empty() {
        name.to_string()
    } else {
        format!("{parent_rel}/{name}")
    }
}

pub struct LayeredResolver {
    layers: Vec<RootResolver>,
}

impl LayeredResolver {
    pub fn from_mounted_view(view: &MountedView) -> io::Result<Self> {
        let layers = view
            .layers
            .iter()
            .map(|path| RootResolver::open(path))
            .collect::<io::Result<Vec<_>>>()?;
        if layers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a mounted view must have at least one layer",
            ));
        }
        Ok(LayeredResolver { layers })
    }

    fn top(&self) -> &RootResolver {
        &self.layers[0]
    }

    fn lower_layers(&self) -> &[RootResolver] {
        &self.layers[1..]
    }

    fn clear_stale_whiteout(&self, parent_rel: &str, name: &str) {
        let _ = self
            .top()
            .remove_file(parent_rel, &format!("{WHITEOUT_PREFIX}{name}"));
    }

    fn ensure_top_dir_chain(&self, dir_rel: &str) -> io::Result<()> {
        let mut parent = String::new();
        for component in dir_rel.split('/').filter(|s| !s.is_empty()) {
            let child = child_path(&parent, component);
            if self.top().stat(&child).is_err() {
                match self.stat(&child) {
                    Ok(info) if info.kind == FileKind::Directory => {
                        self.top().mkdir(&parent, component)?;
                    }
                    _ => return Ok(()),
                }
            }
            parent = child;
        }
        Ok(())
    }

    pub fn touch(&self, rel_path: &str) -> io::Result<()> {
        if self.top().stat(rel_path).is_ok() {
            return Ok(());
        }
        let (parent, name) = rel_path.rsplit_once('/').unwrap_or(("", rel_path));
        self.ensure_top_dir_chain(parent)?;
        let result = match self.read_file(rel_path) {
            Ok(contents) => self.top().write_new_file(rel_path, &contents),
            Err(e) if e.kind() == io::ErrorKind::NotFound => self.top().touch(rel_path),
            Err(e) => Err(e),
        };
        if result.is_ok() {
            self.clear_stale_whiteout(parent, name);
        }
        result
    }

    pub fn mkdir(&self, parent_rel: &str, name: &str) -> io::Result<()> {
        let rel_path = child_path(parent_rel, name);
        if self.stat(&rel_path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{rel_path}: already exists"),
            ));
        }
        self.ensure_top_dir_chain(parent_rel)?;
        let result = self.top().mkdir(parent_rel, name);
        if result.is_ok() {
            self.clear_stale_whiteout(parent_rel, name);
        }
        result
    }

    pub fn write_file(&self, rel_path: &str, contents: &[u8]) -> io::Result<()> {
        let (parent, name) = rel_path.rsplit_once('/').unwrap_or(("", rel_path));
        self.ensure_top_dir_chain(parent)?;
        let result = self.top().write_new_file(rel_path, contents);
        if result.is_ok() {
            self.clear_stale_whiteout(parent, name);
        }
        result
    }

    fn ensure_top_copy(&self, rel_path: &str) -> io::Result<()> {
        if self.top().stat(rel_path).is_ok() {
            return Ok(());
        }
        match self.stat(rel_path) {
            Ok(info) if info.kind == FileKind::Directory => {
                let (parent, name) = rel_path.rsplit_once('/').unwrap_or(("", rel_path));
                self.ensure_top_dir_chain(parent)?;
                self.top().mkdir(parent, name)
            }
            Ok(_) => self.touch(rel_path),
            Err(e) => Err(e),
        }
    }

    pub fn chmod(&self, rel_path: &str, mode: u32) -> io::Result<()> {
        self.ensure_top_copy(rel_path)?;
        let (parent, name) = rel_path.rsplit_once('/').unwrap_or(("", rel_path));
        self.top().set_mode(parent, name, mode)
    }

    pub fn chown(&self, rel_path: &str, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
        self.ensure_top_copy(rel_path)?;
        let (parent, name) = rel_path.rsplit_once('/').unwrap_or(("", rel_path));
        self.top().set_owner(parent, name, uid, gid)
    }

    pub fn remove(&self, parent_rel: &str, name: &str, recursive: bool) -> io::Result<()> {
        let rel_path = child_path(parent_rel, name);
        let info = self.stat(&rel_path)?;
        if info.kind == FileKind::Directory && !recursive {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{rel_path}: is a directory"),
            ));
        }
        let is_dir = info.kind == FileKind::Directory;
        self.ensure_top_dir_chain(parent_rel)?;

        let top_removal = if is_dir {
            self.top().remove_dir_recursive(parent_rel, name)
        } else {
            self.top().remove_file(parent_rel, name)
        };
        if let Err(e) = top_removal {
            if e.kind() != io::ErrorKind::NotFound {
                return Err(e);
            }
        }

        let exists_in_a_lower_layer = self
            .lower_layers()
            .iter()
            .any(|layer| layer.stat(&rel_path).is_ok());
        if exists_in_a_lower_layer {
            self.top().create_whiteout(parent_rel, name)?;
        }
        Ok(())
    }

    fn is_hidden_by_whiteout(&self, rel_path: &str, layer_index: usize) -> bool {
        let components: Vec<&str> = rel_path.split('/').filter(|s| !s.is_empty()).collect();
        for layer in &self.layers[..=layer_index] {
            let mut parent = String::new();
            for component in &components {
                if layer.has_whiteout(&parent, component) {
                    return true;
                }
                parent = child_path(&parent, component);
            }
        }
        false
    }

    pub fn read_file(&self, rel_path: &str) -> io::Result<Vec<u8>> {
        for (i, layer) in self.layers.iter().enumerate() {
            if self.is_hidden_by_whiteout(rel_path, i) {
                return Err(not_found(rel_path));
            }
            match layer.read_file(rel_path) {
                Ok(contents) => return Ok(contents),
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            }
        }
        Err(not_found(rel_path))
    }

    pub fn stat(&self, rel_path: &str) -> io::Result<StatInfo> {
        for (i, layer) in self.layers.iter().enumerate() {
            if self.is_hidden_by_whiteout(rel_path, i) {
                return Err(not_found(rel_path));
            }
            match layer.stat(rel_path) {
                Ok(info) => return Ok(info),
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            }
        }
        Err(not_found(rel_path))
    }

    pub fn read_dir(&self, rel_path: &str) -> io::Result<Vec<String>> {
        let mut visible = std::collections::BTreeSet::new();
        let mut hidden_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut found_in_any_layer = false;

        for (i, layer) in self.layers.iter().enumerate() {
            if self.is_hidden_by_whiteout(rel_path, i) {
                return Err(not_found(rel_path));
            }
            match layer.read_dir(rel_path) {
                Ok(entries) => {
                    found_in_any_layer = true;
                    for name in entries {
                        if let Some(target) = name.strip_prefix(WHITEOUT_PREFIX) {
                            hidden_names.insert(target.to_string());
                            visible.remove(target);
                            continue;
                        }
                        if !hidden_names.contains(&name) {
                            visible.insert(name);
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => continue,
            }
        }
        if !found_in_any_layer {
            return Err(not_found(rel_path));
        }
        Ok(visible.into_iter().collect())
    }
}

fn not_found(rel_path: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("{rel_path}: not found in any layer"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn view_of(dirs: &[&std::path::Path]) -> MountedView {
        MountedView {
            layers: dirs.iter().map(PathBuf::from).collect(),
        }
    }

    #[test]
    fn reads_fall_through_to_a_lower_layer() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::write(bottom.path().join("a.txt"), b"from bottom").unwrap();

        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        assert_eq!(resolver.read_file("a.txt").unwrap(), b"from bottom");
    }

    #[test]
    fn top_layer_shadows_a_lower_layer() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::write(top.path().join("a.txt"), b"from top").unwrap();
        std::fs::write(bottom.path().join("a.txt"), b"from bottom").unwrap();

        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        assert_eq!(resolver.read_file("a.txt").unwrap(), b"from top");
    }

    #[test]
    fn writes_always_land_in_the_top_layer_only() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();

        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        resolver.touch("new.txt").unwrap();

        assert!(top.path().join("new.txt").is_file());
        assert!(!bottom.path().join("new.txt").exists());
    }

    #[test]
    fn touch_copies_a_lower_layer_file_up_instead_of_shadowing_it_empty() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::write(bottom.path().join("a.txt"), b"precious content").unwrap();

        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        resolver.touch("a.txt").unwrap();

        assert_eq!(
            std::fs::read(top.path().join("a.txt")).unwrap(),
            b"precious content"
        );
        assert_eq!(resolver.read_file("a.txt").unwrap(), b"precious content");
    }

    #[test]
    fn touch_on_a_file_already_in_the_top_layer_does_not_touch_lower_layers() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::write(top.path().join("a.txt"), b"top content").unwrap();

        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        resolver.touch("a.txt").unwrap();
        assert_eq!(
            std::fs::read(top.path().join("a.txt")).unwrap(),
            b"top content"
        );
    }

    #[test]
    fn mkdir_refuses_a_name_that_already_exists_in_a_lower_layer() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::create_dir(bottom.path().join("project")).unwrap();

        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        let result = resolver.mkdir("", "project");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert!(
            !top.path().join("project").exists(),
            "must not have created a shadow copy"
        );
    }

    #[test]
    fn mkdir_creates_a_directory_under_a_parent_that_only_exists_in_a_lower_layer() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::create_dir(bottom.path().join("tmp")).unwrap();

        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        resolver.mkdir("tmp", "safeshell-test").unwrap();

        assert_eq!(
            resolver.stat("tmp/safeshell-test").unwrap().kind,
            FileKind::Directory
        );
        assert!(top.path().join("tmp/safeshell-test").is_dir());
    }

    #[test]
    fn touch_creates_a_file_under_a_directory_that_only_exists_in_a_lower_layer() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(bottom.path().join("home/user")).unwrap();

        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        resolver.touch("home/user/new.txt").unwrap();

        assert_eq!(resolver.read_file("home/user/new.txt").unwrap(), b"");
        assert!(top.path().join("home/user/new.txt").is_file());
    }

    #[test]
    fn rm_removes_a_file_whose_parent_directory_only_exists_in_a_lower_layer() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(bottom.path().join("home/user")).unwrap();
        std::fs::write(bottom.path().join("home/user/test.txt"), b"seeded").unwrap();

        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        resolver.remove("home/user", "test.txt", false).unwrap();

        assert_eq!(
            resolver.stat("home/user/test.txt").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(top.path().join("home/user/.wh.test.txt").exists());
    }

    #[test]
    fn read_dir_merges_entries_from_every_layer() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::write(top.path().join("top_only.txt"), b"").unwrap();
        std::fs::write(bottom.path().join("bottom_only.txt"), b"").unwrap();
        std::fs::write(top.path().join("both.txt"), b"top version").unwrap();
        std::fs::write(bottom.path().join("both.txt"), b"bottom version").unwrap();

        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        let entries = resolver.read_dir("").unwrap();
        assert_eq!(
            entries,
            vec![
                "both.txt".to_string(),
                "bottom_only.txt".to_string(),
                "top_only.txt".to_string()
            ]
        );
    }

    #[test]
    fn stat_reports_the_top_layers_version_when_shadowed() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::write(top.path().join("a.txt"), b"12345").unwrap();
        std::fs::write(bottom.path().join("a.txt"), b"1234567890").unwrap();

        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        assert_eq!(resolver.stat("a.txt").unwrap().len, 5);
    }

    #[test]
    fn missing_path_is_not_found_across_the_whole_stack() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();
        assert_eq!(
            resolver.read_file("nope.txt").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn single_layer_view_behaves_like_a_plain_root_resolver() {
        let only = tempfile::tempdir().unwrap();
        std::fs::write(only.path().join("a.txt"), b"solo").unwrap();
        let resolver = LayeredResolver::from_mounted_view(&view_of(&[only.path()])).unwrap();
        assert_eq!(resolver.read_file("a.txt").unwrap(), b"solo");
    }

    #[test]
    fn remove_hides_a_lower_layer_file_from_stat_and_read_file() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::write(bottom.path().join("a.txt"), b"from below").unwrap();
        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();

        resolver.remove("", "a.txt", false).unwrap();

        assert_eq!(
            resolver.read_file("a.txt").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            resolver.stat("a.txt").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(bottom.path().join("a.txt").exists());
    }

    #[test]
    fn remove_of_a_top_layer_only_file_leaves_no_whiteout_marker() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::write(top.path().join("a.txt"), b"only up here").unwrap();
        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();

        resolver.remove("", "a.txt", false).unwrap();

        assert!(
            !top.path().join(".wh.a.txt").exists(),
            "no whiteout is needed when nothing beneath it exists to hide"
        );
        assert_eq!(
            resolver.stat("a.txt").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn remove_without_recursive_refuses_a_directory() {
        let top = tempfile::tempdir().unwrap();
        std::fs::create_dir(top.path().join("project")).unwrap();
        let resolver = LayeredResolver::from_mounted_view(&view_of(&[top.path()])).unwrap();

        let err = resolver.remove("", "project", false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn remove_recursive_hides_a_nested_subtree_from_a_lower_layer() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(bottom.path().join("project")).unwrap();
        std::fs::write(bottom.path().join("project/file.txt"), b"nested").unwrap();
        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();

        resolver.remove("", "project", true).unwrap();

        assert_eq!(
            resolver.stat("project").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            resolver.read_file("project/file.txt").unwrap_err().kind(),
            io::ErrorKind::NotFound,
            "a directory whiteout must hide everything beneath it, not just the directory entry itself"
        );
        assert!(bottom.path().join("project/file.txt").exists());
    }

    #[test]
    fn remove_hides_a_lower_layer_entry_from_read_dir() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::write(bottom.path().join("a.txt"), b"one").unwrap();
        std::fs::write(bottom.path().join("b.txt"), b"two").unwrap();
        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();

        resolver.remove("", "a.txt", false).unwrap();

        let entries = resolver.read_dir("").unwrap();
        assert_eq!(entries, vec!["b.txt".to_string()]);
        assert!(
            !entries.iter().any(|e| e.starts_with(".wh.")),
            "whiteout marker files must never appear as directory entries"
        );
    }

    #[test]
    fn recreating_a_removed_name_through_the_layered_resolver_makes_it_visible_again() {
        let top = tempfile::tempdir().unwrap();
        let bottom = tempfile::tempdir().unwrap();
        std::fs::write(bottom.path().join("a.txt"), b"original").unwrap();
        let resolver =
            LayeredResolver::from_mounted_view(&view_of(&[top.path(), bottom.path()])).unwrap();

        resolver.remove("", "a.txt", false).unwrap();
        assert!(resolver.stat("a.txt").is_err());

        resolver.touch("a.txt").unwrap();

        assert_eq!(resolver.read_file("a.txt").unwrap(), b"");
    }

    #[test]
    fn removing_a_name_that_does_not_exist_anywhere_is_a_not_found_error() {
        let top = tempfile::tempdir().unwrap();
        let resolver = LayeredResolver::from_mounted_view(&view_of(&[top.path()])).unwrap();

        let err = resolver.remove("", "nope.txt", false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}

//! `LayeredResolver` — real filesystem resolution across an ordered stack
//! of layers, composed from `sandbox/worker/resolver.rs`'s `RootResolver`
//! rather than reinventing path-safety logic: each layer gets its own
//! `RootResolver`, so every read/write in this module inherits real
//! `openat2`+`RESOLVE_BENEATH` containment for free (§25.2). This module's
//! only new responsibility is *which layer* handles a given operation —
//! never *how* a single layer is safely resolved.
//!
//! This is what `snapshot/backend.rs`'s module doc named as deferred to
//! this phase: "Building [a merged read/write API over `MountedView`]...
//! is explicitly Build order phase 6's job."
//!
//! **Scope note on writes**: reads fall through the stack top-to-bottom
//! (§14.3's "read-only lower layers are `[W, C_n, ..., base]`"); writes
//! always target the top (index 0) layer only. `touch`/`mkdir` check
//! whether their target already exists lower in the stack and behave
//! accordingly — `touch` copies a lower file's content up before
//! "creating" it (a plain top-layer `O_CREAT` would otherwise shadow the
//! real content with an empty file), `mkdir` refuses to recreate a
//! directory that already exists anywhere in the stack.
//!
//! **Whiteout support** (added for `rm`'s handler — see
//! `sandbox/worker/resolver.rs::WHITEOUT_PREFIX`'s doc comment for the
//! marker convention itself): [`remove`](Self::remove) physically deletes
//! any real copy of the target that exists in the top layer, and — only
//! when the target *also* exists in some lower layer, which can't be
//! deleted for real — leaves a `.wh.<name>` marker in the top layer next
//! to it. Every read method (`stat`, `read_file`, `read_dir`) checks, for
//! each layer top-to-bottom, whether that layer *or any layer above it*
//! has a whiteout covering the target path *or any of its ancestor
//! directories* — [`is_hidden_by_whiteout`](Self::is_hidden_by_whiteout)
//! — before consulting that layer's real content, and stops (reports
//! "not found") the moment one is found, rather than falling through to
//! whatever a deleted directory's lower-layer remnants still contain.
//! One marker per deleted name is enough regardless of how much it
//! contained: a directory's whiteout hides its entire subtree, exactly
//! like a real overlay filesystem's opaque-directory semantics, so
//! nothing inside a deleted directory ever needs its own marker.

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
    /// Top to bottom, matching `MountedView.layers`'s ordering — index 0
    /// is the sole writable layer.
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

    /// Best-effort cleanup after creating a real `<name>` in the top
    /// layer: removes a same-layer `.wh.<name>` marker if one happens to
    /// be present, so a whiteout can never coexist with the real entry it
    /// was recording the absence of. In the real pipeline this is
    /// normally a harmless no-op (`rm` and a later `touch`/`mkdir` of the
    /// same name are always separate transactions, sealed into separate
    /// layers by the time the second one runs) — but `LayeredResolver` is
    /// tested and usable standalone, where "remove, then re-create, in
    /// the same layer" is a real, reachable sequence, and without this
    /// cleanup the stale marker would make the freshly re-created entry
    /// invisible again (`is_hidden_by_whiteout` stops at the first
    /// whiteout it finds, before ever checking that layer's real
    /// content).
    fn clear_stale_whiteout(&self, parent_rel: &str, name: &str) {
        let _ = self
            .top()
            .remove_file(parent_rel, &format!("{WHITEOUT_PREFIX}{name}"));
    }

    /// Copies up empty directory *shells* (no content) for every ancestor
    /// of `dir_rel` that exists somewhere in the stack but not yet in the
    /// top layer. This is the piece the module doc's "writes always
    /// target the top layer" scope note glossed over: every write here
    /// ultimately reaches `RootResolver`'s `openat2`+`RESOLVE_BENEATH`
    /// *within the top layer alone* (the union view is a read-side
    /// construct only), so on a fresh session — before anything has been
    /// written under it — a directory seeded only in `base` (which is
    /// every directory in the seeded image, e.g. `home/user`, `tmp`) has
    /// no real counterpart for the kernel to resolve `parent_rel`
    /// against, and the underlying `openat2` call fails with `ENOENT`
    /// before the write it's spelling out ever runs. `touch`'s own
    /// lower-layer-content copy-up handles a *file's* content the moment
    /// something is actually created there; this handles the directories
    /// leading up to it, which needed the same treatment but never got
    /// it. Whiteout-aware via `stat` — a directory `rm -r`'d earlier is
    /// correctly left un-recreated, matching `mkdir`'s own contract.
    fn ensure_top_dir_chain(&self, dir_rel: &str) -> io::Result<()> {
        let mut parent = String::new();
        for component in dir_rel.split('/').filter(|s| !s.is_empty()) {
            let child = child_path(&parent, component);
            if self.top().stat(&child).is_err() {
                match self.stat(&child) {
                    Ok(info) if info.kind == FileKind::Directory => {
                        self.top().mkdir(&parent, component)?;
                    }
                    // Doesn't exist anywhere, or exists as a non-directory
                    // — either way, not this helper's job to report; the
                    // caller's own real operation will surface the right
                    // error against the path it actually cares about.
                    _ => return Ok(()),
                }
            }
            parent = child;
        }
        Ok(())
    }

    /// `touch`: a no-op if the target already exists in the top layer
    /// (matching `RootResolver::touch`'s own contract); if it exists only
    /// in a lower layer, copies its content up first rather than shadowing
    /// it with an empty file (see module doc); otherwise, an ordinary
    /// create. Reuses [`read_file`](Self::read_file)'s own whiteout-aware
    /// fallthrough (rather than walking `lower_layers()` directly) so
    /// re-creating a file after a `rm` doesn't accidentally copy up a
    /// stale, supposedly-deleted lower-layer version that a whiteout is
    /// hiding.
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

    /// `mkdir`: refuses if the target already exists anywhere in the
    /// stack (matching real `mkdir`'s `EEXIST` behavior — without this
    /// check, a directory that already exists in a lower layer would
    /// silently and pointlessly get an empty shadow copy in the top
    /// layer). Uses [`stat`](Self::stat), which is whiteout-aware, so a
    /// directory `rm -r`'d earlier is correctly re-creatable.
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

    /// `write_file`: creates or overwrites `rel_path` in the top layer with
    /// exactly `contents`, regardless of what (if anything) exists at that
    /// path in a lower layer — the top layer always wins on a write, same
    /// as `touch`/`mkdir`. Used by redirection (`>`/`>>`) and by `cp`/`mv`,
    /// which read a source's bytes via [`read_file`](Self::read_file) and
    /// hand them here rather than needing a new cross-layer "copy"
    /// primitive of their own.
    pub fn write_file(&self, rel_path: &str, contents: &[u8]) -> io::Result<()> {
        let (parent, name) = rel_path.rsplit_once('/').unwrap_or(("", rel_path));
        self.ensure_top_dir_chain(parent)?;
        let result = self.top().write_new_file(rel_path, contents);
        if result.is_ok() {
            self.clear_stale_whiteout(parent, name);
        }
        result
    }

    /// `chmod`/`chown`: like `write_file`, these are mutations that must
    /// land for real in the top layer for the change to be visible (a
    /// lower layer is sealed/read-only checkpoint content) — but unlike
    /// `write_file`, there's no content to copy up: if `<name>` doesn't
    /// already have a real copy in the top layer, `touch`'s own copy-up
    /// (content-preserving) is reused first so the mode/owner change
    /// applies to a full copy of the file, not an empty shell that would
    /// silently lose the lower layer's content.
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

    /// `rm`: removes `<name>` under `parent_rel`. `recursive` gates
    /// directories only (matching real `rm`'s `-r`/`rmdir` split) — a
    /// file is always removable regardless of the flag. Physically
    /// deletes any real copy in the top layer; if `<name>` also exists in
    /// a lower layer (which can't be deleted for real — it may be
    /// checkpointed, shared, or part of the base image), leaves a single
    /// whiteout marker there instead of walking and marking every
    /// descendant individually (see module doc).
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

        // Best-effort: remove any real, top-layer-local copy. `NotFound`
        // there is expected and fine — the content may live only in a
        // lower layer, which is exactly what the whiteout below is for.
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

    /// Whether `rel_path` — or any of its ancestor directories — has been
    /// recorded as deleted in `self.layers[..=layer_index]` (this layer
    /// or any layer above it in resolution order). A whiteout at any
    /// ancestor hides everything beneath it, so this walks every prefix
    /// of `rel_path`, not just the exact path, checking each against
    /// every layer from the top down to (and including) `layer_index`.
    /// Callers stop falling through entirely the moment this returns
    /// true — deeper layers' real content must never become visible
    /// again once something above has recorded it as gone.
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

    /// Read fallthrough: the first layer (top to bottom) where `rel_path`
    /// resolves to something readable wins, unless a whiteout at or above
    /// that layer hides it first (see module doc). An entry that exists
    /// in a higher layer as the *wrong kind* (e.g. a directory shadowing a
    /// lower-layer file of the same name) is intentionally **not** skipped
    /// in favor of the lower one — that shadowing is correct union
    /// semantics, not a fallthrough case.
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

    /// Merged listing across every layer (union of names, deduplicated),
    /// whiteout-aware in both directions: a name whited out by a higher
    /// layer never appears even if a lower layer still really has it, and
    /// the whiteout marker files themselves (`.wh.*`) are never shown as
    /// entries — they're this module's own bookkeeping, not user content.
    /// A single top-to-bottom pass is enough (rather than re-scanning
    /// higher layers per lower one): whiteouts accumulate as the layers
    /// are visited in priority order, so by the time a lower layer's
    /// entries are considered, every higher-layer whiteout that could
    /// affect them has already been recorded. Errors only if `rel_path`
    /// doesn't resolve to a directory in **any** layer, or is itself
    /// hidden by a whiteout.
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
                // A layer where rel_path exists but isn't a directory
                // (e.g. ENOTDIR) is also just "not a directory here" —
                // still worth trying the remaining layers rather than
                // failing outright, since a higher layer's non-directory
                // entry already shadows this one via `stat`/`read_file`'s
                // own fallthrough; `read_dir` callers only reach this path
                // when they already expect a directory.
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

        // The copy-up must have happened: the top layer now has the real
        // content, not an empty file.
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
        // Regression: every directory in a freshly seeded session lives
        // only in the base layer until something is written under it —
        // `mkdir`/`touch`/`remove` must copy up the parent directory
        // shell before asking the top layer's `RootResolver` to resolve
        // into it, or this fails with `ENOENT` even though the target
        // path is entirely valid.
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

    // --- rm / whiteout ---

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
        // The lower layer's real file must be untouched — only hidden.
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
        // The lower layer's real content must be untouched — only hidden.
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

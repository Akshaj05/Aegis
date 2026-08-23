//! CI-enforced check for docs/CLAUDE.md invariant #7 / docs/architecture.md
//! §21.3: `policy/`, `executor/`, and `rollback/` must never depend on
//! `ai/`. This is a text scan over the source tree rather than a real
//! compiler-enforced crate boundary, because the crate is currently laid
//! out as a single crate with submodules (matching docs/architecture.md
//! §40's repository structure) rather than a Cargo workspace with one crate
//! per module — see `src/lib.rs`'s module doc for why that trade-off was
//! made. If this check starts feeling insufficient, the fix is to split the
//! offending module into its own crate so Cargo enforces the boundary,
//! not to weaken this scan.

use std::fs;
use std::path::Path;

mod must_not_be_denied;

const GUARDED_MODULES: &[&str] = &["policy", "executor", "rollback"];

#[test]
fn guarded_modules_never_reference_ai_module() {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut violations = Vec::new();
    for module in GUARDED_MODULES {
        let module_dir = src_root.join(module);
        assert!(module_dir.is_dir(), "expected src/{module}/ to exist");
        scan_dir_for_ai_references(&module_dir, &mut violations);
    }

    assert!(
        violations.is_empty(),
        "found forbidden references to the `ai` module in security-critical \
         code (docs/CLAUDE.md invariant #7 — policy/, executor/, and \
         rollback/ must not depend on ai/):\n{}",
        violations.join("\n")
    );
}

fn scan_dir_for_ai_references(dir: &Path, violations: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("readable module directory") {
        let entry = entry.expect("readable dir entry");
        let path = entry.path();
        if path.is_dir() {
            scan_dir_for_ai_references(&path, violations);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }

        let contents = fs::read_to_string(&path).expect("readable source file");
        for (line_no, line) in contents.lines().enumerate() {
            let trimmed = line.trim_start();
            // Skip doc/comment lines so this check's own explanatory prose
            // (and any future one) doesn't trip itself.
            if trimmed.starts_with("//") {
                continue;
            }
            if line.contains("crate::ai") || line.contains("super::ai") || references_ai_use(line) {
                violations.push(format!(
                    "{}:{}: {}",
                    path.display(),
                    line_no + 1,
                    line.trim()
                ));
            }
        }
    }
}

fn references_ai_use(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("use ai::")
        || trimmed.starts_with("use ai;")
        || trimmed.starts_with("mod ai")
}

#[test]
fn guarded_module_list_matches_lib_rs_module_declarations() {
    // Guards against the guarded-module list silently going stale if
    // policy/executor/rollback are ever renamed.
    let lib_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let contents = fs::read_to_string(&lib_rs).expect("readable src/lib.rs");
    for module in GUARDED_MODULES {
        assert!(
            contents.contains(&format!("pub mod {module};")),
            "src/lib.rs no longer declares `pub mod {module};` — update GUARDED_MODULES in this test"
        );
    }
}

//! Sidecar binary: a thin wrapper around the real `uu_wc` crate's entry
//! point. See `src/handlers/coreutils_proc.rs`'s module doc for why this
//! exists as a separate spawned process rather than an in-process call —
//! `uumain` reads/writes real process-global stdin/stdout, which is only
//! safe to hand to it as a private, per-invocation OS pipe pair, never
//! shared with SafeShell's own multi-session process.

fn main() {
    let args = std::iter::once(std::ffi::OsString::from("wc")).chain(std::env::args_os().skip(1));
    std::process::exit(uu_wc::uumain(args));
}

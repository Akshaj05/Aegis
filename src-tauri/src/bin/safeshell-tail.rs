//! Sidecar binary: a thin wrapper around the real `uu_tail` crate's entry
//! point. See `src/bin/safeshell-wc.rs`'s doc comment for why this exists
//! as a separate spawned process. SafeShell only ever invokes this
//! non-interactively with `-f`/`-F` (follow) omitted — see
//! `handlers/text_filters.rs::cmd_tail`.

fn main() {
    let args = std::iter::once(std::ffi::OsString::from("tail")).chain(std::env::args_os().skip(1));
    std::process::exit(uu_tail::uumain(args));
}

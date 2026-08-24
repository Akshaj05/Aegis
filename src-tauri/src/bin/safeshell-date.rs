//! Sidecar binary: a thin wrapper around the real `uu_date` crate's entry
//! point. See `src/bin/safeshell-wc.rs`'s doc comment for why this exists
//! as a separate spawned process. SafeShell never passes `-s`/`--set`
//! (which would change the host's real clock) — see
//! `handlers/text_filters.rs::cmd_date`.

fn main() {
    let args = std::iter::once(std::ffi::OsString::from("date")).chain(std::env::args_os().skip(1));
    std::process::exit(uu_date::uumain(args));
}

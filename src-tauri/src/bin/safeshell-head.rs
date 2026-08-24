//! Sidecar binary: a thin wrapper around the real `uu_head` crate's entry
//! point. See `src/bin/safeshell-wc.rs`'s doc comment for why this exists
//! as a separate spawned process.

fn main() {
    let args = std::iter::once(std::ffi::OsString::from("head")).chain(std::env::args_os().skip(1));
    std::process::exit(uu_head::uumain(args));
}

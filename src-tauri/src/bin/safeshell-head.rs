// Sidecar binary: thin wrapper spawning the real uu_head crate's entry
// point as a separate process.

fn main() {
    let args = std::iter::once(std::ffi::OsString::from("head")).chain(std::env::args_os().skip(1));
    std::process::exit(uu_head::uumain(args));
}

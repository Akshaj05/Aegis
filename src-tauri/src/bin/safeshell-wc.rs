// Sidecar binary: thin wrapper spawning the real uu_wc crate's entry
// point as a separate process.

fn main() {
    let args = std::iter::once(std::ffi::OsString::from("wc")).chain(std::env::args_os().skip(1));
    std::process::exit(uu_wc::uumain(args));
}

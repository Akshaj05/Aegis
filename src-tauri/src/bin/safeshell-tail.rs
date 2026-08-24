// Sidecar binary: thin wrapper spawning the real uu_tail crate's entry
// point as a separate process.

fn main() {
    let args = std::iter::once(std::ffi::OsString::from("tail")).chain(std::env::args_os().skip(1));
    std::process::exit(uu_tail::uumain(args));
}

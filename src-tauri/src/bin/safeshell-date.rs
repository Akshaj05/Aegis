// Sidecar binary: thin wrapper spawning the real uu_date crate's entry
// point as a separate process.

fn main() {
    let args = std::iter::once(std::ffi::OsString::from("date")).chain(std::env::args_os().skip(1));
    std::process::exit(uu_date::uumain(args));
}

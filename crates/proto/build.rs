// crates/proto/build.rs
// Dummy build script agar cargo tidak error.
// Tidak perlu generate proto di sini, karena build.rs di storage yang akan melakukannya.

fn main() {
    // kalau nanti file proto diubah, ini memastikan cargo re-run build.
    println!("cargo:rerun-if-changed=proto/api.proto");
}

fn main() {
    println!("cargo:rerun-if-changed=proto/api.proto");
}

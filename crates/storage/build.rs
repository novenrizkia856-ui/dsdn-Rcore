// crates/storage/build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Path relatif dari posisi crate storage
    let proto_file = "../proto/proto/api.proto";
    let proto_dir = "../proto/proto";

    println!("cargo:rerun-if-changed={}", proto_file);
    println!("cargo:rerun-if-changed={}", proto_dir);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&[proto_file], &[proto_dir])?;

    println!("cargo:warning=✅ Proto compiled successfully from {}", proto_file);

    Ok(())
}

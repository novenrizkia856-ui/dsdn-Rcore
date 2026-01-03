fn main() -> Result<(), Box<dyn std::error::Error>> {
    // path relative ke crate storage root: ../proto/proto/api.proto
    let proto = "../proto/proto/api.proto";
    let proto_dir = "../proto/proto";

    tonic_build::configure()
        .build_server(true)
        .compile(&[proto], &[proto_dir])?;

    Ok(())
}

use std::env;
use tonic::Request;
use wat::parse_str as wat_parse;

use dsdn_storage::proto::RunWasmRequest;
use dsdn_storage::proto::runtime_client::RuntimeClient;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Note: this bin is part of the crate, so it can use crate::proto defined in lib.rs
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: run_wasm_client <node_addr:port> <module_wat_file> <module_hash_on_node>");
        std::process::exit(2);
    }
    let addr = args[1].clone(); // e.g., 127.0.0.1:50051
    let module_path = &args[2];
    let module_hash = args[3].clone();

    let wat = std::fs::read_to_string(module_path)?;
    let _wasm = wat_parse(&wat)?; // just validate WAT locally, but we assume module is stored on node already

    let mut client = RuntimeClient::connect(format!("http://{}", addr)).await?;
    let req = RunWasmRequest {
        module_hash: module_hash.clone(),
        input: vec![],
        timeout_ms: 2000,
        max_mem_bytes: 65536,
    };

    let resp = client.run_wasm(Request::new(req)).await?;
    let inner = resp.into_inner();
    println!("status: {}", inner.status);
    println!("output ({} bytes):", inner.output.len());
    println!("{}", String::from_utf8_lossy(&inner.output));
    Ok(())
}

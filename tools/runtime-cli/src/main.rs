use dsdn_storage::proto::{
    runtime_client::RuntimeClient,
    RunWasmRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: runtime-cli <node_addr> <module_hash> [input]");
        std::process::exit(1);
    }

    let node_addr = &args[1];
    let module_hash = &args[2];
    let input = if args.len() >= 4 {
        args[3].clone().into_bytes()
    } else {
        Vec::new()
    };

    let mut client = RuntimeClient::connect(format!("http://{}", node_addr)).await?;

    let req = RunWasmRequest {
        module_hash: module_hash.clone(),
        input,
        timeout_ms: 3000,
        max_mem_bytes: 1024 * 1024, 
    };

    let resp = client.run_wasm(req).await?.into_inner();

    println!("status : {}", resp.status);
    println!("output : {:?}", String::from_utf8_lossy(&resp.output));

    Ok(())
}

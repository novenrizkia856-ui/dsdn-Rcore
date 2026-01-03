use std::env;
use std::path::Path;
use std::sync::Arc;
use std::net::SocketAddr;

use tokio::sync::Notify;

use dsdn_common::cid::sha256_hex;
use dsdn_storage::localfs::LocalFsStorage;
use dsdn_storage::chunker;
use dsdn_storage::rpc;
use dsdn_storage::store::Storage;

fn print_usage_and_exit() {
    eprintln!("Usage:");
    eprintln!("  storage-cli server <addr>            # run gRPC server (e.g. 127.0.0.1:50051)");
    eprintln!("  storage-cli put <file> [chunk_size]  # local put (same as before)");
    eprintln!("  storage-cli send <addr> <file>       # send file chunks to remote gRPC server");
    std::process::exit(2);
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage_and_exit();
    }

    match args[1].as_str() {
        "server" => {
            if args.len() != 3 {
                print_usage_and_exit();
            }

            let addr: SocketAddr = args[2].parse().expect("invalid address");
            let store = Arc::new(LocalFsStorage::new("./data").expect("failed to create ./data"));
            let shutdown_notify = Arc::new(Notify::new());

            println!("🚀 Starting DSDN Storage gRPC server at {}", addr);
            println!("Press Ctrl+C to stop.");

            let s_notify = shutdown_notify.clone();
            let st = store.clone();
            let server_task = tokio::spawn(async move {
                if let Err(e) = rpc::run_server(addr, st, s_notify).await {
                    eprintln!("server error: {}", e);
                }
            });

            tokio::signal::ctrl_c().await.expect("failed to wait ctrl-c");
            println!("Shutdown signal received, stopping...");
            shutdown_notify.notify_waiters();
            let _ = server_task.await;
            println!("Server stopped cleanly.");
        }

        "put" => {
            if args.len() < 3 {
                print_usage_and_exit();
            }

            let file = Path::new(&args[2]);
            if !file.exists() {
                eprintln!("file not found: {:?}", file);
                std::process::exit(1);
            }

            let chunk_size = if args.len() >= 4 {
                args[3].parse::<usize>().unwrap_or(16 * 1024 * 1024)
            } else {
                16 * 1024 * 1024
            };

            let mut f = std::fs::File::open(file).expect("open file");
            let chunks = chunker::chunk_reader(&mut f, chunk_size).expect("chunk file");
            let store = LocalFsStorage::new("./data").expect("create store at ./data");

            println!("📦 Uploading {} chunks (chunk_size = {})", chunks.len(), chunk_size);
            for (i, chunk) in chunks.into_iter().enumerate() {
                let h = sha256_hex(&chunk);
                store.put_chunk(&h, &chunk).expect("put chunk");
                println!("chunk {:>4}: {} ({} bytes)", i, h, chunk.len());
            }
            println!("✅ Done storing locally.");
        }

        "send" => {
            if args.len() != 4 {
                print_usage_and_exit();
            }

            let addr = args[2].clone(); // e.g. 127.0.0.1:50051
            let file = Path::new(&args[3]);
            if !file.exists() {
                eprintln!("file not found: {:?}", file);
                std::process::exit(1);
            }

            let mut f = std::fs::File::open(file).expect("open file");
            let chunks = chunker::chunk_reader(&mut f, 16 * 1024 * 1024).expect("chunk file");

            println!("📤 Sending {} chunks to {}", chunks.len(), addr);

            for (i, chunk) in chunks.into_iter().enumerate() {
                let h = sha256_hex(&chunk);
                match rpc::client_put(format!("http://{}", addr), h.clone(), chunk).await {
                    Ok(returned) => println!("chunk {:>4}: sent, hash {}", i, returned),
                    Err(e) => eprintln!("❌ failed to send chunk {}: {}", i, e),
                }
            }
            println!("✅ File transfer done.");
        }

        _ => print_usage_and_exit(),
    }
}

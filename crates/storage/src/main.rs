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
    eprintln!("DSDN Storage CLI");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  storage-cli server <addr>                    Run gRPC server (e.g. 127.0.0.1:50051)");
    eprintln!("  storage-cli put <file> [chunk_size]          Chunk file & store locally in ./data");
    eprintln!("  storage-cli get <hash>                       Get chunk from local store");
    eprintln!("  storage-cli has <hash>                       Check if chunk exists locally");
    eprintln!("  storage-cli send <addr> <file>               Send file chunks to remote gRPC server");
    eprintln!("  storage-cli fetch <addr> <hash> [output]     Fetch chunk from remote gRPC server");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  storage-cli server 127.0.0.1:50051");
    eprintln!("  storage-cli put myfile.dat 4194304");
    eprintln!("  storage-cli get abc123def456...");
    eprintln!("  storage-cli send 127.0.0.1:50051 myfile.dat");
    eprintln!("  storage-cli fetch 127.0.0.1:50051 abc123def456... output.bin");
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
                eprintln!("❌ file not found: {:?}", file);
                std::process::exit(1);
            }

            let chunk_size = if args.len() >= 4 {
                args[3].parse::<usize>().unwrap_or(chunker::DEFAULT_CHUNK_SIZE)
            } else {
                chunker::DEFAULT_CHUNK_SIZE
            };

            let mut f = std::fs::File::open(file).expect("open file");
            let chunks = chunker::chunk_reader(&mut f, chunk_size).expect("chunk file");
            let store = LocalFsStorage::new("./data").expect("create store at ./data");

            println!("📦 Uploading {} chunks (chunk_size = {})", chunks.len(), chunk_size);
            for (i, chunk) in chunks.into_iter().enumerate() {
                let h = sha256_hex(&chunk);
                store.put_chunk(&h, &chunk).expect("put chunk");
                println!("  chunk {:>4}: {} ({} bytes)", i, h, chunk.len());
            }
            println!("✅ Done storing locally in ./data");
        }

        "get" => {
            if args.len() < 3 {
                eprintln!("Usage: storage-cli get <hash> [output_file]");
                std::process::exit(2);
            }

            let hash = &args[2];
            let store = LocalFsStorage::new("./data").expect("create store at ./data");

            match store.get_chunk(hash) {
                Ok(Some(data)) => {
                    if args.len() >= 4 {
                        let output = &args[3];
                        std::fs::write(output, &data).expect("write output");
                        println!("✅ Chunk {} ({} bytes) → {}", hash, data.len(), output);
                    } else {
                        println!("✅ Chunk found: {} ({} bytes)", hash, data.len());
                        if data.len() <= 1024 {
                            if let Ok(text) = std::str::from_utf8(&data) {
                                println!("Content: {}", text);
                            } else {
                                let hex: String = data.iter().take(64).map(|b| format!("{:02x}", b)).collect();
                                println!("Content (hex): {}...", hex);
                            }
                        } else {
                            let hex: String = data.iter().take(64).map(|b| format!("{:02x}", b)).collect();
                            println!("Content (hex, first 64 bytes): {}...", hex);
                        }
                    }
                }
                Ok(None) => {
                    eprintln!("❌ Chunk not found: {}", hash);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("❌ Storage error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        "has" => {
            if args.len() < 3 {
                eprintln!("Usage: storage-cli has <hash>");
                std::process::exit(2);
            }

            let hash = &args[2];
            let store = LocalFsStorage::new("./data").expect("create store at ./data");

            match store.has_chunk(hash) {
                Ok(true) => println!("✅ Chunk exists: {}", hash),
                Ok(false) => {
                    println!("❌ Chunk not found: {}", hash);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("❌ Storage error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        "send" => {
            if args.len() != 4 {
                print_usage_and_exit();
            }

            let addr = args[2].clone(); // e.g. 127.0.0.1:50051
            let file = Path::new(&args[3]);
            if !file.exists() {
                eprintln!("❌ file not found: {:?}", file);
                std::process::exit(1);
            }

            let mut f = std::fs::File::open(file).expect("open file");
            let chunks = chunker::chunk_reader(&mut f, chunker::DEFAULT_CHUNK_SIZE).expect("chunk file");

            println!("📤 Sending {} chunks to {}", chunks.len(), addr);

            for (i, chunk) in chunks.into_iter().enumerate() {
                let h = sha256_hex(&chunk);
                match rpc::client_put(format!("http://{}", addr), h.clone(), chunk).await {
                    Ok(returned) => println!("  chunk {:>4}: sent → {}", i, returned),
                    Err(e) => eprintln!("❌ failed to send chunk {}: {}", i, e),
                }
            }
            println!("✅ File transfer done.");
        }

        "fetch" => {
            if args.len() < 4 {
                eprintln!("Usage: storage-cli fetch <addr> <hash> [output_file]");
                std::process::exit(2);
            }

            let addr = args[2].clone();
            let hash = args[3].clone();

            println!("📥 Fetching chunk {} from {}", hash, addr);

            match rpc::client_get(format!("http://{}", addr), hash.clone()).await {
                Ok(Some(data)) => {
                    if args.len() >= 5 {
                        let output = &args[4];
                        std::fs::write(output, &data).expect("write output");
                        println!("✅ Fetched {} ({} bytes) → {}", hash, data.len(), output);
                    } else {
                        println!("✅ Fetched {} ({} bytes)", hash, data.len());
                        if data.len() <= 1024 {
                            if let Ok(text) = std::str::from_utf8(&data) {
                                println!("Content: {}", text);
                            }
                        }
                    }
                }
                Ok(None) => {
                    eprintln!("❌ Chunk not found on remote: {}", hash);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("❌ gRPC error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        "--help" | "-h" | "help" => print_usage_and_exit(),

        _ => print_usage_and_exit(),
    }
}
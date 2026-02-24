//! # DSDN Node Entry Point (Mainnet Ready)
//!
//! Production entry point for DSDN storage node.
//!
//! ## Key Invariant
//! Node TIDAK menerima instruksi dari Coordinator via RPC.
//! Semua perintah datang via DA events.
//!
//! ## Storage Integration
//!
//! Node menggunakan `LocalFsStorage` dari `dsdn_storage` untuk penyimpanan
//! chunk data yang sebenarnya. Storage diakses melalui:
//! - gRPC server (untuk inter-node replication dan client access)
//! - HTTP endpoints (untuk observability dan basic chunk access)
//! - CLI subcommands (untuk operasi manual)
//!
//! ## Environment File Loading
//!
//! The node automatically loads configuration from environment files
//! (same pattern as coordinator):
//!
//! 1. `DSDN_ENV_FILE` environment variable (custom path)
//! 2. `.env.mainnet` (production default - **DSDN defaults to mainnet**)
//! 3. `.env` (fallback for development)
//!
//! ## CLI Subcommands
//!
//! ### `dsdn-node run [env | <node-id> <da-endpoint> <storage-path> <http-port>]`
//! Start the node. Default mode is `env` (reads from .env.mainnet).
//!
//! ### `dsdn-node status [--port PORT]`
//! Query a running node's status via HTTP.
//!
//! ### `dsdn-node health [--port PORT]`
//! Query a running node's health endpoint via HTTP.
//!
//! ### `dsdn-node info`
//! Display node build and configuration info.
//!
//! ### `dsdn-node version`
//! Display version string.
//!
//! ### `dsdn-node store put <file> [chunk_size]`
//! Chunk a file and store locally.
//!
//! ### `dsdn-node store get <hash> [output_file]`
//! Retrieve a chunk from local storage.
//!
//! ### `dsdn-node store has <hash>`
//! Check if a chunk exists in local storage.
//!
//! ### `dsdn-node store send <grpc-addr> <file>`
//! Send file chunks to a remote node via gRPC.
//!
//! ### `dsdn-node store stats`
//! Show local storage statistics.
//!
//! ## Initialization Flow (run)
//! 1. Load .env.mainnet (or custom env file)
//! 2. Parse configuration (CLI or env)
//! 3. Validate configuration
//! 4. Initialize DA layer with startup health check
//! 5. Initialize storage (LocalFsStorage)
//! 6. Initialize DA follower
//! 7. Start gRPC storage server
//! 8. Start HTTP server (Axum - observability + storage endpoints)
//! 9. Start follower task

use std::env;

use tracing::{info, Level};

mod cli;

// ════════════════════════════════════════════════════════════════════════════
// VERSION & BUILD INFO
// ════════════════════════════════════════════════════════════════════════════

const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");
const NODE_NAME: &str = "dsdn-node";

/// Default gRPC port offset from HTTP port.
const DEFAULT_GRPC_PORT_OFFSET: u16 = 1000;

// ════════════════════════════════════════════════════════════════════════════
// MAIN
// ════════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let prog = &args[0];

    // ─────────────────────────────────────────────────────────────────────
    // Step 0: Load environment from .env.mainnet (or custom env file)
    // This happens BEFORE anything else, same pattern as coordinator.
    // ─────────────────────────────────────────────────────────────────────
    cli::load_env_file();

    // Determine subcommand
    let subcommand = args.get(1).map(|s| s.as_str());

    match subcommand {
        // ── version ──────────────────────────────────────────────────────
        Some("version") | Some("--version") | Some("-V") => {
            cli::cmd_version();
        }

        // ── info ─────────────────────────────────────────────────────────
        Some("info") => {
            cli::cmd_info();
        }

        // ── status ───────────────────────────────────────────────────────
        Some("status") => {
            let port = cli::parse_port_flag(&args[2..]);
            cli::cmd_status(port).await;
        }

        // ── health ───────────────────────────────────────────────────────
        Some("health") => {
            let port = cli::parse_port_flag(&args[2..]);
            cli::cmd_health(port).await;
        }

        // ── store ────────────────────────────────────────────────────────
        Some("store") => {
            let store_sub = args.get(2).map(|s| s.as_str());
            let store_args: Vec<String> = if args.len() > 3 {
                args[3..].to_vec()
            } else {
                vec![]
            };

            match store_sub {
                Some("put") => cli::cmd_store_put(&store_args),
                Some("get") => cli::cmd_store_get(&store_args),
                Some("has") => cli::cmd_store_has(&store_args),
                Some("stats") => cli::cmd_store_stats(),
                Some("send") => {
                    // Need async runtime for gRPC
                    cli::cmd_store_send(&store_args).await;
                }
                Some("fetch") => {
                    cli::cmd_store_fetch(&store_args).await;
                }
                _ => {
                    eprintln!("Usage: dsdn-node store <put|get|has|stats|send|fetch> [args...]");
                    eprintln!();
                    eprintln!("Subcommands:");
                    eprintln!("  put <file> [chunk_size]             Chunk file & store locally");
                    eprintln!("  get <hash> [output_file]            Get chunk from local store");
                    eprintln!("  has <hash>                          Check if chunk exists");
                    eprintln!("  stats                               Show storage statistics");
                    eprintln!("  send <grpc-addr> <file>             Send file chunks via gRPC");
                    eprintln!("  fetch <grpc-addr> <hash> [output]   Fetch chunk from remote");
                    std::process::exit(2);
                }
            }
        }

        // ── run (explicit) ──────────────────────────────────────────────
        Some("run") => {
            // Initialize tracing for run mode
            tracing_subscriber::fmt()
                .with_max_level(Level::INFO)
                .with_target(false)
                .init();

            let run_args = &args[2..];
            cli::cmd_run(run_args.to_vec().as_slice()).await;
        }

        // ── backward compatibility: `dsdn-node env` ─────────────────────
        Some("env") => {
            tracing_subscriber::fmt()
                .with_max_level(Level::INFO)
                .with_target(false)
                .init();

            cli::cmd_run(&[]).await;
        }

        // ── backward compatibility: `dsdn-node <node-id> <da> <path> <port>` ──
        // If first arg is not a known subcommand, treat as legacy CLI mode
        Some(first_arg) if !first_arg.starts_with('-') => {
            tracing_subscriber::fmt()
                .with_max_level(Level::INFO)
                .with_target(false)
                .init();

            // Pass all args after program name as run args (legacy mode)
            cli::cmd_run(&args[1..]).await;
        }

        // ── help ─────────────────────────────────────────────────────────
        Some("--help") | Some("-h") | Some("help") => {
            cli::print_usage(prog);
        }

        // ── no args → default to `run env` ──────────────────────────────
        None => {
            tracing_subscriber::fmt()
                .with_max_level(Level::INFO)
                .with_target(false)
                .init();

            info!("No subcommand specified, defaulting to 'run' (env mode)");
            cli::cmd_run(&[]).await;
        }

        _ => {
            cli::print_usage(prog);
            std::process::exit(1);
        }
    }
}
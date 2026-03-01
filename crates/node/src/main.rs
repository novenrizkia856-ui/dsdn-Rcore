//! # DSDN Node Entry Point (Mainnet Ready)
//!
//! Production entry point for DSDN storage node.
//!
//! ## Key Invariant
//! Node TIDAK menerima instruksi dari Coordinator via RPC.
//! Semua perintah datang via DA events (Celestia).
//!
//! ## CLI Usage
//!
//! ```bash
//! # Start the node server
//! dsdn-node run --node-id node-1 --da-rpc-url http://localhost:26658 \
//!     --da-namespace <HEX> --storage-path ./data --http-port 45832
//!
//! # Development mode (mock DA)
//! dsdn-node run --node-id auto --mock-da --storage-path ./data --http-port 45832
//!
//! # Query running node
//! dsdn-node status [-p 45832]
//! dsdn-node health [-p 45832]
//!
//! # Storage operations
//! dsdn-node store put <file> [--chunk-size 65536]
//! dsdn-node store get <hash> [-o output.dat]
//! dsdn-node store has <hash>
//! dsdn-node store stats
//! dsdn-node store send <grpc-addr> <file>
//! dsdn-node store fetch <grpc-addr> <hash> [-o output.dat]
//!
//! # Info
//! dsdn-node info
//! dsdn-node version
//! ```

use clap::Parser;
use tracing::Level;

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
    // Pre-load env file BEFORE clap parsing so env fallbacks work.
    cli::load_env_file();

    // Parse CLI arguments (clap)
    let parsed = cli::Cli::parse();

    // Commands that don't need tracing
    match &parsed.command {
        Some(cli::Command::Version) => {
            cli::cmd_version();
            return;
        }
        Some(cli::Command::Info) => {
            cli::cmd_info();
            return;
        }
        _ => {}
    }

    // Initialize tracing for all other commands
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    // Dispatch
    match parsed.command {
        Some(cli::Command::Run(args)) => {
            cli::cmd_run(&args).await;
        }
        Some(cli::Command::Status(args)) => {
            cli::cmd_status(&args).await;
        }
        Some(cli::Command::Health(args)) => {
            cli::cmd_health(&args).await;
        }
        Some(cli::Command::Store(cmd)) => {
            cli::cmd_store(cmd).await;
        }
        // No subcommand → default to `run` with env-var defaults
        None => {
            tracing::info!("No subcommand specified, defaulting to 'run' (env mode)...");
            // Re-parse with "run" injected so clap env-fallbacks apply
            let mut argv: Vec<String> = std::env::args().collect();
            argv.insert(1, "run".to_string());
            let cli_run = cli::Cli::parse_from(argv);
            if let Some(cli::Command::Run(run_args)) = cli_run.command {
                cli::cmd_run(&run_args).await;
            }
        }
        // Version/Info already handled above
        _ => unreachable!(),
    }
}
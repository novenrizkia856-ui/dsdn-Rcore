//! # DSDN Storage — Entry Point
//!
//! Minimal main yang delegates semua logic ke `cli` module.

mod cli;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let exit_code = cli::run().await;
    std::process::exit(exit_code);
}
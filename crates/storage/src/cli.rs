//! # DSDN Storage CLI Module
//!
//! Semua CLI command definitions, argument parsing, dan handler functions.
//! Native implementation — tidak bergantung pada OS commands.
//!
//! ## Commands
//!
//! - `server`  : Run gRPC storage server
//! - `put`     : Chunk file & store locally
//! - `get`     : Retrieve chunk dari local store
//! - `has`     : Check chunk existence di local store
//! - `send`    : Send file chunks ke remote gRPC server
//! - `fetch`   : Fetch chunk dari remote gRPC server
//! - `list`    : List semua chunks di local store
//! - `info`    : Show storage info & stats
//! - `delete`  : Delete chunk dari local store
//! - `verify`  : Verify chunk integrity
//! - `export`  : Export chunks ke output file (reassemble)

use std::env;
use std::fmt;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Notify;

use dsdn_common::cid::sha256_hex;
use dsdn_storage::localfs::LocalFsStorage;
use dsdn_storage::chunker;
use dsdn_storage::rpc;
use dsdn_storage::store::Storage;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Default data directory untuk local storage
const DEFAULT_DATA_DIR: &str = "./data";

/// CLI application name
const APP_NAME: &str = "dsdn-storage";

/// CLI version — synced with crate version
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// ─── Error Type ──────────────────────────────────────────────────────────────

/// Unified error type untuk semua CLI operations.
/// Semua errors di-handle secara native tanpa panic/unwrap di handler level.
#[derive(Debug)]
pub enum CliError {
    /// Argument parsing error
    InvalidArgs(String),
    /// File I/O error
    Io(io::Error),
    /// Storage operation error
    Storage(String),
    /// Network / gRPC error
    Network(String),
    /// Address parsing error
    AddrParse(String),
    /// Chunk not found
    ChunkNotFound(String),
    /// File not found
    FileNotFound(PathBuf),
    /// Verification failed
    VerifyFailed(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::InvalidArgs(msg) => write!(f, "invalid arguments: {}", msg),
            CliError::Io(e) => write!(f, "I/O error: {}", e),
            CliError::Storage(msg) => write!(f, "storage error: {}", msg),
            CliError::Network(msg) => write!(f, "network error: {}", msg),
            CliError::AddrParse(addr) => write!(f, "invalid address: {}", addr),
            CliError::ChunkNotFound(hash) => write!(f, "chunk not found: {}", hash),
            CliError::FileNotFound(path) => write!(f, "file not found: {:?}", path),
            CliError::VerifyFailed(msg) => write!(f, "verification failed: {}", msg),
        }
    }
}

impl std::error::Error for CliError {}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        CliError::Io(e)
    }
}

// ─── CLI Command Enum ────────────────────────────────────────────────────────

/// Semua CLI commands yang tersedia, parsed dari args.
///
/// Setiap variant menyimpan semua parameter yang dibutuhkan handler-nya,
/// sehingga handler bisa langsung execute tanpa re-parse args.
#[derive(Debug)]
pub enum Command {
    /// Run gRPC storage server
    Server {
        addr: SocketAddr,
        data_dir: String,
    },

    /// Chunk file & store locally
    Put {
        file: PathBuf,
        chunk_size: usize,
        data_dir: String,
    },

    /// Retrieve chunk dari local store
    Get {
        hash: String,
        output: Option<PathBuf>,
        data_dir: String,
    },

    /// Check chunk existence
    Has {
        hash: String,
        data_dir: String,
    },

    /// Send file chunks ke remote server
    Send {
        addr: String,
        file: PathBuf,
        chunk_size: usize,
    },

    /// Fetch chunk dari remote server
    Fetch {
        addr: String,
        hash: String,
        output: Option<PathBuf>,
    },

    /// List semua chunks di local store
    List {
        data_dir: String,
    },

    /// Show storage info & stats
    Info {
        data_dir: String,
    },

    /// Delete chunk dari local store
    Delete {
        hash: String,
        data_dir: String,
    },

    /// Verify chunk integrity (hash check)
    Verify {
        hash: String,
        data_dir: String,
    },

    /// Export / reassemble chunks ke output file
    Export {
        hashes: Vec<String>,
        output: PathBuf,
        data_dir: String,
    },

    /// Show help
    Help,

    /// Show version
    Version,
}

// ─── Argument Parsing ────────────────────────────────────────────────────────

/// Parse command line arguments ke `Command` enum.
///
/// Native parser — no external dependency (clap, structopt, etc).
/// Supports `--data-dir` global option untuk override default storage path.
pub fn parse_args(args: &[String]) -> Result<Command, CliError> {
    if args.len() < 2 {
        return Ok(Command::Help);
    }

    // Extract global flags dulu
    let data_dir = extract_flag_value(args, "--data-dir")
        .unwrap_or_else(|| DEFAULT_DATA_DIR.to_string());

    // Positional args (skip flags)
    let positional: Vec<&String> = args.iter()
        .skip(1)
        .filter(|a| !a.starts_with("--data-dir") && Some(a.as_str()) != extract_flag_raw(args, "--data-dir").as_deref())
        .collect();

    if positional.is_empty() {
        return Ok(Command::Help);
    }

    match positional[0].as_str() {
        "server" => {
            let addr_str = positional.get(1)
                .ok_or_else(|| CliError::InvalidArgs("server requires <addr>".into()))?;
            let addr: SocketAddr = addr_str.parse()
                .map_err(|_| CliError::AddrParse(addr_str.to_string()))?;
            Ok(Command::Server { addr, data_dir })
        }

        "put" => {
            let file_str = positional.get(1)
                .ok_or_else(|| CliError::InvalidArgs("put requires <file>".into()))?;
            let file = PathBuf::from(file_str);
            if !file.exists() {
                return Err(CliError::FileNotFound(file));
            }
            let chunk_size = positional.get(2)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(chunker::DEFAULT_CHUNK_SIZE);
            Ok(Command::Put { file, chunk_size, data_dir })
        }

        "get" => {
            let hash = positional.get(1)
                .ok_or_else(|| CliError::InvalidArgs("get requires <hash>".into()))?
                .to_string();
            let output = positional.get(2).map(|s| PathBuf::from(s));
            Ok(Command::Get { hash, output, data_dir })
        }

        "has" => {
            let hash = positional.get(1)
                .ok_or_else(|| CliError::InvalidArgs("has requires <hash>".into()))?
                .to_string();
            Ok(Command::Has { hash, data_dir })
        }

        "send" => {
            let addr = positional.get(1)
                .ok_or_else(|| CliError::InvalidArgs("send requires <addr>".into()))?
                .to_string();
            let file_str = positional.get(2)
                .ok_or_else(|| CliError::InvalidArgs("send requires <file>".into()))?;
            let file = PathBuf::from(file_str);
            if !file.exists() {
                return Err(CliError::FileNotFound(file));
            }
            let chunk_size = positional.get(3)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(chunker::DEFAULT_CHUNK_SIZE);
            Ok(Command::Send { addr, file, chunk_size })
        }

        "fetch" => {
            let addr = positional.get(1)
                .ok_or_else(|| CliError::InvalidArgs("fetch requires <addr>".into()))?
                .to_string();
            let hash = positional.get(2)
                .ok_or_else(|| CliError::InvalidArgs("fetch requires <hash>".into()))?
                .to_string();
            let output = positional.get(3).map(|s| PathBuf::from(s));
            Ok(Command::Fetch { addr, hash, output })
        }

        "list" | "ls" => {
            Ok(Command::List { data_dir })
        }

        "info" | "status" => {
            Ok(Command::Info { data_dir })
        }

        "delete" | "rm" => {
            let hash = positional.get(1)
                .ok_or_else(|| CliError::InvalidArgs("delete requires <hash>".into()))?
                .to_string();
            Ok(Command::Delete { hash, data_dir })
        }

        "verify" => {
            let hash = positional.get(1)
                .ok_or_else(|| CliError::InvalidArgs("verify requires <hash>".into()))?
                .to_string();
            Ok(Command::Verify { hash, data_dir })
        }

        "export" => {
            // export <output_file> <hash1> <hash2> ...
            let output_str = positional.get(1)
                .ok_or_else(|| CliError::InvalidArgs("export requires <output> <hash1> [hash2] ...".into()))?;
            let output = PathBuf::from(output_str);
            if positional.len() < 3 {
                return Err(CliError::InvalidArgs("export requires at least one hash".into()));
            }
            let hashes: Vec<String> = positional[2..].iter().map(|s| s.to_string()).collect();
            Ok(Command::Export { hashes, output, data_dir })
        }

        "--version" | "-V" | "version" => Ok(Command::Version),
        "--help" | "-h" | "help" => Ok(Command::Help),

        unknown => Err(CliError::InvalidArgs(format!("unknown command: {}", unknown))),
    }
}

/// Extract `--flag value` dari args
fn extract_flag_value(args: &[String], flag: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == flag {
            return args.get(i + 1).cloned();
        }
        // Support --flag=value
        if let Some(rest) = arg.strip_prefix(&format!("{}=", flag)) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Extract raw flag value reference untuk filtering
fn extract_flag_raw(args: &[String], flag: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == flag {
            return args.get(i + 1).cloned();
        }
    }
    None
}

// ─── Command Handlers ────────────────────────────────────────────────────────

/// Main entry point — parse args dan dispatch ke handler.
///
/// Returns exit code: 0 = success, 1 = error, 2 = usage error.
pub async fn run() -> i32 {
    let args: Vec<String> = env::args().collect();

    match parse_args(&args) {
        Ok(cmd) => match execute(cmd).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("❌ {}", e);
                1
            }
        },
        Err(CliError::InvalidArgs(msg)) => {
            eprintln!("❌ {}", msg);
            print_usage();
            2
        }
        Err(e) => {
            eprintln!("❌ {}", e);
            1
        }
    }
}

/// Dispatch command ke handler yang sesuai
async fn execute(cmd: Command) -> Result<(), CliError> {
    match cmd {
        Command::Server { addr, data_dir } => handle_server(addr, &data_dir).await,
        Command::Put { file, chunk_size, data_dir } => handle_put(&file, chunk_size, &data_dir),
        Command::Get { hash, output, data_dir } => handle_get(&hash, output.as_deref(), &data_dir),
        Command::Has { hash, data_dir } => handle_has(&hash, &data_dir),
        Command::Send { addr, file, chunk_size } => handle_send(&addr, &file, chunk_size).await,
        Command::Fetch { addr, hash, output } => handle_fetch(&addr, &hash, output.as_deref()).await,
        Command::List { data_dir } => handle_list(&data_dir),
        Command::Info { data_dir } => handle_info(&data_dir),
        Command::Delete { hash, data_dir } => handle_delete(&hash, &data_dir),
        Command::Verify { hash, data_dir } => handle_verify(&hash, &data_dir),
        Command::Export { hashes, output, data_dir } => handle_export(&hashes, &output, &data_dir),
        Command::Help => { print_usage(); Ok(()) }
        Command::Version => { print_version(); Ok(()) }
    }
}

// ─── Handler: server ─────────────────────────────────────────────────────────

async fn handle_server(addr: SocketAddr, data_dir: &str) -> Result<(), CliError> {
    let store = Arc::new(
        LocalFsStorage::new(data_dir)
            .map_err(|e| CliError::Storage(format!("failed to init store at {}: {}", data_dir, e)))?
    );
    let shutdown_notify = Arc::new(Notify::new());

    println!("🚀 DSDN Storage gRPC server");
    println!("   addr     : {}", addr);
    println!("   data_dir : {}", data_dir);
    println!("   Press Ctrl+C to stop.");
    println!();

    let s_notify = shutdown_notify.clone();
    let st = store.clone();
    let server_task = tokio::spawn(async move {
        if let Err(e) = rpc::run_server(addr, st, s_notify).await {
            eprintln!("server error: {}", e);
        }
    });

    tokio::signal::ctrl_c().await
        .map_err(|e| CliError::Io(e))?;

    println!();
    println!("⏹  Shutdown signal received, stopping...");
    shutdown_notify.notify_waiters();
    let _ = server_task.await;
    println!("✅ Server stopped cleanly.");
    Ok(())
}

// ─── Handler: put ────────────────────────────────────────────────────────────

fn handle_put(file: &Path, chunk_size: usize, data_dir: &str) -> Result<(), CliError> {
    let mut f = std::fs::File::open(file)?;
    let file_size = f.metadata()?.len();
    let chunks = chunker::chunk_reader(&mut f, chunk_size)
        .map_err(|e| CliError::Storage(format!("chunk error: {}", e)))?;

    let store = LocalFsStorage::new(data_dir)
        .map_err(|e| CliError::Storage(format!("failed to init store: {}", e)))?;

    println!("📦 Storing file: {:?}", file);
    println!("   file_size  : {} bytes", file_size);
    println!("   chunk_size : {} bytes", chunk_size);
    println!("   chunks     : {}", chunks.len());
    println!("   data_dir   : {}", data_dir);
    println!();

    let mut stored_hashes: Vec<String> = Vec::with_capacity(chunks.len());

    for (i, chunk) in chunks.into_iter().enumerate() {
        let hash = sha256_hex(&chunk);
        store.put_chunk(&hash, &chunk)
            .map_err(|e| CliError::Storage(format!("put chunk {}: {}", i, e)))?;
        println!("  [{:>4}] {} ({} bytes)", i, hash, chunk.len());
        stored_hashes.push(hash);
    }

    println!();
    println!("✅ Stored {} chunks in {}", stored_hashes.len(), data_dir);

    // Print manifest untuk reassembly
    println!();
    println!("─── Chunk Manifest (untuk export/reassembly) ───");
    for h in &stored_hashes {
        println!("  {}", h);
    }

    Ok(())
}

// ─── Handler: get ────────────────────────────────────────────────────────────

fn handle_get(hash: &str, output: Option<&Path>, data_dir: &str) -> Result<(), CliError> {
    let store = LocalFsStorage::new(data_dir)
        .map_err(|e| CliError::Storage(format!("failed to init store: {}", e)))?;

    let data = store.get_chunk(hash)
        .map_err(|e| CliError::Storage(e.to_string()))?
        .ok_or_else(|| CliError::ChunkNotFound(hash.to_string()))?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &data)?;
        println!("✅ Chunk {} ({} bytes) → {:?}", hash, data.len(), out_path);
    } else {
        println!("✅ Chunk: {}", hash);
        println!("   size : {} bytes", data.len());
        print_chunk_preview(&data);
    }

    Ok(())
}

// ─── Handler: has ────────────────────────────────────────────────────────────

fn handle_has(hash: &str, data_dir: &str) -> Result<(), CliError> {
    let store = LocalFsStorage::new(data_dir)
        .map_err(|e| CliError::Storage(format!("failed to init store: {}", e)))?;

    let exists = store.has_chunk(hash)
        .map_err(|e| CliError::Storage(e.to_string()))?;

    if exists {
        println!("✅ Chunk exists: {}", hash);
        Ok(())
    } else {
        Err(CliError::ChunkNotFound(hash.to_string()))
    }
}

// ─── Handler: send ───────────────────────────────────────────────────────────

async fn handle_send(addr: &str, file: &Path, chunk_size: usize) -> Result<(), CliError> {
    let mut f = std::fs::File::open(file)?;
    let chunks = chunker::chunk_reader(&mut f, chunk_size)
        .map_err(|e| CliError::Storage(format!("chunk error: {}", e)))?;

    let endpoint = normalize_addr(addr);

    println!("📤 Sending file: {:?}", file);
    println!("   endpoint : {}", endpoint);
    println!("   chunks   : {}", chunks.len());
    println!();

    let mut success = 0usize;
    let mut failed = 0usize;

    for (i, chunk) in chunks.into_iter().enumerate() {
        let hash = sha256_hex(&chunk);
        match rpc::client_put(endpoint.clone(), hash.clone(), chunk).await {
            Ok(returned) => {
                println!("  [{:>4}] ✅ {} → {}", i, hash, returned);
                success += 1;
            }
            Err(e) => {
                eprintln!("  [{:>4}] ❌ {} — {}", i, hash, e);
                failed += 1;
            }
        }
    }

    println!();
    println!("📊 Transfer complete: {} sent, {} failed", success, failed);

    if failed > 0 {
        Err(CliError::Network(format!("{} chunks failed to send", failed)))
    } else {
        Ok(())
    }
}

// ─── Handler: fetch ──────────────────────────────────────────────────────────

async fn handle_fetch(addr: &str, hash: &str, output: Option<&Path>) -> Result<(), CliError> {
    let endpoint = normalize_addr(addr);

    println!("📥 Fetching chunk: {}", hash);
    println!("   endpoint : {}", endpoint);
    println!();

    let data = rpc::client_get(endpoint, hash.to_string()).await
        .map_err(|e| CliError::Network(format!("gRPC error: {}", e)))?
        .ok_or_else(|| CliError::ChunkNotFound(format!("{} (remote)", hash)))?;

    // Verify hash setelah fetch (native integrity check)
    let actual_hash = sha256_hex(&data);
    if actual_hash != hash {
        return Err(CliError::VerifyFailed(format!(
            "hash mismatch: expected {} got {}", hash, actual_hash
        )));
    }

    if let Some(out_path) = output {
        std::fs::write(out_path, &data)?;
        println!("✅ Fetched {} ({} bytes) → {:?}", hash, data.len(), out_path);
    } else {
        println!("✅ Fetched: {}", hash);
        println!("   size     : {} bytes", data.len());
        println!("   verified : ✅ hash matches");
        print_chunk_preview(&data);
    }

    Ok(())
}

// ─── Handler: list ───────────────────────────────────────────────────────────

fn handle_list(data_dir: &str) -> Result<(), CliError> {
    let dir = Path::new(data_dir);
    if !dir.exists() {
        return Err(CliError::Storage(format!("data directory not found: {}", data_dir)));
    }

    let mut entries: Vec<(String, u64)> = Vec::new();
    let mut total_bytes: u64 = 0;

    // Native directory traversal — langsung baca filesystem
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            let size = entry.metadata()?.len();
            total_bytes += size;
            entries.push((name, size));
        }
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    println!("📋 Chunks in {}", data_dir);
    println!("   total: {} chunks, {} bytes", entries.len(), total_bytes);
    println!();

    if entries.is_empty() {
        println!("   (empty)");
    } else {
        for (name, size) in &entries {
            println!("  {} ({} bytes)", name, size);
        }
    }

    Ok(())
}

// ─── Handler: info ───────────────────────────────────────────────────────────

fn handle_info(data_dir: &str) -> Result<(), CliError> {
    let dir = Path::new(data_dir);

    println!("📊 DSDN Storage Info");
    println!("   version  : {}", APP_VERSION);
    println!("   data_dir : {}", data_dir);

    if !dir.exists() {
        println!("   status   : ❌ data directory not found");
        return Ok(());
    }

    let mut chunk_count: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut min_size: u64 = u64::MAX;
    let mut max_size: u64 = 0;

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().is_file() {
            let size = entry.metadata()?.len();
            chunk_count += 1;
            total_bytes += size;
            min_size = min_size.min(size);
            max_size = max_size.max(size);
        }
    }

    if chunk_count == 0 {
        min_size = 0;
    }

    let avg_size = if chunk_count > 0 { total_bytes / chunk_count } else { 0 };

    println!("   status   : ✅ ok");
    println!("   chunks   : {}", chunk_count);
    println!("   total    : {} bytes ({:.2} MB)", total_bytes, total_bytes as f64 / 1_048_576.0);
    println!("   avg_size : {} bytes", avg_size);
    println!("   min_size : {} bytes", min_size);
    println!("   max_size : {} bytes", max_size);

    Ok(())
}

// ─── Handler: delete ─────────────────────────────────────────────────────────

fn handle_delete(hash: &str, data_dir: &str) -> Result<(), CliError> {
    let store = LocalFsStorage::new(data_dir)
        .map_err(|e| CliError::Storage(format!("failed to init store: {}", e)))?;

    // Verify exists dulu
    let exists = store.has_chunk(hash)
        .map_err(|e| CliError::Storage(e.to_string()))?;

    if !exists {
        return Err(CliError::ChunkNotFound(hash.to_string()));
    }

    store.delete_chunk(hash)
        .map_err(|e| CliError::Storage(format!("delete error: {}", e)))?;

    println!("🗑  Deleted chunk: {}", hash);
    Ok(())
}

// ─── Handler: verify ─────────────────────────────────────────────────────────

fn handle_verify(hash: &str, data_dir: &str) -> Result<(), CliError> {
    let store = LocalFsStorage::new(data_dir)
        .map_err(|e| CliError::Storage(format!("failed to init store: {}", e)))?;

    let data = store.get_chunk(hash)
        .map_err(|e| CliError::Storage(e.to_string()))?
        .ok_or_else(|| CliError::ChunkNotFound(hash.to_string()))?;

    // Native hash verification — compute ulang dan compare
    let actual_hash = sha256_hex(&data);

    if actual_hash == hash {
        println!("✅ Chunk verified: {}", hash);
        println!("   size : {} bytes", data.len());
        println!("   hash : ✅ matches");
        Ok(())
    } else {
        Err(CliError::VerifyFailed(format!(
            "chunk {} has hash {} — DATA CORRUPTED", hash, actual_hash
        )))
    }
}

// ─── Handler: export ─────────────────────────────────────────────────────────

fn handle_export(hashes: &[String], output: &Path, data_dir: &str) -> Result<(), CliError> {
    let store = LocalFsStorage::new(data_dir)
        .map_err(|e| CliError::Storage(format!("failed to init store: {}", e)))?;

    println!("📦 Exporting {} chunks → {:?}", hashes.len(), output);

    let mut out_file = std::fs::File::create(output)?;
    let mut total_bytes: u64 = 0;

    for (i, hash) in hashes.iter().enumerate() {
        let data = store.get_chunk(hash)
            .map_err(|e| CliError::Storage(e.to_string()))?
            .ok_or_else(|| CliError::ChunkNotFound(hash.to_string()))?;

        // Verify setiap chunk sebelum export
        let actual_hash = sha256_hex(&data);
        if actual_hash != *hash {
            return Err(CliError::VerifyFailed(format!(
                "chunk {} corrupted during export (got {})", hash, actual_hash
            )));
        }

        out_file.write_all(&data)?;
        total_bytes += data.len() as u64;
        println!("  [{:>4}] {} ({} bytes)", i, hash, data.len());
    }

    out_file.flush()?;

    println!();
    println!("✅ Exported {} bytes to {:?}", total_bytes, output);
    Ok(())
}

// ─── Utility Functions ───────────────────────────────────────────────────────

/// Normalize address ke http:// URL format.
/// Kalau sudah punya scheme, pakai as-is. Kalau belum, tambah http://.
fn normalize_addr(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.to_string()
    } else {
        format!("http://{}", addr)
    }
}

/// Print preview isi chunk (text atau hex)
fn print_chunk_preview(data: &[u8]) {
    const PREVIEW_LIMIT: usize = 1024;
    const HEX_PREVIEW_BYTES: usize = 64;

    if data.is_empty() {
        println!("   content : (empty)");
        return;
    }

    if data.len() <= PREVIEW_LIMIT {
        if let Ok(text) = std::str::from_utf8(data) {
            println!("   content : {}", text);
            return;
        }
    }

    let hex: String = data.iter()
        .take(HEX_PREVIEW_BYTES)
        .map(|b| format!("{:02x}", b))
        .collect();
    let suffix = if data.len() > HEX_PREVIEW_BYTES { "..." } else { "" };
    println!("   content (hex): {}{}", hex, suffix);
}

/// Format bytes ke human-readable string
fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.2} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    }
}

// ─── Usage / Help ────────────────────────────────────────────────────────────

fn print_version() {
    println!("{} {}", APP_NAME, APP_VERSION);
}

pub fn print_usage() {
    println!("{} {} — DSDN Storage CLI", APP_NAME, APP_VERSION);
    println!();
    println!("USAGE:");
    println!("  {} [--data-dir <path>] <command> [args...]", APP_NAME);
    println!();
    println!("COMMANDS:");
    println!("  server <addr>                         Run gRPC storage server");
    println!("  put <file> [chunk_size]               Chunk file & store locally");
    println!("  get <hash> [output_file]              Retrieve chunk from local store");
    println!("  has <hash>                            Check if chunk exists locally");
    println!("  send <addr> <file> [chunk_size]       Send file chunks to remote server");
    println!("  fetch <addr> <hash> [output_file]     Fetch chunk from remote server");
    println!("  list                                  List all chunks in local store");
    println!("  info                                  Show storage info & statistics");
    println!("  delete <hash>                         Delete chunk from local store");
    println!("  verify <hash>                         Verify chunk integrity (hash check)");
    println!("  export <output> <hash1> [hash2] ...   Reassemble chunks to file");
    println!("  version                               Show version");
    println!("  help                                  Show this help");
    println!();
    println!("GLOBAL OPTIONS:");
    println!("  --data-dir <path>    Storage directory (default: ./data)");
    println!();
    println!("EXAMPLES:");
    println!("  {} server 127.0.0.1:50051", APP_NAME);
    println!("  {} put myfile.dat 4194304", APP_NAME);
    println!("  {} get abc123def456...", APP_NAME);
    println!("  {} send 127.0.0.1:50051 myfile.dat", APP_NAME);
    println!("  {} fetch 127.0.0.1:50051 abc123def456... output.bin", APP_NAME);
    println!("  {} --data-dir /mnt/storage list", APP_NAME);
    println!("  {} export restored.dat hash1 hash2 hash3", APP_NAME);
    println!("  {} verify abc123def456...", APP_NAME);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_parse_help() {
        let cmd = parse_args(&args(&["dsdn-storage"])).unwrap();
        assert!(matches!(cmd, Command::Help));

        let cmd = parse_args(&args(&["dsdn-storage", "help"])).unwrap();
        assert!(matches!(cmd, Command::Help));

        let cmd = parse_args(&args(&["dsdn-storage", "--help"])).unwrap();
        assert!(matches!(cmd, Command::Help));
    }

    #[test]
    fn test_parse_version() {
        let cmd = parse_args(&args(&["dsdn-storage", "version"])).unwrap();
        assert!(matches!(cmd, Command::Version));
    }

    #[test]
    fn test_parse_server() {
        let cmd = parse_args(&args(&["dsdn-storage", "server", "127.0.0.1:50051"])).unwrap();
        match cmd {
            Command::Server { addr, data_dir } => {
                assert_eq!(addr.to_string(), "127.0.0.1:50051");
                assert_eq!(data_dir, DEFAULT_DATA_DIR);
            }
            _ => panic!("expected Server command"),
        }
    }

    #[test]
    fn test_parse_has() {
        let cmd = parse_args(&args(&["dsdn-storage", "has", "abc123"])).unwrap();
        match cmd {
            Command::Has { hash, .. } => assert_eq!(hash, "abc123"),
            _ => panic!("expected Has command"),
        }
    }

    #[test]
    fn test_parse_with_data_dir() {
        let cmd = parse_args(&args(&["dsdn-storage", "--data-dir", "/mnt/store", "list"])).unwrap();
        match cmd {
            Command::List { data_dir } => assert_eq!(data_dir, "/mnt/store"),
            _ => panic!("expected List command"),
        }
    }

    #[test]
    fn test_parse_unknown_command() {
        let result = parse_args(&args(&["dsdn-storage", "foobar"]));
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_addr() {
        assert_eq!(normalize_addr("127.0.0.1:50051"), "http://127.0.0.1:50051");
        assert_eq!(normalize_addr("http://127.0.0.1:50051"), "http://127.0.0.1:50051");
        assert_eq!(normalize_addr("https://node.dsdn.io"), "https://node.dsdn.io");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_bytes(5_242_880), "5.00 MB");
    }
}
//! # Gating CLI Commands (14B.53–14B.54)
//!
//! Handles gating-related subcommands for the DSDN Agent CLI.
//!
//! ## Commands
//!
//! - `gating stake-check --address <hex> [--chain-rpc <url>] [--json]`
//! - `gating register --identity-dir <path> --class <storage|compute>
//!     --chain-rpc <url> [--keyfile <path>]`
//!
//! ## Chain RPC Resolution (stake-check)
//!
//! Endpoint resolution order:
//! 1. `--chain-rpc <url>` argument (highest priority)
//! 2. `DSDN_CHAIN_RPC` environment variable
//! 3. Default: `http://127.0.0.1:8545`
//!
//! ## Chain RPC (register)
//!
//! `--chain-rpc` is REQUIRED. No fallback.
//!
//! ## Endpoints
//!
//! - stake-check: `GET {chain_rpc}/api/service_node/stake/{operator_hex}`
//! - register: `POST {chain_rpc}/api/service_node/register`

use std::path::Path;
use anyhow::Result;
use serde::{Deserialize, Serialize};

use dsdn_node::{IdentityStore, NodeIdentityManager};
use dsdn_common::gating::IdentityChallenge;

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Default chain RPC endpoint.
const DEFAULT_CHAIN_RPC: &str = "http://127.0.0.1:8545";

/// Environment variable for chain RPC override.
const ENV_CHAIN_RPC: &str = "DSDN_CHAIN_RPC";

/// REST path template for service node stake query.
/// `{}` is replaced with the operator hex address (no 0x prefix).
const STAKE_ENDPOINT_PATH: &str = "/api/service_node/stake/";

/// REST path for service node registration (POST).
const REGISTER_ENDPOINT_PATH: &str = "/api/service_node/register";

// ════════════════════════════════════════════════════════════════════════════════
// RESPONSE TYPE (mirrors chain rpc.rs ServiceNodeStakeRes)
// ════════════════════════════════════════════════════════════════════════════════

/// Response from chain RPC `get_service_node_stake`.
///
/// Field names and types MUST match `ServiceNodeStakeRes` in chain rpc.rs.
/// All u128 values are represented as String to avoid JSON overflow.
#[derive(Deserialize, Debug, Clone)]
struct ServiceNodeStakeResponse {
    /// Operator address (hex string with 0x prefix)
    operator: String,
    /// Staked amount (u128 as string, smallest unit)
    staked_amount: String,
    /// Node class ("Storage" or "Compute")
    class: String,
    /// Whether staked_amount meets the minimum for this class
    meets_minimum: bool,
}

/// RPC error response from chain node.
///
/// Matches `RpcError` in chain rpc.rs.
#[derive(Deserialize, Debug, Clone)]
struct ChainRpcError {
    code: i64,
    message: String,
}

// ════════════════════════════════════════════════════════════════════════════════
// REGISTER TYPES (14B.54) — mirrors chain rpc.rs RegisterServiceNodeReq
// ════════════════════════════════════════════════════════════════════════════════

/// Request body for POST to chain RPC `/api/service_node/register`.
///
/// Field names and types MUST match `RegisterServiceNodeReq` in chain rpc.rs.
#[derive(Serialize, Debug, Clone)]
struct RegisterRequest {
    operator_hex: String,
    node_id_hex: String,
    class: String,
    tls_fingerprint_hex: String,
    identity_proof_sig_hex: String,
    secret_hex: String,
    fee: String,
}

/// Response from chain RPC `register_service_node`.
///
/// Field names MUST match `SubmitTxRes` in chain rpc.rs.
#[derive(Deserialize, Debug, Clone)]
struct SubmitTxResponse {
    success: bool,
    txid: String,
    message: String,
}

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════════════════════════════════════

/// Handles `gating stake-check --address <hex> [--chain-rpc <url>] [--json]`.
///
/// ## Parameters
///
/// - `address_hex`: Operator address as hex string (40 chars, no 0x prefix).
/// - `chain_rpc_arg`: Optional chain RPC URL override from CLI.
/// - `json`: If true, output as JSON.
///
/// ## Errors
///
/// Returns `Err` if:
/// - Address is not valid 40-char hex.
/// - HTTP request to chain RPC fails.
/// - Chain RPC returns an error (node not found, invalid address).
/// - Response JSON does not match expected schema.
pub async fn handle_stake_check(
    address_hex: &str,
    chain_rpc_arg: Option<&str>,
    json: bool,
) -> Result<()> {
    // Step 1: Validate address hex
    validate_operator_hex(address_hex)?;

    // Step 2: Resolve chain RPC endpoint
    let chain_rpc = resolve_chain_rpc(chain_rpc_arg);

    // Step 3: Build URL
    let url = format!(
        "{}{}{}",
        chain_rpc.trim_end_matches('/'),
        STAKE_ENDPOINT_PATH,
        address_hex,
    );

    // Step 4: Make HTTP request
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to connect to chain RPC at '{}': {}",
                chain_rpc,
                e,
            )
        })?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("failed to read response body: {}", e))?;

    // Step 5: Handle non-success status
    if !status.is_success() {
        // Try to parse as RpcError for better message
        if let Ok(rpc_err) = serde_json::from_str::<ChainRpcError>(&body) {
            return Err(anyhow::anyhow!(
                "chain RPC error (code {}): {}",
                rpc_err.code,
                rpc_err.message,
            ));
        }
        return Err(anyhow::anyhow!(
            "chain RPC returned HTTP {}: {}",
            status.as_u16(),
            truncate_body(&body, 200),
        ));
    }

    // Step 6: Parse response
    let stake_res: ServiceNodeStakeResponse = serde_json::from_str(&body)
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to parse stake response from chain RPC: {}",
                e,
            )
        })?;

    // Step 7: Display
    if json {
        print_json(&stake_res);
    } else {
        print_table(&stake_res);
    }

    Ok(())
}

/// Handles `gating register --identity-dir <path> --class <storage|compute>
/// --chain-rpc <url> [--keyfile <path>]`.
///
/// ## Flow
///
/// 1. Load identity from disk (IdentityStore + NodeIdentityManager).
/// 2. Load TLS fingerprint from identity directory (REQUIRED).
/// 3. Create IdentityChallenge with current timestamp.
/// 4. Sign challenge to produce IdentityProof.
/// 5. Load wallet secret key from keyfile (REQUIRED).
/// 6. POST registration request to chain RPC.
/// 7. Display Tx Hash and Status.
///
/// ## Errors
///
/// Returns `Err` if:
/// - Identity directory does not exist or is corrupted.
/// - TLS fingerprint file is missing or invalid.
/// - Keyfile is not provided, not found, or contains invalid data.
/// - Class value is not "storage" or "compute".
/// - Chain RPC is unreachable or returns an error.
pub async fn handle_register(
    identity_dir: &Path,
    class: &str,
    chain_rpc: &str,
    keyfile: Option<&Path>,
) -> Result<()> {
    // ── Step 1: Validate class ──────────────────────────────────────────
    validate_node_class(class)?;

    // ── Step 2: Validate keyfile (REQUIRED per spec) ────────────────────
    let keyfile_path = keyfile.ok_or_else(|| {
        anyhow::anyhow!(
            "--keyfile is required: provide path to wallet secret key file (64 hex chars)",
        )
    })?;

    // ── Step 3: Load identity from disk ─────────────────────────────────
    let store = IdentityStore::new(identity_dir.to_path_buf());
    if !store.exists() {
        return Err(anyhow::anyhow!(
            "no identity found at '{}': run `identity generate --out-dir {}` first",
            identity_dir.display(),
            identity_dir.display(),
        ));
    }

    let secret = store.load_keypair().map_err(|e| {
        anyhow::anyhow!("failed to load keypair from '{}': {}", identity_dir.display(), e)
    })?;

    let operator_stored = store.load_operator_address().map_err(|e| {
        anyhow::anyhow!(
            "failed to load operator address from '{}': {}",
            identity_dir.display(),
            e,
        )
    })?;

    let mgr = NodeIdentityManager::from_keypair(secret).map_err(|e| {
        anyhow::anyhow!("failed to reconstruct identity: {}", e)
    })?;

    // ── Step 4: Load TLS fingerprint (REQUIRED for registration) ────────
    let tls_fp_hex = load_tls_fingerprint_hex(identity_dir).ok_or_else(|| {
        anyhow::anyhow!(
            "TLS fingerprint not found at '{}/tls.fp': generate TLS certificate first",
            identity_dir.display(),
        )
    })?;

    // ── Step 5: Create identity proof ───────────────────────────────────
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| anyhow::anyhow!("system clock error: {}", e))?;

    let mut nonce = [0u8; 32];
    nonce[0..8].copy_from_slice(&timestamp.to_le_bytes());

    let challenge = IdentityChallenge {
        nonce,
        timestamp,
        challenger: "agent-register".to_string(),
    };

    let proof = mgr.create_identity_proof(challenge);

    // ── Step 6: Load wallet secret from keyfile ─────────────────────────
    let wallet_secret_hex = load_wallet_keyfile(keyfile_path)?;

    // ── Step 7: Build request body ──────────────────────────────────────
    let request_body = RegisterRequest {
        operator_hex: bytes_to_hex(&operator_stored),
        node_id_hex: bytes_to_hex(mgr.node_id()),
        class: class.to_lowercase(),
        tls_fingerprint_hex: tls_fp_hex,
        identity_proof_sig_hex: bytes_to_hex(&proof.signature),
        secret_hex: wallet_secret_hex,
        fee: "0".to_string(),
    };

    // ── Step 8: POST to chain RPC ───────────────────────────────────────
    let url = format!(
        "{}{}",
        chain_rpc.trim_end_matches('/'),
        REGISTER_ENDPOINT_PATH,
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;

    let response = client
        .post(&url)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to connect to chain RPC at '{}': {}",
                chain_rpc,
                e,
            )
        })?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("failed to read response body: {}", e))?;

    if !status.is_success() {
        if let Ok(rpc_err) = serde_json::from_str::<ChainRpcError>(&body) {
            return Err(anyhow::anyhow!(
                "chain RPC error (code {}): {}",
                rpc_err.code,
                rpc_err.message,
            ));
        }
        return Err(anyhow::anyhow!(
            "chain RPC returned HTTP {}: {}",
            status.as_u16(),
            truncate_body(&body, 200),
        ));
    }

    // ── Step 9: Parse and display result ────────────────────────────────
    let tx_res: SubmitTxResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("failed to parse registration response: {}", e))?;

    if tx_res.success {
        println!("Tx Hash: {}", tx_res.txid);
        println!("Status:  submitted");
    } else {
        let hash_display = if tx_res.txid.is_empty() { "(none)" } else { &tx_res.txid };
        println!("Tx Hash: {}", hash_display);
        println!("Status:  failed");
        println!("Error:   {}", tx_res.message);
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: VALIDATION
// ════════════════════════════════════════════════════════════════════════════════

/// Validates that `hex` is exactly 40 lowercase/uppercase hex characters.
///
/// Rejects `0x` prefix explicitly (chain RPC trims it, but CLI should
/// enforce clean input).
fn validate_operator_hex(hex: &str) -> Result<()> {
    if hex.starts_with("0x") || hex.starts_with("0X") {
        return Err(anyhow::anyhow!(
            "address must be 40 hex characters without 0x prefix, got '{}'",
            hex,
        ));
    }

    if hex.len() != 40 {
        return Err(anyhow::anyhow!(
            "address must be exactly 40 hex characters (20 bytes), got {} characters",
            hex.len(),
        ));
    }

    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "address contains non-hex characters: '{}'",
            hex,
        ));
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: ENDPOINT RESOLUTION
// ════════════════════════════════════════════════════════════════════════════════

/// Resolves the chain RPC endpoint URL.
///
/// Priority:
/// 1. CLI argument (`--chain-rpc`)
/// 2. Environment variable (`DSDN_CHAIN_RPC`)
/// 3. Default (`http://127.0.0.1:8545`)
fn resolve_chain_rpc(cli_arg: Option<&str>) -> String {
    if let Some(url) = cli_arg {
        return url.to_string();
    }

    if let Ok(env_url) = std::env::var(ENV_CHAIN_RPC) {
        if !env_url.is_empty() {
            return env_url;
        }
    }

    DEFAULT_CHAIN_RPC.to_string()
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: DISPLAY
// ════════════════════════════════════════════════════════════════════════════════

/// Prints stake check result as a text table.
fn print_table(res: &ServiceNodeStakeResponse) {
    println!("Operator Address: {}", res.operator);
    println!("Staked Amount:    {}", res.staked_amount);
    println!("Node Class:       {}", res.class);
    println!(
        "Meets Minimum:    {}",
        if res.meets_minimum { "Yes" } else { "No" },
    );
}

/// Prints stake check result as JSON.
fn print_json(res: &ServiceNodeStakeResponse) {
    println!(
        "{{\n  \"operator_address\": \"{}\",\n  \"staked_amount\": \"{}\",\n  \"node_class\": \"{}\",\n  \"meets_minimum\": {}\n}}",
        res.operator,
        res.staked_amount,
        res.class,
        res.meets_minimum,
    );
}

/// Truncates a string to `max_len` characters for error display.
fn truncate_body(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut truncated = s[..max_len].to_string();
        truncated.push_str("...");
        truncated
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: REGISTER HELPERS (14B.54)
// ════════════════════════════════════════════════════════════════════════════════

/// Validates node class string.
///
/// Accepts "storage" or "compute" (case-insensitive).
fn validate_node_class(class: &str) -> Result<()> {
    match class.to_lowercase().as_str() {
        "storage" | "compute" => Ok(()),
        _ => Err(anyhow::anyhow!(
            "invalid class '{}': must be 'storage' or 'compute'",
            class,
        )),
    }
}

/// Loads wallet secret key hex from a file.
///
/// File must contain exactly 64 hex characters (32 bytes).
/// Leading/trailing whitespace and newlines are trimmed.
///
/// ## Errors
///
/// - File not found or unreadable.
/// - Content is not exactly 64 hex characters after trimming.
fn load_wallet_keyfile(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!("failed to read keyfile '{}': {}", path.display(), e)
    })?;

    let trimmed = raw.trim();

    if trimmed.len() != 64 {
        return Err(anyhow::anyhow!(
            "keyfile must contain exactly 64 hex characters (32 bytes), got {} characters in '{}'",
            trimmed.len(),
            path.display(),
        ));
    }

    if !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "keyfile contains non-hex characters in '{}'",
            path.display(),
        ));
    }

    Ok(trimmed.to_string())
}

/// Loads TLS fingerprint hex from `<dir>/tls.fp`.
///
/// Returns `None` if file is missing, wrong length, or invalid hex.
/// Does NOT propagate errors — graceful degradation.
fn load_tls_fingerprint_hex(dir: &Path) -> Option<String> {
    let path = dir.join("tls.fp");
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return None;
    }
    if !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Converts a byte slice to a lowercase hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────────
    // A. validate_operator_hex
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn validate_hex_valid_lowercase() {
        let hex = "aa".repeat(20);
        assert!(validate_operator_hex(&hex).is_ok());
    }

    #[test]
    fn validate_hex_valid_uppercase() {
        let hex = "BB".repeat(20);
        assert!(validate_operator_hex(&hex).is_ok());
    }

    #[test]
    fn validate_hex_valid_mixed() {
        let hex = "aAbBcCdDeEfF00112233aAbBcCdDeEfF00112233";
        assert!(validate_operator_hex(hex).is_ok());
    }

    #[test]
    fn validate_hex_too_short() {
        assert!(validate_operator_hex("aabb").is_err());
    }

    #[test]
    fn validate_hex_too_long() {
        let hex = "aa".repeat(21);
        assert!(validate_operator_hex(&hex).is_err());
    }

    #[test]
    fn validate_hex_invalid_chars() {
        let hex = "gg".repeat(20);
        assert!(validate_operator_hex(&hex).is_err());
    }

    #[test]
    fn validate_hex_rejects_0x_prefix() {
        let hex = format!("0x{}", "aa".repeat(19));
        assert!(validate_operator_hex(&hex).is_err());
    }

    #[test]
    fn validate_hex_empty() {
        assert!(validate_operator_hex("").is_err());
    }

    // ──────────────────────────────────────────────────────────────────────
    // B. resolve_chain_rpc
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn resolve_cli_arg_takes_priority() {
        let result = resolve_chain_rpc(Some("http://custom:9999"));
        assert_eq!(result, "http://custom:9999");
    }

    #[test]
    fn resolve_default_when_no_arg_no_env() {
        // Clear env to test default (may not be set)
        let prev = std::env::var(ENV_CHAIN_RPC).ok();
        std::env::remove_var(ENV_CHAIN_RPC);

        let result = resolve_chain_rpc(None);
        assert_eq!(result, DEFAULT_CHAIN_RPC);

        // Restore
        if let Some(val) = prev {
            std::env::set_var(ENV_CHAIN_RPC, val);
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // C. ServiceNodeStakeResponse deserialization
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn deserialize_valid_response() {
        let json = r#"{
            "operator": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "staked_amount": "5000000000000000000000",
            "class": "Storage",
            "meets_minimum": true
        }"#;
        let result = serde_json::from_str::<ServiceNodeStakeResponse>(json);
        assert!(result.is_ok(), "valid JSON must parse");
        if let Ok(res) = result {
            assert_eq!(res.class, "Storage");
            assert!(res.meets_minimum);
        }
    }

    #[test]
    fn deserialize_compute_class() {
        let json = r#"{
            "operator": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "staked_amount": "500000000000000000000",
            "class": "Compute",
            "meets_minimum": false
        }"#;
        let result = serde_json::from_str::<ServiceNodeStakeResponse>(json);
        assert!(result.is_ok());
        if let Ok(res) = result {
            assert_eq!(res.class, "Compute");
            assert!(!res.meets_minimum);
        }
    }

    #[test]
    fn deserialize_rpc_error() {
        let json = r#"{"code": -32100, "message": "service node not found"}"#;
        let result = serde_json::from_str::<ChainRpcError>(json);
        assert!(result.is_ok());
        if let Ok(err) = result {
            assert_eq!(err.code, -32100);
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // D. print_table / print_json (smoke test, no panic)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn print_table_no_panic() {
        let res = ServiceNodeStakeResponse {
            operator: "0xaaaa".to_string(),
            staked_amount: "5000".to_string(),
            class: "Storage".to_string(),
            meets_minimum: true,
        };
        print_table(&res); // Must not panic
    }

    #[test]
    fn print_json_no_panic() {
        let res = ServiceNodeStakeResponse {
            operator: "0xbbbb".to_string(),
            staked_amount: "500".to_string(),
            class: "Compute".to_string(),
            meets_minimum: false,
        };
        print_json(&res); // Must not panic
    }

    // ──────────────────────────────────────────────────────────────────────
    // E. truncate_body
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate_body("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string() {
        let long = "a".repeat(300);
        let result = truncate_body(&long, 50);
        assert_eq!(result.len(), 53); // 50 + "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_exact_length() {
        let s = "a".repeat(10);
        assert_eq!(truncate_body(&s, 10), s);
    }

    // ──────────────────────────────────────────────────────────────────────
    // F. handle_stake_check — validation failures (no network)
    // ──────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn stake_check_invalid_address_errors() {
        let result = handle_stake_check("short", None, false).await;
        assert!(result.is_err(), "invalid address must fail before HTTP");
    }

    #[tokio::test]
    async fn stake_check_0x_prefix_errors() {
        let hex = format!("0x{}", "aa".repeat(19));
        let result = handle_stake_check(&hex, None, false).await;
        assert!(result.is_err(), "0x prefix must fail before HTTP");
    }

    #[tokio::test]
    async fn stake_check_nonhex_errors() {
        let hex = "gg".repeat(20);
        let result = handle_stake_check(&hex, None, false).await;
        assert!(result.is_err(), "non-hex must fail before HTTP");
    }

    // ──────────────────────────────────────────────────────────────────────
    // G. validate_node_class (14B.54)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn validate_class_storage() {
        assert!(validate_node_class("storage").is_ok());
    }

    #[test]
    fn validate_class_compute() {
        assert!(validate_node_class("compute").is_ok());
    }

    #[test]
    fn validate_class_case_insensitive() {
        assert!(validate_node_class("Storage").is_ok());
        assert!(validate_node_class("COMPUTE").is_ok());
    }

    #[test]
    fn validate_class_invalid() {
        assert!(validate_node_class("validator").is_err());
        assert!(validate_node_class("").is_err());
    }

    // ──────────────────────────────────────────────────────────────────────
    // H. load_wallet_keyfile (14B.54)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn load_keyfile_valid() {
        let dir = std::env::temp_dir().join("dsdn_test_keyfile_valid");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("wallet.key");
        let hex = "aa".repeat(32);
        std::fs::write(&path, &hex).ok();
        let result = load_wallet_keyfile(&path);
        assert!(result.is_ok(), "valid keyfile must parse");
        let val = result.unwrap_or_default();
        assert_eq!(val, hex);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_keyfile_with_whitespace() {
        let dir = std::env::temp_dir().join("dsdn_test_keyfile_ws");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("wallet.key");
        let hex = "bb".repeat(32);
        std::fs::write(&path, format!("  {}  \n", hex)).ok();
        let result = load_wallet_keyfile(&path);
        assert!(result.is_ok(), "whitespace-trimmed keyfile must parse");
        let val = result.unwrap_or_default();
        assert_eq!(val, hex);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_keyfile_wrong_length() {
        let dir = std::env::temp_dir().join("dsdn_test_keyfile_len");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("wallet.key");
        std::fs::write(&path, "aabb").ok();
        assert!(load_wallet_keyfile(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_keyfile_nonhex() {
        let dir = std::env::temp_dir().join("dsdn_test_keyfile_nonhex");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("wallet.key");
        std::fs::write(&path, "gg".repeat(32)).ok();
        assert!(load_wallet_keyfile(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_keyfile_not_found() {
        let path = std::path::PathBuf::from("/tmp/dsdn_nonexistent_keyfile_12345");
        assert!(load_wallet_keyfile(&path).is_err());
    }

    // ──────────────────────────────────────────────────────────────────────
    // I. load_tls_fingerprint_hex (14B.54)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn tls_fp_missing_returns_none() {
        let dir = std::env::temp_dir().join("dsdn_test_tls_miss");
        std::fs::create_dir_all(&dir).ok();
        assert!(load_tls_fingerprint_hex(&dir).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tls_fp_valid_returns_some() {
        let dir = std::env::temp_dir().join("dsdn_test_tls_valid");
        std::fs::create_dir_all(&dir).ok();
        let hex = "cc".repeat(32);
        std::fs::write(dir.join("tls.fp"), &hex).ok();
        let result = load_tls_fingerprint_hex(&dir);
        assert_eq!(result.as_deref(), Some(hex.as_str()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tls_fp_wrong_length_returns_none() {
        let dir = std::env::temp_dir().join("dsdn_test_tls_len");
        std::fs::create_dir_all(&dir).ok();
        std::fs::write(dir.join("tls.fp"), "aabb").ok();
        assert!(load_tls_fingerprint_hex(&dir).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    // ──────────────────────────────────────────────────────────────────────
    // J. bytes_to_hex (14B.54)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn bytes_to_hex_empty() {
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn bytes_to_hex_known() {
        assert_eq!(bytes_to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    // ──────────────────────────────────────────────────────────────────────
    // K. RegisterRequest serialization (14B.54)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn register_request_serializes() {
        let req = RegisterRequest {
            operator_hex: "aa".repeat(20),
            node_id_hex: "bb".repeat(32),
            class: "storage".to_string(),
            tls_fingerprint_hex: "cc".repeat(32),
            identity_proof_sig_hex: "dd".repeat(64),
            secret_hex: "ee".repeat(32),
            fee: "0".to_string(),
        };
        let json = serde_json::to_string(&req);
        assert!(json.is_ok(), "RegisterRequest must serialize to JSON");
    }

    #[test]
    fn submit_tx_response_deserializes() {
        let json = r#"{"success": true, "txid": "abc123", "message": "Transaction accepted"}"#;
        let result = serde_json::from_str::<SubmitTxResponse>(json);
        assert!(result.is_ok());
        if let Ok(res) = result {
            assert!(res.success);
            assert_eq!(res.txid, "abc123");
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // L. handle_register — validation failures (no network)
    // ──────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn register_invalid_class_errors() {
        let dir = std::env::temp_dir().join("dsdn_test_reg_class");
        std::fs::create_dir_all(&dir).ok();
        let result = handle_register(
            &dir,
            "validator",
            "http://127.0.0.1:8545",
            Some(std::path::Path::new("/tmp/dummy")),
        ).await;
        assert!(result.is_err(), "invalid class must fail before network");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn register_no_keyfile_errors() {
        let dir = std::env::temp_dir().join("dsdn_test_reg_nokey");
        std::fs::create_dir_all(&dir).ok();
        let result = handle_register(
            &dir,
            "storage",
            "http://127.0.0.1:8545",
            None,
        ).await;
        assert!(result.is_err(), "missing keyfile must fail before network");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn register_no_identity_errors() {
        let dir = std::env::temp_dir().join("dsdn_test_reg_noid");
        std::fs::create_dir_all(&dir).ok();
        let keyfile = dir.join("wallet.key");
        std::fs::write(&keyfile, "aa".repeat(32)).ok();
        let result = handle_register(
            &dir,
            "storage",
            "http://127.0.0.1:8545",
            Some(&keyfile),
        ).await;
        assert!(result.is_err(), "missing identity must fail before network");
        std::fs::remove_dir_all(&dir).ok();
    }
}
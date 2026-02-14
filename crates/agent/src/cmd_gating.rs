//! # Gating CLI Commands (14B.53–14B.57)
//!
//! Handles gating-related subcommands for the DSDN Agent CLI.
//!
//! ## Commands
//!
//! - `gating stake-check --address <hex> [--chain-rpc <url>] [--json]`
//! - `gating register --identity-dir <path> --class <storage|compute>
//!     --chain-rpc <url> [--keyfile <path>]`
//! - `gating status --address <hex> [--chain-rpc <url>] [--json]`
//! - `gating slashing-status --address <hex> [--chain-rpc <url>] [--json]`
//! - `gating node-class --address <hex> [--chain-rpc <url>] [--json]`
//! - `gating list-active [--chain-rpc <url>] [--json]`
//!
//! ## Chain RPC Resolution (stake-check, status)
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
//! - status (info): `GET {chain_rpc}/api/service_node/info/{operator_hex}`
//! - status (slashing): `GET {chain_rpc}/api/service_node/slashing/{operator_hex}`
//! - slashing-status: `GET {chain_rpc}/api/service_node/slashing/{operator_hex}`
//! - node-class: `GET {chain_rpc}/api/service_node/class/{operator_hex}`
//!              + `GET {chain_rpc}/api/service_node/stake/{operator_hex}`
//! - list-active: `GET {chain_rpc}/api/service_node/active`

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

/// REST path for service node info query (14B.55).
/// Maps to `FullNodeRpc::get_service_node_info` on chain node.
const INFO_ENDPOINT_PATH: &str = "/api/service_node/info/";

/// REST path for service node slashing status query (14B.55).
/// Maps to `FullNodeRpc::get_service_node_slashing_status` on chain node.
const SLASHING_ENDPOINT_PATH: &str = "/api/service_node/slashing/";

/// REST path for service node class query (14B.57).
/// Maps to `FullNodeRpc::get_service_node_class` on chain node.
const CLASS_ENDPOINT_PATH: &str = "/api/service_node/class/";

/// REST path for listing active service nodes (14B.57).
/// Maps to `FullNodeRpc::list_active_service_nodes` on chain node.
const ACTIVE_ENDPOINT_PATH: &str = "/api/service_node/active";

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
// STATUS RESPONSE TYPES (14B.55) — mirrors chain rpc.rs
// ════════════════════════════════════════════════════════════════════════════════

/// Response from chain RPC `get_service_node_info`.
///
/// Field names and types MUST match `ServiceNodeInfoRes` in chain rpc.rs.
#[derive(Deserialize, Debug, Clone)]
struct ServiceNodeInfoResponse {
    /// Operator address (hex string with 0x prefix)
    operator: String,
    /// Node ID as lowercase hex string (64 chars, no prefix)
    node_id_hex: String,
    /// Node class ("Storage" or "Compute")
    class: String,
    /// Node lifecycle status ("Pending", "Active", "Quarantined", "Banned")
    status: String,
    /// Staked amount (u128 as string, smallest unit)
    staked_amount: String,
    /// Block height at which the node was first registered
    registered_height: u64,
    /// TLS certificate fingerprint as lowercase hex (None if not set)
    tls_fingerprint_hex: Option<String>,
}

/// Response from chain RPC `get_service_node_slashing_status`.
///
/// Field names and types MUST match `ServiceNodeSlashingRes` in chain rpc.rs.
#[derive(Deserialize, Debug, Clone)]
struct ServiceNodeSlashingResponse {
    /// Operator address (hex string with 0x prefix)
    operator: String,
    /// Whether the node is currently slashed
    is_slashed: bool,
    /// Whether a cooldown period is currently active
    cooldown_active: bool,
    /// Seconds remaining in cooldown (None if not in cooldown)
    cooldown_remaining_secs: Option<u64>,
    /// Total count of slashing-related events
    slash_count: u64,
}

// ════════════════════════════════════════════════════════════════════════════════
// NODE-CLASS / LIST-ACTIVE RESPONSE TYPES (14B.57) — mirrors chain rpc.rs
// ════════════════════════════════════════════════════════════════════════════════

/// Response from chain RPC `get_service_node_class`.
///
/// Field names and types MUST match `ServiceNodeClassRes` in chain rpc.rs.
#[derive(Deserialize, Debug, Clone)]
struct ServiceNodeClassResponse {
    /// Operator address (hex string with 0x prefix)
    operator: String,
    /// Node class ("Storage" or "Compute")
    class: String,
    /// Minimum stake required for this class (u128 as string)
    min_stake_required: String,
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

/// Handles `gating status --address <hex> [--chain-rpc <url>] [--json]`.
///
/// Queries two chain RPC endpoints to assemble full gating status:
///
/// 1. `get_service_node_info` → identity, class, status, stake, TLS
/// 2. `get_service_node_slashing_status` → cooldown, slash count
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
pub async fn handle_status(
    address_hex: &str,
    chain_rpc_arg: Option<&str>,
    json: bool,
) -> Result<()> {
    // ── Step 1: Validate address ────────────────────────────────────────
    validate_operator_hex(address_hex)?;

    // ── Step 2: Resolve chain RPC endpoint ──────────────────────────────
    let chain_rpc = resolve_chain_rpc(chain_rpc_arg);
    let base = chain_rpc.trim_end_matches('/');

    // ── Step 3: Build HTTP client (reused for both queries) ─────────────
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;

    // ── Step 4: Query get_service_node_info ─────────────────────────────
    let info_url = format!("{}{}{}", base, INFO_ENDPOINT_PATH, address_hex);
    let info_res = query_chain_rpc::<ServiceNodeInfoResponse>(
        &client, &info_url, &chain_rpc, "node info",
    ).await?;

    // ── Step 5: Query get_service_node_slashing_status ──────────────────
    //            Non-fatal: if slashing endpoint fails, proceed without it
    let slashing_url = format!("{}{}{}", base, SLASHING_ENDPOINT_PATH, address_hex);
    let slashing_res = query_chain_rpc::<ServiceNodeSlashingResponse>(
        &client, &slashing_url, &chain_rpc, "slashing status",
    ).await.ok();

    // ── Step 6: Display ─────────────────────────────────────────────────
    if json {
        print_status_json(&info_res, slashing_res.as_ref());
    } else {
        print_status_table(&info_res, slashing_res.as_ref());
    }

    Ok(())
}

/// Handles `gating slashing-status --address <hex> [--chain-rpc <url>] [--json]`.
///
/// Queries chain RPC for slashing & cooldown status of a service node.
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
///
/// ## Notes
///
/// Chain `ServiceNodeSlashingRes` does NOT contain `last_slash_height`.
/// Only available fields: operator, is_slashed, cooldown_active,
/// cooldown_remaining_secs, slash_count.
pub async fn handle_slashing_status(
    address_hex: &str,
    chain_rpc_arg: Option<&str>,
    json: bool,
) -> Result<()> {
    // ── Step 1: Validate address ────────────────────────────────────────
    validate_operator_hex(address_hex)?;

    // ── Step 2: Resolve chain RPC endpoint ──────────────────────────────
    let chain_rpc = resolve_chain_rpc(chain_rpc_arg);
    let base = chain_rpc.trim_end_matches('/');

    // ── Step 3: Build HTTP client ───────────────────────────────────────
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;

    // ── Step 4: Query get_service_node_slashing_status ──────────────────
    let url = format!("{}{}{}", base, SLASHING_ENDPOINT_PATH, address_hex);
    let res = query_chain_rpc::<ServiceNodeSlashingResponse>(
        &client, &url, &chain_rpc, "slashing status",
    ).await?;

    // ── Step 5: Display ─────────────────────────────────────────────────
    if json {
        print_slashing_json(&res);
    } else {
        print_slashing_table(&res);
    }

    Ok(())
}

/// Handles `gating node-class --address <hex> [--chain-rpc <url>] [--json]`.
///
/// Queries TWO chain RPC endpoints to assemble node class information:
///
/// 1. `get_service_node_class` → class, min_stake_required
/// 2. `get_service_node_stake` → current_stake, meets_minimum
///
/// ## Errors
///
/// Returns `Err` if:
/// - Address is not valid 40-char hex.
/// - Either HTTP request to chain RPC fails.
/// - Chain RPC returns an error (node not found).
/// - Response JSON does not match expected schema.
pub async fn handle_node_class(
    address_hex: &str,
    chain_rpc_arg: Option<&str>,
    json: bool,
) -> Result<()> {
    // ── Step 1: Validate address ────────────────────────────────────────
    validate_operator_hex(address_hex)?;

    // ── Step 2: Resolve chain RPC endpoint ──────────────────────────────
    let chain_rpc = resolve_chain_rpc(chain_rpc_arg);
    let base = chain_rpc.trim_end_matches('/');

    // ── Step 3: Build HTTP client (reused for both queries) ─────────────
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;

    // ── Step 4: Query get_service_node_class ─────────────────────────────
    let class_url = format!("{}{}{}", base, CLASS_ENDPOINT_PATH, address_hex);
    let class_res = query_chain_rpc::<ServiceNodeClassResponse>(
        &client, &class_url, &chain_rpc, "node class",
    ).await?;

    // ── Step 5: Query get_service_node_stake ─────────────────────────────
    let stake_url = format!("{}{}{}", base, STAKE_ENDPOINT_PATH, address_hex);
    let stake_res = query_chain_rpc::<ServiceNodeStakeResponse>(
        &client, &stake_url, &chain_rpc, "node stake",
    ).await?;

    // ── Step 6: Display ─────────────────────────────────────────────────
    if json {
        print_node_class_json(&class_res, &stake_res);
    } else {
        print_node_class_table(&class_res, &stake_res);
    }

    Ok(())
}

/// Handles `gating list-active [--chain-rpc <url>] [--json]`.
///
/// Queries chain RPC for all active service nodes, sorts by stake
/// descending, and displays with per-class counts.
///
/// ## Notes
///
/// - Chain returns nodes filtered to `Active` status and sorted by operator.
/// - Agent re-sorts by staked_amount descending (deterministic: ties broken
///   by operator address ascending, matching chain's default order).
/// - Stake is parsed as u128 for sorting; unparseable values sort as 0.
///
/// ## Errors
///
/// Returns `Err` if:
/// - HTTP request to chain RPC fails.
/// - Response JSON does not match expected schema.
pub async fn handle_list_active(
    chain_rpc_arg: Option<&str>,
    json: bool,
) -> Result<()> {
    // ── Step 1: Resolve chain RPC endpoint ──────────────────────────────
    let chain_rpc = resolve_chain_rpc(chain_rpc_arg);
    let base = chain_rpc.trim_end_matches('/');

    // ── Step 2: Build HTTP client ───────────────────────────────────────
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {}", e))?;

    // ── Step 3: Query list_active_service_nodes ─────────────────────────
    let url = format!("{}{}", base, ACTIVE_ENDPOINT_PATH);
    let mut nodes = query_chain_rpc::<Vec<ServiceNodeInfoResponse>>(
        &client, &url, &chain_rpc, "active service nodes",
    ).await?;

    // ── Step 4: Sort by stake descending ────────────────────────────────
    //            Stable sort: ties preserve chain ordering (by operator asc)
    nodes.sort_by(|a, b| {
        let stake_a = a.staked_amount.parse::<u128>().unwrap_or(0);
        let stake_b = b.staked_amount.parse::<u128>().unwrap_or(0);
        stake_b.cmp(&stake_a)
    });

    // ── Step 5: Count by class ──────────────────────────────────────────
    let total = nodes.len();
    let storage_count = nodes.iter().filter(|n| n.class == "Storage").count();
    let compute_count = nodes.iter().filter(|n| n.class == "Compute").count();

    // ── Step 6: Display ─────────────────────────────────────────────────
    if json {
        print_active_json(&nodes);
    } else {
        print_active_table(&nodes, total, storage_count, compute_count);
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
// INTERNAL: DISPLAY (stake-check)
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

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: DISPLAY (status, 14B.55)
// ════════════════════════════════════════════════════════════════════════════════

/// Prints full gating status as a text table.
///
/// Slashing info is optional — if absent, cooldown shows "unknown".
fn print_status_table(
    info: &ServiceNodeInfoResponse,
    slashing: Option<&ServiceNodeSlashingResponse>,
) {
    println!("Node ID:          {}", info.node_id_hex);
    println!("Operator:         {}", info.operator);
    println!("Class:            {}", info.class);
    println!("Status:           {}", format_status_display(&info.status));
    println!("Stake:            {}", info.staked_amount);
    println!("Registered At:    block {}", info.registered_height);
    println!("Cooldown:         {}", format_cooldown(slashing));
    println!(
        "TLS Valid:        {}",
        if info.tls_fingerprint_hex.is_some() { "true" } else { "false" },
    );
}

/// Prints full gating status as JSON.
///
/// All fields are present, `null` for missing values.
fn print_status_json(
    info: &ServiceNodeInfoResponse,
    slashing: Option<&ServiceNodeSlashingResponse>,
) {
    let tls_valid = info.tls_fingerprint_hex.is_some();
    let cooldown = format_cooldown(slashing);

    // Build JSON manually for deterministic field ordering
    let cooldown_json = if cooldown == "none" {
        "null".to_string()
    } else {
        format!("\"{}\"", cooldown)
    };

    println!(
        "{{\
        \n  \"node_id\": \"{}\",\
        \n  \"operator\": \"{}\",\
        \n  \"class\": \"{}\",\
        \n  \"status\": \"{}\",\
        \n  \"staked_amount\": \"{}\",\
        \n  \"registered_height\": {},\
        \n  \"cooldown\": {},\
        \n  \"tls_valid\": {}\
        \n}}",
        info.node_id_hex,
        info.operator,
        info.class,
        info.status,
        info.staked_amount,
        info.registered_height,
        cooldown_json,
        tls_valid,
    );
}

/// Maps node status string to human-readable display with emoji.
///
/// Explicit match — unknown values are shown as-is with question mark.
fn format_status_display(status: &str) -> String {
    match status {
        "Active" => "\u{2705} Active".to_string(),
        "Pending" => "\u{23f3} Pending".to_string(),
        "Quarantined" => "\u{26a0}\u{fe0f} Quarantined".to_string(),
        "Banned" => "\u{274c} Banned".to_string(),
        other => format!("? {}", other),
    }
}

/// Formats cooldown information from slashing response.
///
/// Returns:
/// - `"none"` if no cooldown active
/// - `"<N>s remaining"` if cooldown active with known duration
/// - `"active (unknown duration)"` if cooldown active without duration
/// - `"unknown"` if slashing data is unavailable
fn format_cooldown(slashing: Option<&ServiceNodeSlashingResponse>) -> String {
    match slashing {
        None => "unknown".to_string(),
        Some(s) => {
            if !s.cooldown_active {
                "none".to_string()
            } else {
                match s.cooldown_remaining_secs {
                    Some(secs) => format!("{}s remaining", secs),
                    None => "active (unknown duration)".to_string(),
                }
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: DISPLAY (slashing-status, 14B.56)
// ════════════════════════════════════════════════════════════════════════════════

/// Prints slashing status as a text table.
///
/// If `slash_count == 0` and no active slashing/cooldown, prints a short
/// summary instead of full table.
fn print_slashing_table(res: &ServiceNodeSlashingResponse) {
    if res.slash_count == 0 && !res.is_slashed && !res.cooldown_active {
        println!("No slashing events found for {}", res.operator);
        return;
    }

    println!("Operator:           {}", res.operator);
    println!(
        "Slashed:            {}",
        if res.is_slashed { "true" } else { "false" },
    );
    println!("Slash Count:        {}", res.slash_count);
    println!(
        "Cooldown Active:    {}",
        if res.cooldown_active { "true" } else { "false" },
    );
    println!(
        "Cooldown Remaining: {}",
        format_cooldown_remaining(res.cooldown_active, res.cooldown_remaining_secs),
    );
}

/// Prints slashing status as JSON.
///
/// All fields are present. `cooldown_remaining_seconds` is `null` when
/// not in cooldown.
fn print_slashing_json(res: &ServiceNodeSlashingResponse) {
    let cooldown_json = match res.cooldown_remaining_secs {
        Some(secs) => format!("{}", secs),
        None => "null".to_string(),
    };

    println!(
        "{{\
        \n  \"operator\": \"{}\",\
        \n  \"is_slashed\": {},\
        \n  \"slash_count\": {},\
        \n  \"cooldown_active\": {},\
        \n  \"cooldown_remaining_seconds\": {}\
        \n}}",
        res.operator,
        res.is_slashed,
        res.slash_count,
        res.cooldown_active,
        cooldown_json,
    );
}

/// Formats cooldown remaining time for table display.
///
/// Returns:
/// - `"No cooldown"` if cooldown not active
/// - `"X hours Y minutes"` if cooldown active with known duration (hours > 0)
/// - `"Y minutes"` if cooldown active with known duration (hours == 0, min > 0)
/// - `"Z seconds"` if cooldown active with known duration (< 1 minute)
/// - `"Active (unknown duration)"` if cooldown active but no seconds
///
/// All arithmetic is overflow-safe (u64 division, no panics).
fn format_cooldown_remaining(active: bool, remaining_secs: Option<u64>) -> String {
    if !active {
        return "No cooldown".to_string();
    }

    match remaining_secs {
        Some(secs) => {
            let hours = secs / 3600;
            let minutes = (secs % 3600) / 60;
            if hours > 0 {
                format!("{} hours {} minutes", hours, minutes)
            } else if minutes > 0 {
                format!("{} minutes", minutes)
            } else {
                format!("{} seconds", secs)
            }
        }
        None => "Active (unknown duration)".to_string(),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: DISPLAY (node-class, 14B.57)
// ════════════════════════════════════════════════════════════════════════════════

/// Prints node class info as a text table.
fn print_node_class_table(
    class_res: &ServiceNodeClassResponse,
    stake_res: &ServiceNodeStakeResponse,
) {
    println!("Operator:               {}", class_res.operator);
    println!("Class:                  {}", class_res.class);
    println!("Minimum Stake Required: {}", class_res.min_stake_required);
    println!("Current Stake:          {}", stake_res.staked_amount);
    println!(
        "Meets Minimum:          {}",
        if stake_res.meets_minimum { "Yes" } else { "No" },
    );
}

/// Prints node class info as JSON.
fn print_node_class_json(
    class_res: &ServiceNodeClassResponse,
    stake_res: &ServiceNodeStakeResponse,
) {
    println!(
        "{{\
        \n  \"operator\": \"{}\",\
        \n  \"class\": \"{}\",\
        \n  \"min_stake_required\": \"{}\",\
        \n  \"current_stake\": \"{}\",\
        \n  \"meets_minimum\": {}\
        \n}}",
        class_res.operator,
        class_res.class,
        class_res.min_stake_required,
        stake_res.staked_amount,
        stake_res.meets_minimum,
    );
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: DISPLAY (list-active, 14B.57)
// ════════════════════════════════════════════════════════════════════════════════

/// Prints active nodes as a text table with footer counts.
///
/// Node ID is truncated to first 16 hex chars + "..." for readability.
/// Columns: Operator | Node ID | Class | Stake | Status
fn print_active_table(
    nodes: &[ServiceNodeInfoResponse],
    total: usize,
    storage_count: usize,
    compute_count: usize,
) {
    if nodes.is_empty() {
        println!("No active service nodes found.");
        println!();
        println!("Total Active Nodes: 0");
        return;
    }

    // Header
    println!(
        "{:<44} {:<19} {:<9} {:<26} {}",
        "Operator", "Node ID", "Class", "Stake", "Status",
    );
    println!("{}", "-".repeat(110));

    // Rows
    for node in nodes {
        println!(
            "{:<44} {:<19} {:<9} {:<26} {}",
            node.operator,
            truncate_node_id(&node.node_id_hex),
            node.class,
            node.staked_amount,
            node.status,
        );
    }

    // Footer
    println!();
    println!("Total Active Nodes: {}", total);
    println!("Storage Nodes:      {}", storage_count);
    println!("Compute Nodes:      {}", compute_count);
}

/// Prints active nodes as a JSON array.
///
/// Each element has: operator, node_id, class, stake, status.
/// Array is sorted by stake descending (caller ensures ordering).
fn print_active_json(nodes: &[ServiceNodeInfoResponse]) {
    println!("[");
    for (i, node) in nodes.iter().enumerate() {
        let comma = if i + 1 < nodes.len() { "," } else { "" };
        println!(
            "  {{\
            \n    \"operator\": \"{}\",\
            \n    \"node_id\": \"{}\",\
            \n    \"class\": \"{}\",\
            \n    \"stake\": \"{}\",\
            \n    \"status\": \"{}\"\
            \n  }}{}",
            node.operator,
            node.node_id_hex,
            node.class,
            node.staked_amount,
            node.status,
            comma,
        );
    }
    println!("]");
}

/// Truncates a node ID hex string for table display.
///
/// Shows first 16 hex characters followed by "..." for readability.
/// If the input is 16 chars or fewer, returns it unchanged.
fn truncate_node_id(hex: &str) -> String {
    if hex.len() <= 16 {
        hex.to_string()
    } else {
        let mut s = hex[..16].to_string();
        s.push_str("...");
        s
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: HTTP QUERY HELPER
// ════════════════════════════════════════════════════════════════════════════════

/// Generic HTTP GET → JSON parse for chain RPC queries.
///
/// Builds URL externally. Handles:
/// - HTTP request failure → error with chain_rpc in message
/// - Non-success HTTP status → try parse as `ChainRpcError`, fallback to body
/// - JSON parse failure → error with context
///
/// ## Parameters
///
/// - `client`: Shared `reqwest::Client` (reuse across multiple queries).
/// - `url`: Fully constructed URL.
/// - `chain_rpc`: Base RPC URL for error messages only.
/// - `context`: Human-readable name for error messages (e.g. "node info").
async fn query_chain_rpc<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    chain_rpc: &str,
    context: &str,
) -> Result<T> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to query {} from chain RPC at '{}': {}",
                context,
                chain_rpc,
                e,
            )
        })?;

    let http_status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("failed to read {} response body: {}", context, e))?;

    if !http_status.is_success() {
        if let Ok(rpc_err) = serde_json::from_str::<ChainRpcError>(&body) {
            return Err(anyhow::anyhow!(
                "chain RPC error querying {} (code {}): {}",
                context,
                rpc_err.code,
                rpc_err.message,
            ));
        }
        return Err(anyhow::anyhow!(
            "chain RPC returned HTTP {} for {}: {}",
            http_status.as_u16(),
            context,
            truncate_body(&body, 200),
        ));
    }

    serde_json::from_str::<T>(&body).map_err(|e| {
        anyhow::anyhow!(
            "failed to parse {} response from chain RPC: {}",
            context,
            e,
        )
    })
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

    // ──────────────────────────────────────────────────────────────────────
    // M. ServiceNodeInfoResponse deserialization (14B.55)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn deserialize_info_response_full() {
        let json = r#"{
            "operator": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "node_id_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "class": "Storage",
            "status": "Active",
            "staked_amount": "5000000000000000000000",
            "registered_height": 12345,
            "tls_fingerprint_hex": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }"#;
        let result = serde_json::from_str::<ServiceNodeInfoResponse>(json);
        assert!(result.is_ok(), "full info response must parse");
        if let Ok(res) = result {
            assert_eq!(res.status, "Active");
            assert_eq!(res.registered_height, 12345);
            assert!(res.tls_fingerprint_hex.is_some());
        }
    }

    #[test]
    fn deserialize_info_response_null_tls() {
        let json = r#"{
            "operator": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "node_id_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "class": "Compute",
            "status": "Pending",
            "staked_amount": "0",
            "registered_height": 0,
            "tls_fingerprint_hex": null
        }"#;
        let result = serde_json::from_str::<ServiceNodeInfoResponse>(json);
        assert!(result.is_ok(), "null tls must parse");
        if let Ok(res) = result {
            assert_eq!(res.status, "Pending");
            assert!(res.tls_fingerprint_hex.is_none());
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // N. ServiceNodeSlashingResponse deserialization (14B.55)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn deserialize_slashing_no_cooldown() {
        let json = r#"{
            "operator": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "is_slashed": false,
            "cooldown_active": false,
            "cooldown_remaining_secs": null,
            "slash_count": 0
        }"#;
        let result = serde_json::from_str::<ServiceNodeSlashingResponse>(json);
        assert!(result.is_ok(), "no-cooldown response must parse");
        if let Ok(res) = result {
            assert!(!res.cooldown_active);
            assert!(res.cooldown_remaining_secs.is_none());
        }
    }

    #[test]
    fn deserialize_slashing_with_cooldown() {
        let json = r#"{
            "operator": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "is_slashed": true,
            "cooldown_active": true,
            "cooldown_remaining_secs": 3600,
            "slash_count": 2
        }"#;
        let result = serde_json::from_str::<ServiceNodeSlashingResponse>(json);
        assert!(result.is_ok(), "cooldown response must parse");
        if let Ok(res) = result {
            assert!(res.is_slashed);
            assert!(res.cooldown_active);
            assert_eq!(res.cooldown_remaining_secs, Some(3600));
            assert_eq!(res.slash_count, 2);
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // O. format_status_display (14B.55)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn status_display_active() {
        let result = format_status_display("Active");
        assert!(result.contains("Active"));
    }

    #[test]
    fn status_display_pending() {
        let result = format_status_display("Pending");
        assert!(result.contains("Pending"));
    }

    #[test]
    fn status_display_quarantined() {
        let result = format_status_display("Quarantined");
        assert!(result.contains("Quarantined"));
    }

    #[test]
    fn status_display_banned() {
        let result = format_status_display("Banned");
        assert!(result.contains("Banned"));
    }

    #[test]
    fn status_display_unknown() {
        let result = format_status_display("SomeNewStatus");
        assert!(result.contains("SomeNewStatus"));
        assert!(result.starts_with("? "));
    }

    // ──────────────────────────────────────────────────────────────────────
    // P. format_cooldown (14B.55)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn cooldown_none_when_no_slashing() {
        assert_eq!(format_cooldown(None), "unknown");
    }

    #[test]
    fn cooldown_none_when_inactive() {
        let s = ServiceNodeSlashingResponse {
            operator: "0xaaaa".to_string(),
            is_slashed: false,
            cooldown_active: false,
            cooldown_remaining_secs: None,
            slash_count: 0,
        };
        assert_eq!(format_cooldown(Some(&s)), "none");
    }

    #[test]
    fn cooldown_with_remaining() {
        let s = ServiceNodeSlashingResponse {
            operator: "0xaaaa".to_string(),
            is_slashed: true,
            cooldown_active: true,
            cooldown_remaining_secs: Some(7200),
            slash_count: 1,
        };
        assert_eq!(format_cooldown(Some(&s)), "7200s remaining");
    }

    #[test]
    fn cooldown_active_no_duration() {
        let s = ServiceNodeSlashingResponse {
            operator: "0xaaaa".to_string(),
            is_slashed: true,
            cooldown_active: true,
            cooldown_remaining_secs: None,
            slash_count: 3,
        };
        assert_eq!(format_cooldown(Some(&s)), "active (unknown duration)");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Q. print_status_table / print_status_json smoke tests (14B.55)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn print_status_table_no_panic() {
        let info = ServiceNodeInfoResponse {
            operator: "0xaaaa".to_string(),
            node_id_hex: "bb".repeat(32),
            class: "Storage".to_string(),
            status: "Active".to_string(),
            staked_amount: "5000".to_string(),
            registered_height: 100,
            tls_fingerprint_hex: Some("cc".repeat(32)),
        };
        let slashing = ServiceNodeSlashingResponse {
            operator: "0xaaaa".to_string(),
            is_slashed: false,
            cooldown_active: false,
            cooldown_remaining_secs: None,
            slash_count: 0,
        };
        print_status_table(&info, Some(&slashing));
    }

    #[test]
    fn print_status_table_no_slashing_no_panic() {
        let info = ServiceNodeInfoResponse {
            operator: "0xaaaa".to_string(),
            node_id_hex: "bb".repeat(32),
            class: "Compute".to_string(),
            status: "Pending".to_string(),
            staked_amount: "0".to_string(),
            registered_height: 0,
            tls_fingerprint_hex: None,
        };
        print_status_table(&info, None);
    }

    #[test]
    fn print_status_json_no_panic() {
        let info = ServiceNodeInfoResponse {
            operator: "0xaaaa".to_string(),
            node_id_hex: "bb".repeat(32),
            class: "Storage".to_string(),
            status: "Quarantined".to_string(),
            staked_amount: "1000".to_string(),
            registered_height: 50,
            tls_fingerprint_hex: None,
        };
        let slashing = ServiceNodeSlashingResponse {
            operator: "0xaaaa".to_string(),
            is_slashed: true,
            cooldown_active: true,
            cooldown_remaining_secs: Some(3600),
            slash_count: 1,
        };
        print_status_json(&info, Some(&slashing));
    }

    // ──────────────────────────────────────────────────────────────────────
    // R. handle_status — validation failures (no network, 14B.55)
    // ──────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn status_invalid_address_errors() {
        let result = handle_status("short", None, false).await;
        assert!(result.is_err(), "invalid address must fail before HTTP");
    }

    #[tokio::test]
    async fn status_0x_prefix_errors() {
        let hex = format!("0x{}", "aa".repeat(19));
        let result = handle_status(&hex, None, false).await;
        assert!(result.is_err(), "0x prefix must fail before HTTP");
    }

    #[tokio::test]
    async fn status_nonhex_errors() {
        let hex = "gg".repeat(20);
        let result = handle_status(&hex, None, false).await;
        assert!(result.is_err(), "non-hex must fail before HTTP");
    }

    // ──────────────────────────────────────────────────────────────────────
    // S. print_slashing_table / print_slashing_json smoke tests (14B.56)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn print_slashing_table_no_events() {
        let res = ServiceNodeSlashingResponse {
            operator: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            is_slashed: false,
            cooldown_active: false,
            cooldown_remaining_secs: None,
            slash_count: 0,
        };
        // Must print "No slashing events found" and not panic
        print_slashing_table(&res);
    }

    #[test]
    fn print_slashing_table_active_slash() {
        let res = ServiceNodeSlashingResponse {
            operator: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            is_slashed: true,
            cooldown_active: true,
            cooldown_remaining_secs: Some(7200),
            slash_count: 2,
        };
        print_slashing_table(&res);
    }

    #[test]
    fn print_slashing_json_no_events() {
        let res = ServiceNodeSlashingResponse {
            operator: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            is_slashed: false,
            cooldown_active: false,
            cooldown_remaining_secs: None,
            slash_count: 0,
        };
        // Must output valid JSON even with no events
        print_slashing_json(&res);
    }

    #[test]
    fn print_slashing_json_active_cooldown() {
        let res = ServiceNodeSlashingResponse {
            operator: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            is_slashed: true,
            cooldown_active: true,
            cooldown_remaining_secs: Some(3600),
            slash_count: 5,
        };
        print_slashing_json(&res);
    }

    // ──────────────────────────────────────────────────────────────────────
    // T. format_cooldown_remaining (14B.56)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn cooldown_remaining_not_active() {
        assert_eq!(format_cooldown_remaining(false, None), "No cooldown");
    }

    #[test]
    fn cooldown_remaining_not_active_with_secs() {
        // Even if secs present, if not active → "No cooldown"
        assert_eq!(format_cooldown_remaining(false, Some(3600)), "No cooldown");
    }

    #[test]
    fn cooldown_remaining_hours_and_minutes() {
        assert_eq!(
            format_cooldown_remaining(true, Some(7200)),
            "2 hours 0 minutes",
        );
    }

    #[test]
    fn cooldown_remaining_mixed() {
        assert_eq!(
            format_cooldown_remaining(true, Some(5400)),
            "1 hours 30 minutes",
        );
    }

    #[test]
    fn cooldown_remaining_minutes_only() {
        assert_eq!(
            format_cooldown_remaining(true, Some(300)),
            "5 minutes",
        );
    }

    #[test]
    fn cooldown_remaining_seconds_only() {
        assert_eq!(
            format_cooldown_remaining(true, Some(45)),
            "45 seconds",
        );
    }

    #[test]
    fn cooldown_remaining_zero() {
        assert_eq!(
            format_cooldown_remaining(true, Some(0)),
            "0 seconds",
        );
    }

    #[test]
    fn cooldown_remaining_unknown() {
        assert_eq!(
            format_cooldown_remaining(true, None),
            "Active (unknown duration)",
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // U. handle_slashing_status — validation failures (no network, 14B.56)
    // ──────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn slashing_status_invalid_address_errors() {
        let result = handle_slashing_status("short", None, false).await;
        assert!(result.is_err(), "invalid address must fail before HTTP");
    }

    #[tokio::test]
    async fn slashing_status_0x_prefix_errors() {
        let hex = format!("0x{}", "aa".repeat(19));
        let result = handle_slashing_status(&hex, None, false).await;
        assert!(result.is_err(), "0x prefix must fail before HTTP");
    }

    #[tokio::test]
    async fn slashing_status_nonhex_errors() {
        let hex = "gg".repeat(20);
        let result = handle_slashing_status(&hex, None, false).await;
        assert!(result.is_err(), "non-hex must fail before HTTP");
    }

    // ──────────────────────────────────────────────────────────────────────
    // V. ServiceNodeClassResponse deserialization (14B.57)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn deserialize_class_response() {
        let json = r#"{
            "operator": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "class": "Storage",
            "min_stake_required": "5000000000000000000000"
        }"#;
        let result = serde_json::from_str::<ServiceNodeClassResponse>(json);
        assert!(result.is_ok(), "class response must parse");
        if let Ok(res) = result {
            assert_eq!(res.class, "Storage");
        }
    }

    #[test]
    fn deserialize_class_response_compute() {
        let json = r#"{
            "operator": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "class": "Compute",
            "min_stake_required": "1000000000000000000000"
        }"#;
        let result = serde_json::from_str::<ServiceNodeClassResponse>(json);
        assert!(result.is_ok());
        if let Ok(res) = result {
            assert_eq!(res.class, "Compute");
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // W. print_node_class smoke tests (14B.57)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn print_node_class_table_no_panic() {
        let class_res = ServiceNodeClassResponse {
            operator: "0xaaaa".to_string(),
            class: "Storage".to_string(),
            min_stake_required: "5000".to_string(),
        };
        let stake_res = ServiceNodeStakeResponse {
            operator: "0xaaaa".to_string(),
            staked_amount: "10000".to_string(),
            class: "Storage".to_string(),
            meets_minimum: true,
        };
        print_node_class_table(&class_res, &stake_res);
    }

    #[test]
    fn print_node_class_json_no_panic() {
        let class_res = ServiceNodeClassResponse {
            operator: "0xbbbb".to_string(),
            class: "Compute".to_string(),
            min_stake_required: "1000".to_string(),
        };
        let stake_res = ServiceNodeStakeResponse {
            operator: "0xbbbb".to_string(),
            staked_amount: "500".to_string(),
            class: "Compute".to_string(),
            meets_minimum: false,
        };
        print_node_class_json(&class_res, &stake_res);
    }

    // ──────────────────────────────────────────────────────────────────────
    // X. truncate_node_id (14B.57)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn truncate_node_id_long() {
        let hex = "aa".repeat(32); // 64 chars
        let result = truncate_node_id(&hex);
        assert_eq!(result.len(), 19); // 16 + "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_node_id_short() {
        let hex = "aabb";
        assert_eq!(truncate_node_id(hex), "aabb");
    }

    #[test]
    fn truncate_node_id_exact() {
        let hex = "a".repeat(16);
        assert_eq!(truncate_node_id(&hex), hex);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Y. print_active smoke tests (14B.57)
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn print_active_table_empty() {
        let nodes: Vec<ServiceNodeInfoResponse> = vec![];
        print_active_table(&nodes, 0, 0, 0);
    }

    #[test]
    fn print_active_table_with_nodes() {
        let nodes = vec![
            ServiceNodeInfoResponse {
                operator: "0xaaaa".to_string(),
                node_id_hex: "bb".repeat(32),
                class: "Storage".to_string(),
                status: "Active".to_string(),
                staked_amount: "10000".to_string(),
                registered_height: 100,
                tls_fingerprint_hex: Some("cc".repeat(32)),
            },
            ServiceNodeInfoResponse {
                operator: "0xdddd".to_string(),
                node_id_hex: "ee".repeat(32),
                class: "Compute".to_string(),
                status: "Active".to_string(),
                staked_amount: "5000".to_string(),
                registered_height: 200,
                tls_fingerprint_hex: None,
            },
        ];
        print_active_table(&nodes, 2, 1, 1);
    }

    #[test]
    fn print_active_json_empty() {
        let nodes: Vec<ServiceNodeInfoResponse> = vec![];
        print_active_json(&nodes);
    }

    #[test]
    fn print_active_json_with_nodes() {
        let nodes = vec![
            ServiceNodeInfoResponse {
                operator: "0xaaaa".to_string(),
                node_id_hex: "bb".repeat(32),
                class: "Storage".to_string(),
                status: "Active".to_string(),
                staked_amount: "10000".to_string(),
                registered_height: 100,
                tls_fingerprint_hex: None,
            },
        ];
        print_active_json(&nodes);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Z. handle_node_class — validation failures (no network, 14B.57)
    // ──────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn node_class_invalid_address_errors() {
        let result = handle_node_class("short", None, false).await;
        assert!(result.is_err(), "invalid address must fail before HTTP");
    }

    #[tokio::test]
    async fn node_class_0x_prefix_errors() {
        let hex = format!("0x{}", "aa".repeat(19));
        let result = handle_node_class(&hex, None, false).await;
        assert!(result.is_err(), "0x prefix must fail before HTTP");
    }

    #[tokio::test]
    async fn node_class_nonhex_errors() {
        let hex = "gg".repeat(20);
        let result = handle_node_class(&hex, None, false).await;
        assert!(result.is_err(), "non-hex must fail before HTTP");
    }
}
//! # Gating CLI Commands (14B.53)
//!
//! Handles gating-related subcommands for the DSDN Agent CLI.
//!
//! ## Commands
//!
//! - `gating stake-check --address <hex> [--chain-rpc <url>] [--json]`
//!
//! ## Chain RPC Resolution
//!
//! Endpoint resolution order:
//! 1. `--chain-rpc <url>` argument (highest priority)
//! 2. `DSDN_CHAIN_RPC` environment variable
//! 3. Default: `http://127.0.0.1:8545`
//!
//! ## Endpoint
//!
//! Calls `GET {chain_rpc}/api/service_node/stake/{operator_hex}`
//! which maps to `FullNodeRpc::get_service_node_stake` on the chain node.
//!
//! ## Response Type
//!
//! Expects JSON matching `ServiceNodeStakeRes` from chain rpc.rs:
//! ```json
//! {
//!   "operator": "0x...",
//!   "staked_amount": "5000000000000000000000",
//!   "class": "Storage",
//!   "meets_minimum": true
//! }
//! ```

use anyhow::Result;
use serde::Deserialize;

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
}
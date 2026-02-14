//! # Identity CLI Commands (14B.51)
//!
//! Handles the `identity generate` subcommand for the DSDN Agent CLI.
//!
//! ## Commands
//!
//! - `identity generate`: Generate a new Ed25519 identity keypair.
//!   - `--out-dir <path>`: Persist identity to disk via `IdentityStore`.
//!   - `--operator <hex>`: Override operator address (40 hex chars).
//!
//! ## Behavior
//!
//! Without `--out-dir`: ephemeral generation, printed to stdout only.
//! No files created or read.
//!
//! With `--out-dir`: uses `IdentityStore::load_or_generate()` to either
//! load an existing identity or generate and persist a new one. If
//! `--operator` is provided, the operator address file is overwritten.
//!
//! ## Output Format
//!
//! ```text
//! node_id: <64 hex chars>
//! operator_address: <40 hex chars>
//! key_path: <path>          (only with --out-dir)
//! operator_path: <path>     (only with --out-dir)
//! ```

use std::path::Path;

use anyhow::Result;

use dsdn_node::{IdentityStore, NodeIdentityManager};

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════════════════════════════════════

/// Handles `identity generate`.
///
/// ## Parameters
///
/// - `out_dir`: If `Some`, persist identity to this directory.
/// - `operator_hex`: If `Some`, override operator address (must be
///   exactly 40 lowercase/uppercase hex characters, no `0x` prefix).
///
/// ## Errors
///
/// Returns `Err` if:
/// - `--operator` value is not valid hex or not 40 characters.
/// - Identity generation fails (OS entropy unavailable).
/// - Disk I/O fails when `--out-dir` is provided.
pub fn handle_identity_generate(
    out_dir: Option<&Path>,
    operator_hex: Option<&str>,
) -> Result<()> {
    // Step 1: Validate --operator if provided (before any I/O)
    let operator_override: Option<[u8; 20]> = match operator_hex {
        Some(hex) => Some(parse_operator_hex(hex)?),
        None => None,
    };

    // Step 2: Generate or load identity
    match out_dir {
        Some(dir) => handle_persistent(dir, operator_override),
        None => handle_ephemeral(operator_override),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: PERSISTENT PATH
// ════════════════════════════════════════════════════════════════════════════════

/// Persistent generation: uses `IdentityStore::load_or_generate()`.
///
/// If the directory already contains a valid identity, it is loaded
/// (not regenerated). If `operator_override` is `Some`, the stored
/// operator address file is overwritten.
fn handle_persistent(
    dir: &Path,
    operator_override: Option<[u8; 20]>,
) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to create output directory '{}': {}",
            dir.display(),
            e,
        )
    })?;

    let store = IdentityStore::new(dir.to_path_buf());
    let mgr = store.load_or_generate().map_err(|e| {
        anyhow::anyhow!("identity generation/load failed: {}", e)
    })?;

    // If --operator override, save custom operator address
    if let Some(op_bytes) = operator_override {
        store.save_operator_address(&op_bytes).map_err(|e| {
            anyhow::anyhow!("failed to save operator address: {}", e)
        })?;
    }

    // Determine which operator to display
    let display_operator = match operator_override {
        Some(op) => op,
        None => *mgr.operator_address(),
    };

    // Print results with file paths
    let key_path = dir.join("node_identity.key");
    let operator_path = dir.join("operator.addr");

    println!("node_id: {}", bytes_to_hex(mgr.node_id()));
    println!("operator_address: {}", bytes_to_hex(&display_operator));
    println!("key_path: {}", key_path.display());
    println!("operator_path: {}", operator_path.display());

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// INTERNAL: EPHEMERAL PATH
// ════════════════════════════════════════════════════════════════════════════════

/// Ephemeral generation: no disk I/O. Prints identity to stdout only.
fn handle_ephemeral(operator_override: Option<[u8; 20]>) -> Result<()> {
    let mgr = NodeIdentityManager::generate().map_err(|e| {
        anyhow::anyhow!("identity generation failed: {}", e)
    })?;

    let display_operator = match operator_override {
        Some(op) => op,
        None => *mgr.operator_address(),
    };

    println!("node_id: {}", bytes_to_hex(mgr.node_id()));
    println!("operator_address: {}", bytes_to_hex(&display_operator));

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════════
// HEX UTILITIES
// ════════════════════════════════════════════════════════════════════════════════

/// Parses a hex-encoded operator address string into `[u8; 20]`.
///
/// ## Validation
///
/// - Must be exactly 40 characters (20 bytes in hex).
/// - Must contain only valid hex digits (0-9, a-f, A-F).
/// - Leading `0x` prefix is NOT accepted (explicit rejection).
fn parse_operator_hex(hex: &str) -> Result<[u8; 20]> {
    // Reject 0x prefix explicitly
    if hex.starts_with("0x") || hex.starts_with("0X") {
        return Err(anyhow::anyhow!(
            "operator address must be 40 hex characters without 0x prefix, got '{}'",
            hex,
        ));
    }

    if hex.len() != 40 {
        return Err(anyhow::anyhow!(
            "operator address must be exactly 40 hex characters (20 bytes), got {} characters",
            hex.len(),
        ));
    }

    // Validate all chars are hex before parsing
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "operator address contains non-hex characters: '{}'",
            hex,
        ));
    }

    let hex_bytes = hex.as_bytes();
    let mut result = [0u8; 20];
    for i in 0..20 {
        let hi = decode_hex_nibble(hex_bytes[i * 2]);
        let lo = decode_hex_nibble(hex_bytes[i * 2 + 1]);
        result[i] = (hi << 4) | lo;
    }

    Ok(result)
}

/// Converts a single ASCII hex digit to its numeric value (0–15).
///
/// Caller MUST ensure `b` is a valid hex digit. This function is only
/// called after full hex validation in `parse_operator_hex`.
fn decode_hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        // Pre-validated: unreachable after hex validation.
        // Returns 0 as safe fallback (no panic).
        _ => 0,
    }
}

/// Converts a byte slice to a lowercase hex string (no `0x` prefix).
fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────────
    // A. parse_operator_hex
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn parse_hex_valid_lowercase() {
        let hex = "aa".repeat(20);
        let result = parse_operator_hex(&hex);
        assert!(result.is_ok(), "valid lowercase hex must succeed");
        if let Ok(bytes) = result {
            assert_eq!(bytes, [0xAA; 20]);
        }
    }

    #[test]
    fn parse_hex_valid_uppercase() {
        let hex = "BB".repeat(20);
        let result = parse_operator_hex(&hex);
        assert!(result.is_ok(), "valid uppercase hex must succeed");
        if let Ok(bytes) = result {
            assert_eq!(bytes, [0xBB; 20]);
        }
    }

    #[test]
    fn parse_hex_valid_mixed_case() {
        let hex = "aAbBcCdDeEfF00112233aAbBcCdDeEfF00112233";
        let result = parse_operator_hex(hex);
        assert!(result.is_ok(), "valid mixed-case hex must succeed");
    }

    #[test]
    fn parse_hex_wrong_length_short() {
        let result = parse_operator_hex("aabb");
        assert!(result.is_err(), "short hex must fail");
    }

    #[test]
    fn parse_hex_wrong_length_long() {
        let hex = "aa".repeat(21);
        let result = parse_operator_hex(&hex);
        assert!(result.is_err(), "long hex must fail");
    }

    #[test]
    fn parse_hex_invalid_chars() {
        let hex = "gg".repeat(20);
        let result = parse_operator_hex(&hex);
        assert!(result.is_err(), "non-hex chars must fail");
    }

    #[test]
    fn parse_hex_rejects_0x_prefix() {
        let hex = format!("0x{}", "aa".repeat(19));
        let result = parse_operator_hex(&hex);
        assert!(result.is_err(), "0x prefix must be rejected");
    }

    #[test]
    fn parse_hex_empty() {
        let result = parse_operator_hex("");
        assert!(result.is_err(), "empty string must fail");
    }

    #[test]
    fn parse_hex_all_zeros() {
        let hex = "00".repeat(20);
        let result = parse_operator_hex(&hex);
        assert!(result.is_ok());
        if let Ok(bytes) = result {
            assert_eq!(bytes, [0u8; 20]);
        }
    }

    #[test]
    fn parse_hex_all_ff() {
        let hex = "ff".repeat(20);
        let result = parse_operator_hex(&hex);
        assert!(result.is_ok());
        if let Ok(bytes) = result {
            assert_eq!(bytes, [0xFF; 20]);
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // B. bytes_to_hex
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn hex_encode_basic() {
        assert_eq!(bytes_to_hex(&[0xAB, 0xCD, 0x01]), "abcd01");
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn hex_encode_zeros() {
        assert_eq!(bytes_to_hex(&[0, 0, 0]), "000000");
    }

    #[test]
    fn hex_encode_ff() {
        assert_eq!(bytes_to_hex(&[0xFF, 0xFF]), "ffff");
    }

    #[test]
    fn hex_encode_32_bytes() {
        let bytes = [0x01u8; 32];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex.len(), 64, "32 bytes = 64 hex chars");
    }

    #[test]
    fn hex_encode_20_bytes() {
        let bytes = [0xAA; 20];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex.len(), 40, "20 bytes = 40 hex chars");
        assert_eq!(hex, "aa".repeat(20));
    }

    // ──────────────────────────────────────────────────────────────────────
    // C. decode_hex_nibble
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn nibble_digits() {
        for d in 0..=9u8 {
            assert_eq!(decode_hex_nibble(b'0' + d), d);
        }
    }

    #[test]
    fn nibble_lowercase() {
        for (i, c) in (b'a'..=b'f').enumerate() {
            assert_eq!(decode_hex_nibble(c), (i as u8) + 10);
        }
    }

    #[test]
    fn nibble_uppercase() {
        for (i, c) in (b'A'..=b'F').enumerate() {
            assert_eq!(decode_hex_nibble(c), (i as u8) + 10);
        }
    }

    #[test]
    fn nibble_invalid_returns_zero() {
        // After pre-validation, this branch is unreachable in production.
        // Tests the safe fallback behavior.
        assert_eq!(decode_hex_nibble(b'g'), 0);
        assert_eq!(decode_hex_nibble(b' '), 0);
    }

    // ──────────────────────────────────────────────────────────────────────
    // D. handle_identity_generate — ephemeral
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn generate_ephemeral_succeeds() {
        let result = handle_identity_generate(None, None);
        assert!(result.is_ok(), "ephemeral generate must succeed");
    }

    #[test]
    fn generate_ephemeral_with_operator() {
        let op = "aa".repeat(20);
        let result = handle_identity_generate(None, Some(&op));
        assert!(result.is_ok(), "ephemeral + operator must succeed");
    }

    #[test]
    fn generate_ephemeral_invalid_operator() {
        let result = handle_identity_generate(None, Some("short"));
        assert!(result.is_err(), "invalid operator must fail");
    }

    // ──────────────────────────────────────────────────────────────────────
    // E. handle_identity_generate — persistent
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn generate_persistent_creates_files() {
        let dir = std::env::temp_dir().join(format!(
            "dsdn_cmd_id_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let result = handle_identity_generate(Some(dir.as_path()), None);
        assert!(result.is_ok(), "persistent generate must succeed");

        assert!(
            dir.join("node_identity.key").is_file(),
            "key file must exist"
        );
        assert!(
            dir.join("operator.addr").is_file(),
            "operator file must exist"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_persistent_with_operator_override() {
        let dir = std::env::temp_dir().join(format!(
            "dsdn_cmd_id_op_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let op = "bb".repeat(20);
        let result = handle_identity_generate(Some(dir.as_path()), Some(&op));
        assert!(result.is_ok(), "persistent + operator must succeed");

        let store = IdentityStore::new(dir.clone());
        let loaded = store.load_operator_address();
        assert!(loaded.is_ok(), "operator must be loadable");
        if let Ok(addr) = loaded {
            assert_eq!(addr, [0xBB; 20], "operator must match override");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_persistent_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "dsdn_cmd_id_idem_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let r1 = handle_identity_generate(Some(dir.as_path()), None);
        assert!(r1.is_ok());

        let r2 = handle_identity_generate(Some(dir.as_path()), None);
        assert!(r2.is_ok(), "idempotent call must succeed");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
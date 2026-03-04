//! # Economic Validation & Chain Forwarding (14C.C.27)
//!
//! Validation layer, input sanitization, and chain forwarding abstraction
//! for all economic endpoints.
//!
//! ## Validation
//!
//! All validation functions perform input sanitization (trim whitespace)
//! before applying rules. Validation logic lives ONLY in this module —
//! handlers delegate here, no duplicate logic.
//!
//! ## Chain Forwarding
//!
//! [`ChainForwarder`] is the single abstraction through which all handlers
//! query the chain. It implements [`ReceiptQueryService`] and
//! [`RewardQueryService`] with built-in retry logic.
//!
//! Currently a stub — real RPC calls will replace the placeholder
//! implementations when the chain layer is connected.
//!
//! ## Retry
//!
//! All forwarded operations go through [`retry_async`] which provides
//! exponential backoff with configurable max retries and base delay.

#![allow(dead_code)]

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::economic_handlers::{
    ChainReceiptInfo, ChainRewardInfo, ChainTreasuryInfo, ChainValidatorRewardInfo,
    ReceiptQueryService, ReceiptStatus, RewardQueryService,
};

// ════════════════════════════════════════════════════════════════════════════
// VALIDATION ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Validation error with structured context.
///
/// `Send + Sync + Debug + Display` compatible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Field contains non-hex or otherwise malformed hex data.
    InvalidHexFormat {
        field: String,
        value: String,
    },

    /// Field has wrong length.
    InvalidLength {
        field: String,
        expected: usize,
        got: usize,
    },

    /// Required field is empty.
    EmptyField {
        field: String,
    },

    /// Request was rate limited.
    RateLimited {
        retry_after_secs: u64,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::InvalidHexFormat { field, value } => {
                write!(f, "invalid hex format for {}: '{}'", field, value)
            }
            ValidationError::InvalidLength {
                field,
                expected,
                got,
            } => {
                write!(
                    f,
                    "{} must be exactly {} characters, got {}",
                    field, expected, got
                )
            }
            ValidationError::EmptyField { field } => {
                write!(f, "{} must not be empty", field)
            }
            ValidationError::RateLimited { retry_after_secs } => {
                write!(f, "rate limited, retry after {} seconds", retry_after_secs)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

// ════════════════════════════════════════════════════════════════════════════
// INPUT SANITIZATION
// ════════════════════════════════════════════════════════════════════════════

/// Sanitize input by trimming leading and trailing whitespace.
///
/// All validation functions call this before applying rules.
pub fn sanitize_input(input: &str) -> String {
    input.trim().to_string()
}

// ════════════════════════════════════════════════════════════════════════════
// VALIDATE RECEIPT HASH
// ════════════════════════════════════════════════════════════════════════════

/// Validate and sanitize a receipt hash.
///
/// 1. Trim whitespace (sanitize)
/// 2. Not empty
/// 3. No remaining whitespace
/// 4. No `0x` / `0X` prefix
/// 5. Exactly 64 characters
/// 6. All valid hex characters
///
/// Returns sanitized hash on success.
pub fn validate_receipt_hash(hash: &str) -> Result<String, ValidationError> {
    let sanitized = sanitize_input(hash);

    if sanitized.is_empty() {
        return Err(ValidationError::EmptyField {
            field: "receipt_hash".to_string(),
        });
    }

    if sanitized.chars().any(|c| c.is_whitespace()) {
        return Err(ValidationError::InvalidHexFormat {
            field: "receipt_hash".to_string(),
            value: sanitized,
        });
    }

    if sanitized.starts_with("0x") || sanitized.starts_with("0X") {
        return Err(ValidationError::InvalidHexFormat {
            field: "receipt_hash".to_string(),
            value: sanitized,
        });
    }

    if sanitized.len() != 64 {
        return Err(ValidationError::InvalidLength {
            field: "receipt_hash".to_string(),
            expected: 64,
            got: sanitized.len(),
        });
    }

    if !sanitized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidHexFormat {
            field: "receipt_hash".to_string(),
            value: sanitized,
        });
    }

    Ok(sanitized)
}

// ════════════════════════════════════════════════════════════════════════════
// VALIDATE ADDRESS
// ════════════════════════════════════════════════════════════════════════════

/// Validate and sanitize an address.
///
/// 1. Trim whitespace (sanitize)
/// 2. Not empty
/// 3. No remaining whitespace
/// 4. No `0x` / `0X` prefix
/// 5. Exactly 40 characters
/// 6. All valid hex characters
///
/// Returns sanitized address on success.
pub fn validate_address(addr: &str) -> Result<String, ValidationError> {
    let sanitized = sanitize_input(addr);

    if sanitized.is_empty() {
        return Err(ValidationError::EmptyField {
            field: "address".to_string(),
        });
    }

    if sanitized.chars().any(|c| c.is_whitespace()) {
        return Err(ValidationError::InvalidHexFormat {
            field: "address".to_string(),
            value: sanitized,
        });
    }

    if sanitized.starts_with("0x") || sanitized.starts_with("0X") {
        return Err(ValidationError::InvalidHexFormat {
            field: "address".to_string(),
            value: sanitized,
        });
    }

    if sanitized.len() != 40 {
        return Err(ValidationError::InvalidLength {
            field: "address".to_string(),
            expected: 40,
            got: sanitized.len(),
        });
    }

    if !sanitized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidHexFormat {
            field: "address".to_string(),
            value: sanitized,
        });
    }

    Ok(sanitized)
}

// ════════════════════════════════════════════════════════════════════════════
// VALIDATE PROOF TYPE
// ════════════════════════════════════════════════════════════════════════════

/// Allowed proof type values.
const VALID_PROOF_TYPES: [&str; 3] = [
    "execution_mismatch",
    "invalid_commitment",
    "resource_inflation",
];

/// Validate and sanitize a proof type.
///
/// After trim, must be exactly one of the allowed values.
/// Returns sanitized proof type on success.
pub fn validate_proof_type(proof_type: &str) -> Result<String, ValidationError> {
    let sanitized = sanitize_input(proof_type);

    if sanitized.is_empty() {
        return Err(ValidationError::EmptyField {
            field: "proof_type".to_string(),
        });
    }

    if VALID_PROOF_TYPES.contains(&sanitized.as_str()) {
        Ok(sanitized)
    } else {
        Err(ValidationError::InvalidHexFormat {
            field: "proof_type".to_string(),
            value: sanitized,
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CLAIM REWARD REQUEST
// ════════════════════════════════════════════════════════════════════════════

/// Request body for claiming a reward.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRewardRequest {
    /// Receipt hash (hex, 64 chars).
    pub receipt_hash: String,
    /// Submitter address (hex, 40 chars).
    pub submitter_address: String,
    /// Receipt data bytes. Must not be empty.
    pub receipt_data: Vec<u8>,
}

/// Validate a claim reward request (sanitizes all fields).
///
/// - `receipt_hash`: valid 64-char hex
/// - `submitter_address`: valid 40-char hex
/// - `receipt_data`: not empty
pub fn validate_claim_request(req: &ClaimRewardRequest) -> Result<(), ValidationError> {
    validate_receipt_hash(&req.receipt_hash)?;
    validate_address(&req.submitter_address)?;

    if req.receipt_data.is_empty() {
        return Err(ValidationError::EmptyField {
            field: "receipt_data".to_string(),
        });
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// CHAIN RESPONSE TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Generic response from chain forwarding operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainResponse {
    /// Whether the operation succeeded.
    pub success: bool,
    /// Human-readable message.
    pub message: String,
}

/// Balance information returned by chain query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceInfo {
    pub balance: u128,
    pub pending_rewards: u128,
    pub claimed_rewards: u128,
    pub node_earnings: u128,
    pub is_validator: bool,
    pub is_node: bool,
}

// ════════════════════════════════════════════════════════════════════════════
// RETRY LOGIC
// ════════════════════════════════════════════════════════════════════════════

/// Execute an async operation with exponential backoff retry.
///
/// - `max_retries`: maximum number of attempts (must be ≥ 1)
/// - `base_delay_ms`: initial delay between retries in milliseconds
/// - `make_future`: factory that creates the operation future on each attempt
///
/// On first success, returns immediately. On failure after all retries, returns
/// the last error.
pub async fn retry_async<T, F, Fut>(
    max_retries: u32,
    base_delay_ms: u64,
    mut make_future: F,
) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let effective_retries = if max_retries == 0 { 1 } else { max_retries };
    let mut attempt = 0u32;

    loop {
        match make_future().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                attempt = attempt.saturating_add(1);
                if attempt >= effective_retries {
                    return Err(format!(
                        "max retries ({}) exceeded, last error: {}",
                        effective_retries, e
                    ));
                }
                let shift = attempt.min(6);
                let delay_ms = base_delay_ms.saturating_mul(1u64.wrapping_shl(shift));
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CHAIN FORWARDER
// ════════════════════════════════════════════════════════════════════════════

/// Chain forwarding abstraction.
///
/// All economic endpoint queries go through this forwarder.
/// Implements [`ReceiptQueryService`] and [`RewardQueryService`] with
/// built-in retry logic.
///
/// Currently a stub — returns default/not-found values.
/// Real RPC calls will be wired in when chain layer is connected.
///
/// # Thread Safety
///
/// `Send + Sync + 'static` — all fields are owned, no interior mutability.
#[derive(Debug, Clone)]
pub struct ChainForwarder {
    /// Chain RPC endpoint URL.
    pub chain_endpoint: String,
    /// Timeout for each individual RPC call.
    pub timeout: Duration,
    /// Maximum retry attempts for transient failures.
    pub max_retries: u32,
    /// Base delay between retries (exponential backoff).
    pub retry_base_delay_ms: u64,
}

impl ChainForwarder {
    /// Create a new forwarder with default retry settings.
    pub fn new(chain_endpoint: String, timeout: Duration) -> Self {
        Self {
            chain_endpoint,
            timeout,
            max_retries: 3,
            retry_base_delay_ms: 100,
        }
    }

    /// Create a forwarder with custom retry configuration.
    pub fn with_retry(
        chain_endpoint: String,
        timeout: Duration,
        max_retries: u32,
        retry_base_delay_ms: u64,
    ) -> Self {
        Self {
            chain_endpoint,
            timeout,
            max_retries,
            retry_base_delay_ms,
        }
    }

    /// Forward a claim request to the chain.
    ///
    /// Uses retry logic. Currently a stub.
    pub async fn forward_claim(
        &self,
        _request: &ClaimRewardRequest,
    ) -> Result<ChainResponse, String> {
        let retries = self.max_retries;
        let delay = self.retry_base_delay_ms;
        retry_async(retries, delay, || async {
            // NOTE(14C.C.27): Replace with real chain RPC call.
            Ok(ChainResponse {
                success: true,
                message: "claim accepted (stub)".to_string(),
            })
        })
        .await
    }

    /// Query receipt status via chain.
    ///
    /// Uses retry logic. Currently a stub returning NotFound.
    pub async fn query_receipt_status_forwarded(
        &self,
        _hash: &str,
    ) -> Result<ChainReceiptInfo, String> {
        let retries = self.max_retries;
        let delay = self.retry_base_delay_ms;
        retry_async(retries, delay, || async {
            // NOTE(14C.C.27): Replace with real chain RPC call.
            Ok(ChainReceiptInfo {
                status: ReceiptStatus::NotFound,
                reward_amount: None,
                challenge_expires_at: None,
                node_id: None,
                workload_type: None,
                submitted_at: None,
            })
        })
        .await
    }

    /// Query balance via chain.
    ///
    /// Uses retry logic. Currently a stub returning zeros.
    pub async fn query_balance_forwarded(
        &self,
        _address: &str,
    ) -> Result<BalanceInfo, String> {
        let retries = self.max_retries;
        let delay = self.retry_base_delay_ms;
        retry_async(retries, delay, || async {
            // NOTE(14C.C.27): Replace with real chain RPC call.
            Ok(BalanceInfo {
                balance: 0,
                pending_rewards: 0,
                claimed_rewards: 0,
                node_earnings: 0,
                is_validator: false,
                is_node: false,
            })
        })
        .await
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TRAIT IMPLEMENTATIONS FOR CHAIN FORWARDER
// ════════════════════════════════════════════════════════════════════════════

impl ReceiptQueryService for ChainForwarder {
    fn query_receipt(
        &self,
        _receipt_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ChainReceiptInfo, String>> + Send + '_>> {
        let retries = self.max_retries;
        let delay = self.retry_base_delay_ms;
        Box::pin(async move {
            retry_async(retries, delay, || async {
                // NOTE(14C.C.27): Replace with real chain RPC call.
                Ok(ChainReceiptInfo {
                    status: ReceiptStatus::NotFound,
                    reward_amount: None,
                    challenge_expires_at: None,
                    node_id: None,
                    workload_type: None,
                    submitted_at: None,
                })
            })
            .await
        })
    }
}

impl RewardQueryService for ChainForwarder {
    fn query_balance(
        &self,
        _address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ChainRewardInfo, String>> + Send + '_>> {
        let retries = self.max_retries;
        let delay = self.retry_base_delay_ms;
        Box::pin(async move {
            retry_async(retries, delay, || async {
                // NOTE(14C.C.27): Replace with real chain RPC call.
                Ok(ChainRewardInfo {
                    balance: 0,
                    pending_rewards: 0,
                    claimed_rewards: 0,
                    node_earnings: 0,
                    is_validator: false,
                    is_node: false,
                })
            })
            .await
        })
    }

    fn list_validator_rewards(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ChainValidatorRewardInfo>, String>> + Send + '_>>
    {
        let retries = self.max_retries;
        let delay = self.retry_base_delay_ms;
        Box::pin(async move {
            retry_async(retries, delay, || async {
                // NOTE(14C.C.27): Replace with real chain RPC call.
                Ok(Vec::new())
            })
            .await
        })
    }

    fn query_treasury(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<ChainTreasuryInfo, String>> + Send + '_>> {
        let retries = self.max_retries;
        let delay = self.retry_base_delay_ms;
        Box::pin(async move {
            retry_async(retries, delay, || async {
                // NOTE(14C.C.27): Replace with real chain RPC call.
                Ok(ChainTreasuryInfo {
                    treasury_balance: 0,
                    total_rewards_distributed: 0,
                    total_validator_rewards: 0,
                    total_node_rewards: 0,
                })
            })
            .await
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ────────────────────────────────────────────────────────────────────────

    fn valid_hash_64(seed: u8) -> String {
        format!("{:0>64x}", seed)
    }

    fn valid_addr_40(seed: u8) -> String {
        format!("{:0>40x}", seed)
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: validate_receipt_hash_valid
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn validate_receipt_hash_valid() {
        let hash = valid_hash_64(0xAB);
        let result = validate_receipt_hash(&hash);
        assert!(result.is_ok());
        match result {
            Ok(s) => assert_eq!(s, hash),
            Err(_) => assert!(false, "expected Ok"),
        }

        // Uppercase hex
        let upper = "A".repeat(64);
        assert!(validate_receipt_hash(&upper).is_ok());

        // Mixed
        let mixed = "0123456789abcdef".repeat(4);
        assert!(validate_receipt_hash(&mixed).is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: validate_receipt_hash_invalid_length
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn validate_receipt_hash_invalid_length() {
        // Too short
        let result = validate_receipt_hash("abcd");
        assert!(result.is_err());
        match result {
            Err(ValidationError::InvalidLength { expected, got, .. }) => {
                assert_eq!(expected, 64);
                assert_eq!(got, 4);
            }
            _ => assert!(false, "expected InvalidLength"),
        }

        // Too long (65)
        assert!(validate_receipt_hash(&"a".repeat(65)).is_err());

        // Empty
        match validate_receipt_hash("") {
            Err(ValidationError::EmptyField { .. }) => {}
            _ => assert!(false, "expected EmptyField"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: validate_receipt_hash_invalid_hex
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn validate_receipt_hash_invalid_hex() {
        // Non-hex character 'g'
        let bad = format!("{}g", "a".repeat(63));
        match validate_receipt_hash(&bad) {
            Err(ValidationError::InvalidHexFormat { .. }) => {}
            _ => assert!(false, "expected InvalidHexFormat"),
        }

        // 0x prefix
        let with_prefix = format!("0x{}", "a".repeat(64));
        assert!(validate_receipt_hash(&with_prefix).is_err());

        // Internal whitespace (after trim still has space inside)
        let internal_space = format!("{} {}", "a".repeat(32), "b".repeat(31));
        assert!(validate_receipt_hash(&internal_space).is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: validate_address_valid
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn validate_address_valid() {
        let addr = valid_addr_40(0x01);
        let result = validate_address(&addr);
        assert!(result.is_ok());
        match result {
            Ok(s) => assert_eq!(s, addr),
            Err(_) => assert!(false, "expected Ok"),
        }

        // Uppercase
        assert!(validate_address(&"F".repeat(40)).is_ok());

        // All zeros
        assert!(validate_address(&"0".repeat(40)).is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: validate_address_invalid
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn validate_address_invalid() {
        // Too short
        assert!(validate_address("abc").is_err());

        // Too long (41)
        assert!(validate_address(&"a".repeat(41)).is_err());

        // Empty
        assert!(validate_address("").is_err());

        // 0x prefix
        assert!(validate_address(&format!("0x{}", "a".repeat(40))).is_err());

        // Non-hex
        assert!(validate_address(&"z".repeat(40)).is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: validate_claim_request_valid
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn validate_claim_request_valid() {
        let req = ClaimRewardRequest {
            receipt_hash: valid_hash_64(0x01),
            submitter_address: valid_addr_40(0x02),
            receipt_data: vec![1, 2, 3],
        };
        assert!(validate_claim_request(&req).is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: validate_claim_request_empty_fields
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn validate_claim_request_empty_fields() {
        // Empty receipt_hash
        let req1 = ClaimRewardRequest {
            receipt_hash: String::new(),
            submitter_address: valid_addr_40(0x02),
            receipt_data: vec![1],
        };
        match validate_claim_request(&req1) {
            Err(ValidationError::EmptyField { field }) => assert_eq!(field, "receipt_hash"),
            _ => assert!(false, "expected EmptyField for receipt_hash"),
        }

        // Empty submitter_address
        let req2 = ClaimRewardRequest {
            receipt_hash: valid_hash_64(0x01),
            submitter_address: String::new(),
            receipt_data: vec![1],
        };
        match validate_claim_request(&req2) {
            Err(ValidationError::EmptyField { field }) => assert_eq!(field, "address"),
            _ => assert!(false, "expected EmptyField for address"),
        }

        // Empty receipt_data
        let req3 = ClaimRewardRequest {
            receipt_hash: valid_hash_64(0x01),
            submitter_address: valid_addr_40(0x02),
            receipt_data: Vec::new(),
        };
        match validate_claim_request(&req3) {
            Err(ValidationError::EmptyField { field }) => assert_eq!(field, "receipt_data"),
            _ => assert!(false, "expected EmptyField for receipt_data"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: sanitize_whitespace_inputs
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn sanitize_whitespace_inputs() {
        // Leading/trailing spaces on valid hash → trimmed and valid
        let padded = format!("  {}  ", valid_hash_64(0xCC));
        let result = validate_receipt_hash(&padded);
        assert!(result.is_ok(), "padded hash should be valid after trim");
        match result {
            Ok(s) => assert_eq!(s, valid_hash_64(0xCC)),
            Err(_) => assert!(false, "expected Ok"),
        }

        // Leading/trailing spaces on valid address → trimmed and valid
        let padded_addr = format!("\t{}\n", valid_addr_40(0xDD));
        let result2 = validate_address(&padded_addr);
        assert!(result2.is_ok(), "padded address should be valid after trim");
        match result2 {
            Ok(s) => assert_eq!(s, valid_addr_40(0xDD)),
            Err(_) => assert!(false, "expected Ok"),
        }

        // Leading/trailing spaces on proof type → trimmed and valid
        let padded_type = "  execution_mismatch  ";
        let result3 = validate_proof_type(padded_type);
        assert!(result3.is_ok(), "padded proof_type should be valid after trim");
        match result3 {
            Ok(s) => assert_eq!(s, "execution_mismatch"),
            Err(_) => assert!(false, "expected Ok"),
        }

        // sanitize_input directly
        assert_eq!(sanitize_input("  hello  "), "hello");
        assert_eq!(sanitize_input("\thello\n"), "hello");
        assert_eq!(sanitize_input("hello"), "hello");
        assert_eq!(sanitize_input(""), "");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: chain_forwarder_forward_claim
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn chain_forwarder_forward_claim() {
        let fwd = ChainForwarder::new(
            "http://localhost:9000".to_string(),
            Duration::from_secs(5),
        );
        let req = ClaimRewardRequest {
            receipt_hash: valid_hash_64(0x01),
            submitter_address: valid_addr_40(0x02),
            receipt_data: vec![1, 2, 3],
        };
        let result = fwd.forward_claim(&req).await;
        assert!(result.is_ok());
        match result {
            Ok(resp) => {
                assert!(resp.success);
                assert!(!resp.message.is_empty());
            }
            Err(e) => assert!(false, "forward_claim failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: chain_forwarder_query_status
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn chain_forwarder_query_status() {
        let fwd = ChainForwarder::new(
            "http://localhost:9000".to_string(),
            Duration::from_secs(5),
        );
        let hash = valid_hash_64(0xAA);
        let result = fwd.query_receipt_status_forwarded(&hash).await;
        assert!(result.is_ok());
        match result {
            Ok(info) => {
                // Stub returns NotFound
                assert_eq!(info.status.as_str(), "not_found");
            }
            Err(e) => assert!(false, "query_status failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: chain_forwarder_query_balance
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn chain_forwarder_query_balance() {
        let fwd = ChainForwarder::new(
            "http://localhost:9000".to_string(),
            Duration::from_secs(5),
        );
        let addr = valid_addr_40(0xBB);
        let result = fwd.query_balance_forwarded(&addr).await;
        assert!(result.is_ok());
        match result {
            Ok(info) => {
                // Stub returns zeros
                assert_eq!(info.balance, 0);
                assert_eq!(info.pending_rewards, 0);
                assert!(!info.is_validator);
                assert!(!info.is_node);
            }
            Err(e) => assert!(false, "query_balance failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: rate_limit_mutation_endpoint
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn rate_limit_mutation_endpoint() {
        // Mutation endpoints: 10 req/min per IP, burst 10
        let config = crate::rate_limit::LimitConfig::per_ip_per_minute(10, 10);
        assert_eq!(config.burst_size, 10);
        assert_eq!(config.by, crate::rate_limit::RateLimitKey::Ip);

        // Verify burst behavior: 10 requests pass, 11th fails
        let mut limiter = crate::rate_limit::RateLimiter::new();
        limiter.add_limit("mutation", config.clone());
        let key = "ip:test_mutation";
        for i in 0..10 {
            assert!(
                limiter.check_and_record(key, &config).is_ok(),
                "mutation request {} should pass",
                i
            );
        }
        assert!(
            limiter.check_and_record(key, &config).is_err(),
            "11th mutation request should fail"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: rate_limit_query_endpoint
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn rate_limit_query_endpoint() {
        // Query endpoints: 60 req/min per IP, burst 60
        let config = crate::rate_limit::LimitConfig::per_ip_per_minute(60, 60);
        assert_eq!(config.burst_size, 60);
        assert_eq!(config.by, crate::rate_limit::RateLimitKey::Ip);

        // Verify burst: 60 pass, 61st fails
        let mut limiter = crate::rate_limit::RateLimiter::new();
        limiter.add_limit("query", config.clone());
        let key = "ip:test_query";
        for i in 0..60 {
            assert!(
                limiter.check_and_record(key, &config).is_ok(),
                "query request {} should pass",
                i
            );
        }
        assert!(
            limiter.check_and_record(key, &config).is_err(),
            "61st query request should fail"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: no_panic_invalid_inputs
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn no_panic_invalid_inputs() {
        // Various garbage inputs — must not panic, must return Err
        let bad_hashes: Vec<&str> = vec![
            "",
            " ",
            "0x",
            "\n",
            "\t",
            "!@#$%^&*()",
            "<script>",
        ];
        for bad in &bad_hashes {
            assert!(validate_receipt_hash(bad).is_err(), "expected Err for hash: {:?}", bad);
        }

        let bad_addrs: Vec<&str> = vec![
            "",
            " ",
            "0x",
            "\n",
        ];
        for bad in &bad_addrs {
            assert!(validate_address(bad).is_err(), "expected Err for addr: {:?}", bad);
        }
        // Non-hex 40-char address tested separately
        let non_hex_40 = "g".repeat(40);
        assert!(validate_address(&non_hex_40).is_err(), "expected Err for non-hex 40-char addr");

        // Invalid proof types
        let bad_types: Vec<&str> = vec![
            "",
            "invalid",
            "EXECUTION_MISMATCH",
            "  ",
        ];
        for bad in &bad_types {
            assert!(validate_proof_type(bad).is_err(), "expected Err for type: {:?}", bad);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: chain_forwarder_trait_impls
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn chain_forwarder_trait_impls() {
        let fwd = ChainForwarder::new(
            "http://localhost:9000".to_string(),
            Duration::from_secs(5),
        );

        // ReceiptQueryService::query_receipt
        let receipt_result = fwd.query_receipt(&valid_hash_64(0x01)).await;
        assert!(receipt_result.is_ok());

        // RewardQueryService::query_balance
        let balance_result = fwd.query_balance(&valid_addr_40(0x01)).await;
        assert!(balance_result.is_ok());

        // RewardQueryService::list_validator_rewards
        let val_result = fwd.list_validator_rewards().await;
        assert!(val_result.is_ok());
        match val_result {
            Ok(v) => assert!(v.is_empty()),
            Err(e) => assert!(false, "list_validator_rewards failed: {}", e),
        }

        // RewardQueryService::query_treasury
        let treasury_result = fwd.query_treasury().await;
        assert!(treasury_result.is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 16: validation_error_display
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn validation_error_display() {
        let e1 = ValidationError::EmptyField {
            field: "test".to_string(),
        };
        assert!(format!("{}", e1).contains("must not be empty"));

        let e2 = ValidationError::InvalidLength {
            field: "hash".to_string(),
            expected: 64,
            got: 10,
        };
        assert!(format!("{}", e2).contains("64"));
        assert!(format!("{}", e2).contains("10"));

        let e3 = ValidationError::InvalidHexFormat {
            field: "addr".to_string(),
            value: "bad".to_string(),
        };
        assert!(format!("{}", e3).contains("invalid hex"));

        let e4 = ValidationError::RateLimited {
            retry_after_secs: 30,
        };
        assert!(format!("{}", e4).contains("30"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 17: retry_async_succeeds_first_try
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn retry_async_succeeds_first_try() {
        let result: Result<i32, String> =
            retry_async(3, 100, || async { Ok(42) }).await;
        assert!(result.is_ok());
        match result {
            Ok(v) => assert_eq!(v, 42),
            Err(e) => assert!(false, "unexpected error: {}", e),
        }
    }
}
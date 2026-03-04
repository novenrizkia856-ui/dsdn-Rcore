//! # Receipt Status Query Handlers (14C.C.24)
//!
//! HTTP handlers for querying receipt status from the chain via coordinator.
//!
//! ## Architecture
//!
//! ```text
//! Client ──GET /receipt/:hash──▶ handle_receipt_status ──▶ ReceiptQueryService
//!                                        │                         │
//!                                   validate_hash            query_receipt
//!                                        │                         │
//!                                        ▼                         ▼
//!                                    400 / 200             ChainReceiptInfo
//!                                                                  │
//! Client ──POST /receipts/status──▶ handle_batch         map_to_response
//!                                        │                         │
//!                                  validate_all                    ▼
//!                                  concurrent query   ReceiptStatusResponse
//!                                  preserve order
//! ```
//!
//! ## Endpoints
//!
//! | Endpoint              | Method | Description                         |
//! |-----------------------|--------|-------------------------------------|
//! | `/receipt/:hash`      | GET    | Query single receipt status by hash |
//! | `/receipts/status`    | POST   | Batch query up to 100 receipt hashes|
//!
//! ## Status Values
//!
//! | Wire Value           | Meaning                              |
//! |----------------------|--------------------------------------|
//! | `"pending"`          | Receipt submitted, awaiting processing |
//! | `"challenge_period"` | In challenge window                  |
//! | `"finalized"`        | Fully confirmed on-chain             |
//! | `"challenged"`       | Under active challenge               |
//! | `"rejected"`         | Rejected by chain                    |
//! | `"not_found"`        | Receipt hash not found on-chain      |
//!
//! ## Hash Validation
//!
//! All receipt hashes must be:
//! - Exactly 64 hex characters (a-f, A-F, 0-9)
//! - No whitespace
//! - No `0x` / `0X` prefix
//! - Not empty

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

// ════════════════════════════════════════════════════════════════════════════
// RECEIPT STATUS ENUM
// ════════════════════════════════════════════════════════════════════════════

/// Allowed receipt status values.
///
/// Type-safe mapping from chain state to wire-format string.
/// Exhaustive — no other values permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptStatus {
    Pending,
    ChallengePeriod,
    Finalized,
    Challenged,
    Rejected,
    NotFound,
}

impl ReceiptStatus {
    /// Convert to the wire-format string.
    ///
    /// Mapping is injective and total — every variant maps to exactly one string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ChallengePeriod => "challenge_period",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::NotFound => "not_found",
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CHAIN RECEIPT INFO
// ════════════════════════════════════════════════════════════════════════════

/// Raw receipt info returned by the coordinator / chain query.
///
/// This is the internal data model that [`ReceiptQueryService`] produces.
/// Handlers map it to [`ReceiptStatusResponse`] for the wire.
#[derive(Debug, Clone)]
pub struct ChainReceiptInfo {
    pub status: ReceiptStatus,
    pub reward_amount: Option<u128>,
    pub challenge_expires_at: Option<u64>,
    pub node_id: Option<String>,
    pub workload_type: Option<String>,
    pub submitted_at: Option<u64>,
}

// ════════════════════════════════════════════════════════════════════════════
// RECEIPT QUERY SERVICE TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Abstraction over receipt status queries against the chain.
///
/// # Implementations
///
/// - Production: wraps `CoordinatorClient` RPC call (stub until RPC available)
/// - Testing: `MockReceiptQuery` — deterministic, no network
///
/// # Thread Safety
///
/// `Send + Sync + 'static` required for use behind `Arc` in async Axum handlers.
pub trait ReceiptQueryService: Send + Sync + 'static {
    /// Query a single receipt by hash.
    ///
    /// Returns `Ok(info)` on success (including `NotFound` status).
    /// Returns `Err(msg)` only on internal / network errors.
    fn query_receipt(
        &self,
        receipt_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ChainReceiptInfo, String>> + Send + '_>>;
}

// ════════════════════════════════════════════════════════════════════════════
// RESPONSE STRUCT
// ════════════════════════════════════════════════════════════════════════════

/// Receipt status response returned by both single and batch endpoints.
///
/// All fields are `Serialize` + `Deserialize` for JSON round-trip.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptStatusResponse {
    /// The queried receipt hash (hex, 64 chars).
    pub receipt_hash: String,

    /// Receipt status on-chain.
    ///
    /// Constrained to: `"pending"`, `"challenge_period"`, `"finalized"`,
    /// `"challenged"`, `"rejected"`, `"not_found"`.
    pub status: String,

    /// Reward amount in smallest denomination. `None` if not applicable.
    pub reward_amount: Option<u128>,

    /// Challenge expiration timestamp (unix seconds). `None` if not in challenge.
    pub challenge_expires_at: Option<u64>,

    /// Service node that produced the receipt. `None` if not found.
    pub node_id: Option<String>,

    /// Workload type: `"storage"` or `"compute"`. `None` if not found.
    pub workload_type: Option<String>,

    /// Submission timestamp (unix seconds). `None` if not found.
    pub submitted_at: Option<u64>,
}

// ════════════════════════════════════════════════════════════════════════════
// ERROR RESPONSE
// ════════════════════════════════════════════════════════════════════════════

/// JSON error body for 400 / 500 responses.
#[derive(Debug, Clone, Serialize)]
struct ErrorBody {
    error: String,
}

// ════════════════════════════════════════════════════════════════════════════
// BATCH REQUEST BODY
// ════════════════════════════════════════════════════════════════════════════

/// Request body for POST /receipts/status.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchReceiptRequest {
    /// List of receipt hashes to query. Min 1, max 100.
    pub hashes: Vec<String>,
}

/// Maximum number of hashes in a single batch request.
pub const BATCH_LIMIT: usize = 100;

// ════════════════════════════════════════════════════════════════════════════
// HASH VALIDATION
// ════════════════════════════════════════════════════════════════════════════

/// Validate a receipt hash string.
///
/// Rules enforced:
/// 1. Not empty
/// 2. No whitespace anywhere
/// 3. No `0x` / `0X` prefix
/// 4. Exactly 64 characters
/// 5. All characters valid hex (`0-9`, `a-f`, `A-F`)
///
/// Returns `Ok(())` on success, `Err(reason)` on failure.
pub fn validate_receipt_hash(hash: &str) -> Result<(), String> {
    if hash.is_empty() {
        return Err("hash must not be empty".to_string());
    }

    if hash.chars().any(|c| c.is_whitespace()) {
        return Err("hash must not contain whitespace".to_string());
    }

    if hash.starts_with("0x") || hash.starts_with("0X") {
        return Err("hash must not have 0x prefix".to_string());
    }

    if hash.len() != 64 {
        return Err(format!(
            "hash must be exactly 64 hex characters, got {}",
            hash.len()
        ));
    }

    if !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("hash contains non-hex characters".to_string());
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// MAP HELPER
// ════════════════════════════════════════════════════════════════════════════

/// Map [`ChainReceiptInfo`] → [`ReceiptStatusResponse`].
fn map_to_response(receipt_hash: &str, info: ChainReceiptInfo) -> ReceiptStatusResponse {
    ReceiptStatusResponse {
        receipt_hash: receipt_hash.to_string(),
        status: info.status.as_str().to_string(),
        reward_amount: info.reward_amount,
        challenge_expires_at: info.challenge_expires_at,
        node_id: info.node_id,
        workload_type: info.workload_type,
        submitted_at: info.submitted_at,
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SHARED STATE
// ════════════════════════════════════════════════════════════════════════════

/// Shared state for economic handlers.
///
/// Generic over `S` to support both production and test implementations.
#[derive(Clone)]
pub struct EconomicState<S: ReceiptQueryService> {
    pub service: Arc<S>,
}

// ════════════════════════════════════════════════════════════════════════════
// HANDLER: GET /receipt/:hash
// ════════════════════════════════════════════════════════════════════════════

/// Handle `GET /receipt/:hash` — single receipt status query.
///
/// ## HTTP Status Codes
///
/// | Code | Condition              |
/// |------|------------------------|
/// | 200  | Successful query       |
/// | 400  | Invalid hash format    |
/// | 500  | Internal query error   |
pub async fn handle_receipt_status<S: ReceiptQueryService>(
    Path(hash): Path<String>,
    State(state): State<EconomicState<S>>,
) -> axum::response::Response {
    // 1. Validate hash
    if let Err(reason) = validate_receipt_hash(&hash) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody { error: reason }),
        )
            .into_response();
    }

    // 2. Query chain
    match state.service.query_receipt(&hash).await {
        Ok(info) => {
            let resp = map_to_response(&hash, info);
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("internal query error: {}", err),
            }),
        )
            .into_response(),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HANDLER: POST /receipts/status
// ════════════════════════════════════════════════════════════════════════════

/// Handle `POST /receipts/status` — batch receipt status query.
///
/// ## HTTP Status Codes
///
/// | Code | Condition                  |
/// |------|----------------------------|
/// | 200  | All queries succeeded      |
/// | 400  | Empty / over-limit / bad hash |
/// | 500  | Internal query error       |
///
/// Response order matches input order.
pub async fn handle_batch_receipt_status<S: ReceiptQueryService>(
    State(state): State<EconomicState<S>>,
    Json(body): Json<BatchReceiptRequest>,
) -> axum::response::Response {
    // 1. Non-empty check
    if body.hashes.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "hashes array must not be empty".to_string(),
            }),
        )
            .into_response();
    }

    // 2. Batch limit check
    if body.hashes.len() > BATCH_LIMIT {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!(
                    "batch limit exceeded: max {}, got {}",
                    BATCH_LIMIT,
                    body.hashes.len()
                ),
            }),
        )
            .into_response();
    }

    // 3. Validate ALL hashes BEFORE querying (fail-fast)
    for (i, hash) in body.hashes.iter().enumerate() {
        if let Err(reason) = validate_receipt_hash(hash) {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: format!("invalid hash at index {}: {}", i, reason),
                }),
            )
                .into_response();
        }
    }

    // 4. Query all hashes concurrently via tokio::spawn, preserving input order.
    //
    //    Each query is spawned as an independent task with its index.
    //    Results are collected and sorted by original index to guarantee
    //    response order matches input order.
    //
    //    Guarantees:
    //    - Concurrent execution (no sequential blocking)
    //    - Order preservation (sort by index after collect)
    //    - No race condition (each task owns its own Arc + hash clone)
    //    - No wild thread spawn (tokio task pool only)
    let len = body.hashes.len();
    let mut handles: Vec<tokio::task::JoinHandle<(usize, String, Result<ChainReceiptInfo, String>)>> =
        Vec::with_capacity(len);

    for (idx, hash) in body.hashes.into_iter().enumerate() {
        let svc = Arc::clone(&state.service);
        handles.push(tokio::spawn(async move {
            let result = svc.query_receipt(&hash).await;
            (idx, hash, result)
        }));
    }

    // Collect all results. If any task panicked, return 500.
    let mut indexed: Vec<(usize, String, Result<ChainReceiptInfo, String>)> =
        Vec::with_capacity(len);

    for handle in handles {
        match handle.await {
            Ok(triple) => indexed.push(triple),
            Err(join_err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorBody {
                        error: format!("task join error: {}", join_err),
                    }),
                )
                    .into_response();
            }
        }
    }

    // Sort by original index to preserve input order.
    indexed.sort_by_key(|(idx, _, _)| *idx);

    // Map to response, failing on first query error.
    let mut responses: Vec<ReceiptStatusResponse> = Vec::with_capacity(len);
    for (_, hash, result) in indexed {
        match result {
            Ok(info) => {
                responses.push(map_to_response(&hash, info));
            }
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorBody {
                        error: format!("query error for {}: {}", hash, err),
                    }),
                )
                    .into_response();
            }
        }
    }

    (StatusCode::OK, Json(responses)).into_response()
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ────────────────────────────────────────────────────────────────────────
    // MOCK RECEIPT QUERY SERVICE
    // ────────────────────────────────────────────────────────────────────────

    /// Mock implementation of [`ReceiptQueryService`].
    ///
    /// Deterministic, no network, no SystemTime, no sleep.
    /// Thread-safe via `Mutex<HashMap>`.
    struct MockReceiptQuery {
        receipts: Mutex<HashMap<String, ChainReceiptInfo>>,
        force_error: Mutex<Option<String>>,
    }

    impl MockReceiptQuery {
        fn new() -> Self {
            Self {
                receipts: Mutex::new(HashMap::new()),
                force_error: Mutex::new(None),
            }
        }

        fn insert(&self, hash: &str, info: ChainReceiptInfo) {
            if let Ok(mut map) = self.receipts.lock() {
                map.insert(hash.to_string(), info);
            }
        }

        fn set_force_error(&self, err: &str) {
            if let Ok(mut e) = self.force_error.lock() {
                *e = Some(err.to_string());
            }
        }
    }

    impl ReceiptQueryService for MockReceiptQuery {
        fn query_receipt(
            &self,
            receipt_hash: &str,
        ) -> Pin<Box<dyn Future<Output = Result<ChainReceiptInfo, String>> + Send + '_>> {
            let hash = receipt_hash.to_string();
            Box::pin(async move {
                // Check forced error first
                if let Ok(guard) = self.force_error.lock() {
                    if let Some(ref err) = *guard {
                        return Err(err.clone());
                    }
                }

                // Lookup in map — not found returns NotFound status (not error)
                if let Ok(map) = self.receipts.lock() {
                    if let Some(info) = map.get(&hash) {
                        return Ok(info.clone());
                    }
                }

                Ok(ChainReceiptInfo {
                    status: ReceiptStatus::NotFound,
                    reward_amount: None,
                    challenge_expires_at: None,
                    node_id: None,
                    workload_type: None,
                    submitted_at: None,
                })
            })
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ────────────────────────────────────────────────────────────────────────

    /// Generate a valid 64-char hex hash from a u8 seed.
    fn valid_hash(seed: u8) -> String {
        format!("{:0>64x}", seed)
    }

    fn make_state(mock: Arc<MockReceiptQuery>) -> EconomicState<MockReceiptQuery> {
        EconomicState { service: mock }
    }

    /// Extract response body as String. Returns empty on error.
    async fn body_string(resp: axum::response::Response) -> String {
        match axum::body::to_bytes(resp.into_body(), 1024 * 1024).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => String::new(),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: valid_single_receipt_query
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn valid_single_receipt_query() {
        let mock = Arc::new(MockReceiptQuery::new());
        let hash = valid_hash(1);
        mock.insert(
            &hash,
            ChainReceiptInfo {
                status: ReceiptStatus::Finalized,
                reward_amount: Some(5000),
                challenge_expires_at: None,
                node_id: Some("node-abc".to_string()),
                workload_type: Some("storage".to_string()),
                submitted_at: Some(1700000000),
            },
        );

        let state = make_state(mock);
        let resp = handle_receipt_status(Path(hash.clone()), State(state))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"status\":\"finalized\""));
        assert!(body.contains("\"reward_amount\":5000"));
        assert!(body.contains("\"node_id\":\"node-abc\""));
        assert!(body.contains("\"workload_type\":\"storage\""));
        assert!(body.contains("\"submitted_at\":1700000000"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: invalid_hash_length
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn invalid_hash_length() {
        // Too short
        let r1 = validate_receipt_hash("abcdef1234");
        assert!(r1.is_err());
        if let Err(msg) = r1 {
            assert!(msg.contains("exactly 64"));
        }

        // Too long (65 chars)
        let long = "a".repeat(65);
        assert!(validate_receipt_hash(&long).is_err());

        // Empty
        assert!(validate_receipt_hash("").is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: invalid_hash_hex
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn invalid_hash_hex() {
        // Contains 'g' — not valid hex
        let bad = format!("{}g", "a".repeat(63));
        assert!(validate_receipt_hash(&bad).is_err());

        // Contains whitespace (space in middle)
        let spaced = format!("{} {}", "a".repeat(32), "b".repeat(31));
        assert!(validate_receipt_hash(&spaced).is_err());

        // Has 0x prefix
        let prefixed = format!("0x{}", "a".repeat(62));
        assert!(validate_receipt_hash(&prefixed).is_err());

        // Has 0X prefix (uppercase)
        let prefixed_upper = format!("0X{}", "a".repeat(62));
        assert!(validate_receipt_hash(&prefixed_upper).is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: receipt_not_found_status
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn receipt_not_found_status() {
        let mock = Arc::new(MockReceiptQuery::new());
        // Nothing inserted → not_found
        let hash = valid_hash(99);
        let state = make_state(mock);
        let resp = handle_receipt_status(Path(hash), State(state))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"status\":\"not_found\""));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: receipt_pending_status
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn receipt_pending_status() {
        let mock = Arc::new(MockReceiptQuery::new());
        let hash = valid_hash(5);
        mock.insert(
            &hash,
            ChainReceiptInfo {
                status: ReceiptStatus::Pending,
                reward_amount: None,
                challenge_expires_at: None,
                node_id: Some("node-1".to_string()),
                workload_type: Some("compute".to_string()),
                submitted_at: Some(1700001000),
            },
        );

        let state = make_state(mock);
        let resp = handle_receipt_status(Path(hash), State(state))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"status\":\"pending\""));
        assert!(body.contains("\"workload_type\":\"compute\""));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: receipt_challenge_period_status
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn receipt_challenge_period_status() {
        let mock = Arc::new(MockReceiptQuery::new());
        let hash = valid_hash(6);
        mock.insert(
            &hash,
            ChainReceiptInfo {
                status: ReceiptStatus::ChallengePeriod,
                reward_amount: Some(2000),
                challenge_expires_at: Some(1700100000),
                node_id: Some("node-2".to_string()),
                workload_type: Some("storage".to_string()),
                submitted_at: Some(1700002000),
            },
        );

        let state = make_state(mock);
        let resp = handle_receipt_status(Path(hash), State(state))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"status\":\"challenge_period\""));
        assert!(body.contains("\"challenge_expires_at\":1700100000"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: receipt_challenged_status
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn receipt_challenged_status() {
        let mock = Arc::new(MockReceiptQuery::new());
        let hash = valid_hash(7);
        mock.insert(
            &hash,
            ChainReceiptInfo {
                status: ReceiptStatus::Challenged,
                reward_amount: Some(3000),
                challenge_expires_at: Some(1700200000),
                node_id: Some("node-3".to_string()),
                workload_type: Some("compute".to_string()),
                submitted_at: Some(1700003000),
            },
        );

        let state = make_state(mock);
        let resp = handle_receipt_status(Path(hash), State(state))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"status\":\"challenged\""));
        assert!(body.contains("\"reward_amount\":3000"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: receipt_finalized_status
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn receipt_finalized_status() {
        let mock = Arc::new(MockReceiptQuery::new());
        let hash = valid_hash(8);
        mock.insert(
            &hash,
            ChainReceiptInfo {
                status: ReceiptStatus::Finalized,
                reward_amount: Some(10000),
                challenge_expires_at: None,
                node_id: Some("node-fin".to_string()),
                workload_type: Some("storage".to_string()),
                submitted_at: Some(1700004000),
            },
        );

        let state = make_state(mock);
        let resp = handle_receipt_status(Path(hash), State(state))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"status\":\"finalized\""));
        assert!(body.contains("\"reward_amount\":10000"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: receipt_rejected_status
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn receipt_rejected_status() {
        let mock = Arc::new(MockReceiptQuery::new());
        let hash = valid_hash(9);
        mock.insert(
            &hash,
            ChainReceiptInfo {
                status: ReceiptStatus::Rejected,
                reward_amount: None,
                challenge_expires_at: None,
                node_id: Some("node-rej".to_string()),
                workload_type: Some("compute".to_string()),
                submitted_at: Some(1700005000),
            },
        );

        let state = make_state(mock);
        let resp = handle_receipt_status(Path(hash), State(state))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"status\":\"rejected\""));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: batch_query_valid
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn batch_query_valid() {
        let mock = Arc::new(MockReceiptQuery::new());
        let h1 = valid_hash(10);
        let h2 = valid_hash(11);
        let h3 = valid_hash(12);

        mock.insert(
            &h1,
            ChainReceiptInfo {
                status: ReceiptStatus::Pending,
                reward_amount: None,
                challenge_expires_at: None,
                node_id: None,
                workload_type: None,
                submitted_at: None,
            },
        );
        mock.insert(
            &h2,
            ChainReceiptInfo {
                status: ReceiptStatus::Finalized,
                reward_amount: Some(999),
                challenge_expires_at: None,
                node_id: None,
                workload_type: None,
                submitted_at: None,
            },
        );
        // h3 not inserted → not_found

        let state = make_state(mock);
        let body_req = BatchReceiptRequest {
            hashes: vec![h1, h2, h3],
        };
        let resp = handle_batch_receipt_status(State(state), Json(body_req))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"status\":\"pending\""));
        assert!(body.contains("\"status\":\"finalized\""));
        assert!(body.contains("\"status\":\"not_found\""));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: batch_query_limit_100
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn batch_query_limit_100() {
        let mock = Arc::new(MockReceiptQuery::new());
        let state = make_state(mock);

        // Exactly 100 valid hashes — must succeed
        let hashes: Vec<String> = (0u8..100).map(valid_hash).collect();
        let body_req = BatchReceiptRequest { hashes };
        let resp = handle_batch_receipt_status(State(state), Json(body_req))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: batch_query_over_limit_error
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn batch_query_over_limit_error() {
        let mock = Arc::new(MockReceiptQuery::new());
        let state = make_state(mock);

        // 101 hashes — must fail
        let hashes: Vec<String> = (0..101u16)
            .map(|i| valid_hash((i % 256) as u8))
            .collect();
        let body_req = BatchReceiptRequest { hashes };
        let resp = handle_batch_receipt_status(State(state), Json(body_req))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp).await;
        assert!(body.contains("batch limit exceeded"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: batch_query_invalid_hash_error
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn batch_query_invalid_hash_error() {
        let mock = Arc::new(MockReceiptQuery::new());
        let state = make_state(mock);

        let hashes = vec![
            valid_hash(1),
            "invalid_hash_too_short".to_string(),
            valid_hash(3),
        ];
        let body_req = BatchReceiptRequest { hashes };
        let resp = handle_batch_receipt_status(State(state), Json(body_req))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp).await;
        assert!(body.contains("invalid hash at index 1"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: batch_response_order_preserved
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn batch_response_order_preserved() {
        let mock = Arc::new(MockReceiptQuery::new());
        let h_a = valid_hash(0xaa);
        let h_b = valid_hash(0xbb);
        let h_c = valid_hash(0xcc);

        mock.insert(
            &h_a,
            ChainReceiptInfo {
                status: ReceiptStatus::Pending,
                reward_amount: None,
                challenge_expires_at: None,
                node_id: None,
                workload_type: None,
                submitted_at: None,
            },
        );
        mock.insert(
            &h_b,
            ChainReceiptInfo {
                status: ReceiptStatus::Finalized,
                reward_amount: Some(1),
                challenge_expires_at: None,
                node_id: None,
                workload_type: None,
                submitted_at: None,
            },
        );
        mock.insert(
            &h_c,
            ChainReceiptInfo {
                status: ReceiptStatus::Challenged,
                reward_amount: Some(2),
                challenge_expires_at: None,
                node_id: None,
                workload_type: None,
                submitted_at: None,
            },
        );

        // Input order: c, a, b — output MUST be c, a, b
        let state = make_state(mock);
        let body_req = BatchReceiptRequest {
            hashes: vec![h_c.clone(), h_a.clone(), h_b.clone()],
        };
        let resp = handle_batch_receipt_status(State(state), Json(body_req))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;

        // Parse as array and verify order
        let parsed: Vec<ReceiptStatusResponse> = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].receipt_hash, h_c);
        assert_eq!(parsed[0].status, "challenged");
        assert_eq!(parsed[1].receipt_hash, h_a);
        assert_eq!(parsed[1].status, "pending");
        assert_eq!(parsed[2].receipt_hash, h_b);
        assert_eq!(parsed[2].status, "finalized");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: batch_query_empty_array_error
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn batch_query_empty_array_error() {
        let mock = Arc::new(MockReceiptQuery::new());
        let state = make_state(mock);

        let body_req = BatchReceiptRequest {
            hashes: Vec::new(),
        };
        let resp = handle_batch_receipt_status(State(state), Json(body_req))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp).await;
        assert!(body.contains("must not be empty"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 16: internal_error_returns_500
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn internal_error_returns_500() {
        let mock = Arc::new(MockReceiptQuery::new());
        mock.set_force_error("database connection lost");

        let hash = valid_hash(50);
        let state = make_state(mock);
        let resp = handle_receipt_status(Path(hash), State(state))
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_string(resp).await;
        assert!(body.contains("internal query error"));
        assert!(body.contains("database connection lost"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 17: receipt_status_enum_mapping
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn receipt_status_enum_mapping() {
        assert_eq!(ReceiptStatus::Pending.as_str(), "pending");
        assert_eq!(ReceiptStatus::ChallengePeriod.as_str(), "challenge_period");
        assert_eq!(ReceiptStatus::Finalized.as_str(), "finalized");
        assert_eq!(ReceiptStatus::Challenged.as_str(), "challenged");
        assert_eq!(ReceiptStatus::Rejected.as_str(), "rejected");
        assert_eq!(ReceiptStatus::NotFound.as_str(), "not_found");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 18: hash_validation_edge_cases
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn hash_validation_edge_cases() {
        // Valid: exactly 64 hex chars (lowercase)
        let valid_lower = "a".repeat(64);
        assert!(validate_receipt_hash(&valid_lower).is_ok());

        // Valid: mixed hex digits
        let mixed = "0123456789abcdef".repeat(4);
        assert!(validate_receipt_hash(&mixed).is_ok());

        // Valid: uppercase hex allowed by is_ascii_hexdigit
        let upper = "A".repeat(64);
        assert!(validate_receipt_hash(&upper).is_ok());

        // Invalid: contains newline
        let with_newline = format!("{}\n{}", "a".repeat(32), "b".repeat(31));
        assert!(validate_receipt_hash(&with_newline).is_err());

        // Invalid: contains tab
        let with_tab = format!("{}\t{}", "a".repeat(32), "b".repeat(31));
        assert!(validate_receipt_hash(&with_tab).is_err());

        // Invalid: only spaces (non-empty but all whitespace, len != 64)
        assert!(validate_receipt_hash("   ").is_err());
    }
}
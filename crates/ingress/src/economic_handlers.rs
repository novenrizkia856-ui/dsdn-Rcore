//! # Economic Query Handlers (14C.C.24 + 14C.C.25)
//!
//! HTTP handlers for querying receipt status and reward economics from the
//! chain via coordinator.
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
//!
//! Client ──GET /rewards/:address──▶ handle_reward_balance ──▶ RewardQueryService
//!                                        │                           │
//!                                   validate_address           query_balance
//!                                        │                           │
//!                                        ▼                           ▼
//!                                    400 / 200              ChainRewardInfo
//!                                                                    │
//! Client ──GET /rewards/validators──▶ handle_validator_rewards       │
//!                                        │                           │
//!                                   list + sort by id     list_validator_rewards
//!                                        │                           │
//! Client ──GET /rewards/treasury──▶ handle_treasury_rewards          │
//!                                        │                    query_treasury
//!                                        ▼                           │
//!                                    200 / 500           ChainTreasuryInfo
//! ```
//!
//! ## Endpoints
//!
//! | Endpoint              | Method | Description                         |
//! |-----------------------|--------|-------------------------------------|
//! | `/receipt/:hash`      | GET    | Query single receipt status by hash |
//! | `/receipts/status`    | POST   | Batch query up to 100 receipt hashes|
//! | `/rewards/:address`   | GET    | Query reward balance by address     |
//! | `/rewards/validators` | GET    | List all validator reward summaries  |
//! | `/rewards/treasury`   | GET    | Query treasury reward statistics    |
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
//!
//! ## Address Validation (14C.C.25)
//!
//! All reward addresses must be:
//! - Exactly 40 hex characters (a-f, A-F, 0-9)
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
use std::sync::{Arc, RwLock};
use tracing::info;

use crate::receipt_event_logger::{ReceiptEconomicEvent, ReceiptEventLogger};

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
///
/// Delegates to [`crate::economic_validation::validate_receipt_hash`].
/// No duplicate validation logic — this is a thin adapter.
pub fn validate_receipt_hash(hash: &str) -> Result<(), String> {
    crate::economic_validation::validate_receipt_hash(hash)
        .map(|_| ())
        .map_err(|e| e.to_string())
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
// CHAIN REWARD DATA MODELS (14C.C.25)
// ════════════════════════════════════════════════════════════════════════════

/// Raw reward/balance info returned by chain state query for an address.
///
/// Internal data model produced by [`RewardQueryService::query_balance`].
/// Handlers map it to [`RewardBalanceResponse`] for the wire.
#[derive(Debug, Clone)]
pub struct ChainRewardInfo {
    /// Total balance in smallest denomination.
    pub balance: u128,
    /// Pending (unclaimed) rewards.
    pub pending_rewards: u128,
    /// Already-claimed rewards.
    pub claimed_rewards: u128,
    /// Earnings from node operation.
    pub node_earnings: u128,
    /// Whether this address is a registered validator.
    pub is_validator: bool,
    /// Whether this address is a registered service node.
    pub is_node: bool,
}

/// Raw validator reward info from chain state.
///
/// Internal data model produced by [`RewardQueryService::list_validator_rewards`].
#[derive(Debug, Clone)]
pub struct ChainValidatorRewardInfo {
    /// Unique validator identifier (hex).
    pub validator_id: String,
    /// Pending (unclaimed) rewards.
    pub pending_rewards: u128,
    /// Already-claimed rewards.
    pub claimed_rewards: u128,
    /// Total lifetime earnings.
    pub total_earned: u128,
}

/// Raw treasury info from chain state.
///
/// Internal data model produced by [`RewardQueryService::query_treasury`].
#[derive(Debug, Clone)]
pub struct ChainTreasuryInfo {
    /// Current treasury balance.
    pub treasury_balance: u128,
    /// Total rewards distributed across all recipients.
    pub total_rewards_distributed: u128,
    /// Total rewards distributed to validators specifically.
    pub total_validator_rewards: u128,
    /// Total rewards distributed to service nodes specifically.
    pub total_node_rewards: u128,
}

// ════════════════════════════════════════════════════════════════════════════
// REWARD QUERY SERVICE TRAIT (14C.C.25)
// ════════════════════════════════════════════════════════════════════════════

/// Abstraction over reward/balance queries against the chain.
///
/// # Implementations
///
/// - Production: wraps `CoordinatorClient` RPC call (stub until RPC available)
/// - Testing: `MockRewardQuery` — deterministic, no network
///
/// # Thread Safety
///
/// `Send + Sync + 'static` required for use behind `Arc` in async Axum handlers.
pub trait RewardQueryService: Send + Sync + 'static {
    /// Query reward balance for a single address.
    ///
    /// Returns `Ok(info)` on success (including zero-balance addresses).
    /// Returns `Err(msg)` only on internal / network errors.
    fn query_balance(
        &self,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ChainRewardInfo, String>> + Send + '_>>;

    /// List all validator reward summaries.
    ///
    /// Returns the full set of validators. Handlers sort by `validator_id`.
    /// Returns `Err(msg)` only on internal / network errors.
    fn list_validator_rewards(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ChainValidatorRewardInfo>, String>> + Send + '_>>;

    /// Query treasury reward statistics.
    ///
    /// Returns `Err(msg)` only on internal / network errors.
    fn query_treasury(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<ChainTreasuryInfo, String>> + Send + '_>>;
}

// ════════════════════════════════════════════════════════════════════════════
// REWARD RESPONSE STRUCTS (14C.C.25)
// ════════════════════════════════════════════════════════════════════════════

/// Reward balance response for `GET /rewards/:address`.
///
/// All fields are `Serialize` + `Deserialize` for JSON round-trip.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardBalanceResponse {
    /// The queried address (hex, 40 chars).
    pub address: String,

    /// Total balance in smallest denomination.
    pub balance: u128,

    /// Pending (unclaimed) rewards.
    pub pending_rewards: u128,

    /// Already-claimed rewards.
    pub claimed_rewards: u128,

    /// Earnings from node operation.
    pub node_earnings: u128,

    /// Whether this address is a registered validator.
    pub is_validator: bool,

    /// Whether this address is a registered service node.
    pub is_node: bool,
}

/// Validator reward summary for `GET /rewards/validators`.
///
/// Returned as `Vec<ValidatorRewardSummary>` sorted by `validator_id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorRewardSummary {
    /// Unique validator identifier.
    pub validator_id: String,

    /// Pending (unclaimed) rewards.
    pub pending_rewards: u128,

    /// Already-claimed rewards.
    pub claimed_rewards: u128,

    /// Total lifetime earnings.
    pub total_earned: u128,
}

/// Treasury reward statistics for `GET /rewards/treasury`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreasuryRewardResponse {
    /// Current treasury balance.
    pub treasury_balance: u128,

    /// Total rewards distributed across all recipients.
    pub total_rewards_distributed: u128,

    /// Total rewards distributed to validators specifically.
    pub total_validator_rewards: u128,

    /// Total rewards distributed to service nodes specifically.
    pub total_node_rewards: u128,
}

// ════════════════════════════════════════════════════════════════════════════
// ADDRESS VALIDATION (14C.C.25)
// ════════════════════════════════════════════════════════════════════════════

/// Validate a reward address string.
///
/// Rules enforced:
/// 1. Not empty
/// 2. No whitespace anywhere
/// 3. No `0x` / `0X` prefix
/// 4. Exactly 40 characters
/// 5. All characters valid hex (`0-9`, `a-f`, `A-F`)
///
/// Returns `Ok(())` on success, `Err(reason)` on failure.
///
/// Delegates to [`crate::economic_validation::validate_address`].
/// No duplicate validation logic — this is a thin adapter.
pub fn validate_address(address: &str) -> Result<(), String> {
    crate::economic_validation::validate_address(address)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ════════════════════════════════════════════════════════════════════════════
// REWARD STATE (14C.C.25)
// ════════════════════════════════════════════════════════════════════════════

/// Shared state for reward handlers.
///
/// Generic over `R` to support both production and test implementations.
/// Manual `Clone` impl — only clones `Arc`, does NOT require `R: Clone`.
pub struct EconomicRewardState<R: RewardQueryService> {
    pub service: Arc<R>,
}

impl<R: RewardQueryService> Clone for EconomicRewardState<R> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HANDLER: GET /rewards/:address (14C.C.25)
// ════════════════════════════════════════════════════════════════════════════

/// Handle `GET /rewards/:address` — single address reward balance query.
///
/// ## HTTP Status Codes
///
/// | Code | Condition                |
/// |------|--------------------------|
/// | 200  | Successful query         |
/// | 400  | Invalid address format   |
/// | 500  | Internal query error     |
pub async fn handle_reward_balance<R: RewardQueryService>(
    Path(address): Path<String>,
    State(state): State<EconomicRewardState<R>>,
) -> axum::response::Response {
    // 1. Validate address
    if let Err(reason) = validate_address(&address) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody { error: reason }),
        )
            .into_response();
    }

    // 2. Query chain
    match state.service.query_balance(&address).await {
        Ok(info) => {
            let resp = RewardBalanceResponse {
                address,
                balance: info.balance,
                pending_rewards: info.pending_rewards,
                claimed_rewards: info.claimed_rewards,
                node_earnings: info.node_earnings,
                is_validator: info.is_validator,
                is_node: info.is_node,
            };
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
// HANDLER: GET /rewards/validators (14C.C.25)
// ════════════════════════════════════════════════════════════════════════════

/// Handle `GET /rewards/validators` — list all validator reward summaries.
///
/// Response is sorted by `validator_id` (lexicographic) for deterministic order.
///
/// ## HTTP Status Codes
///
/// | Code | Condition                |
/// |------|--------------------------|
/// | 200  | Successful query         |
/// | 500  | Internal query error     |
pub async fn handle_validator_rewards<R: RewardQueryService>(
    State(state): State<EconomicRewardState<R>>,
) -> axum::response::Response {
    match state.service.list_validator_rewards().await {
        Ok(mut validators) => {
            // Sort by validator_id for deterministic output order.
            validators.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));

            let summaries: Vec<ValidatorRewardSummary> = validators
                .into_iter()
                .map(|v| ValidatorRewardSummary {
                    validator_id: v.validator_id,
                    pending_rewards: v.pending_rewards,
                    claimed_rewards: v.claimed_rewards,
                    total_earned: v.total_earned,
                })
                .collect();

            (StatusCode::OK, Json(summaries)).into_response()
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
// HANDLER: GET /rewards/treasury (14C.C.25)
// ════════════════════════════════════════════════════════════════════════════

/// Handle `GET /rewards/treasury` — treasury reward statistics.
///
/// ## HTTP Status Codes
///
/// | Code | Condition                |
/// |------|--------------------------|
/// | 200  | Successful query         |
/// | 500  | Internal query error     |
pub async fn handle_treasury_rewards<R: RewardQueryService>(
    State(state): State<EconomicRewardState<R>>,
) -> axum::response::Response {
    match state.service.query_treasury().await {
        Ok(info) => {
            let resp = TreasuryRewardResponse {
                treasury_balance: info.treasury_balance,
                total_rewards_distributed: info.total_rewards_distributed,
                total_validator_rewards: info.total_validator_rewards,
                total_node_rewards: info.total_node_rewards,
            };
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
// FRAUD PROOF DATA MODELS (14C.C.26)
// ════════════════════════════════════════════════════════════════════════════

/// Fraud proof log entry stored in application state.
///
/// Contains the original request fields plus a generated `fraud_proof_id`.
/// This is the "log struct equivalent" returned by `GET /fraud-proofs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FraudProofLogEntry {
    /// Receipt hash being challenged (hex, 64 chars).
    pub receipt_hash: String,

    /// Type of fraud proof.
    /// Must be: `"execution_mismatch"`, `"invalid_commitment"`, or `"resource_inflation"`.
    pub proof_type: String,

    /// Raw proof data bytes. Must not be empty.
    pub proof_data: Vec<u8>,

    /// Address of the submitter (hex, 40 chars).
    pub submitter_address: String,

    /// Optional challenge identifier.
    pub challenge_id: Option<String>,

    /// Generated fraud proof identifier (deterministic).
    pub fraud_proof_id: String,
}

/// Request body for `POST /fraud-proof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProofRequest {
    /// Receipt hash being challenged (hex, 64 chars).
    pub receipt_hash: String,

    /// Type of fraud proof.
    /// Must be: `"execution_mismatch"`, `"invalid_commitment"`, or `"resource_inflation"`.
    pub proof_type: String,

    /// Raw proof data bytes. Must not be empty.
    pub proof_data: Vec<u8>,

    /// Address of the submitter (hex, 40 chars).
    pub submitter_address: String,

    /// Optional challenge identifier.
    pub challenge_id: Option<String>,
}

/// Response for `POST /fraud-proof`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FraudProofResponse {
    /// Always `true` for placeholder acceptance.
    pub accepted: bool,

    /// Generated fraud proof identifier.
    pub fraud_proof_id: String,

    /// Human-readable message.
    pub message: String,

    /// Placeholder note — always `"placeholder — not processed until Tahap 18.8"`.
    pub note: String,
}

/// Thread-safe fraud proof log type.
///
/// Uses `RwLock` for concurrent read access on `GET /fraud-proofs`.
pub type FraudProofLog = Arc<RwLock<Vec<FraudProofLogEntry>>>;

/// Placeholder note constant.
///
/// Returned verbatim in every `FraudProofResponse`.
pub const FRAUD_PROOF_PLACEHOLDER_NOTE: &str = "placeholder \u{2014} not processed until Tahap 18.8";

/// Allowed proof type values.
///
/// Canonical list defined in [`crate::economic_validation`].
/// Kept here for reference only; validation delegates to that module.
#[allow(dead_code)]
const VALID_PROOF_TYPES: [&str; 3] = [
    "execution_mismatch",
    "invalid_commitment",
    "resource_inflation",
];

// ════════════════════════════════════════════════════════════════════════════
// FRAUD PROOF VALIDATION (14C.C.26)
// ════════════════════════════════════════════════════════════════════════════

/// Validate a fraud proof type string.
///
/// Delegates to [`crate::economic_validation::validate_proof_type`].
/// No duplicate validation logic — this is a thin adapter.
pub fn validate_proof_type(proof_type: &str) -> Result<(), String> {
    crate::economic_validation::validate_proof_type(proof_type)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ════════════════════════════════════════════════════════════════════════════
// FRAUD PROOF ID GENERATION (14C.C.26)
// ════════════════════════════════════════════════════════════════════════════

/// Generate a deterministic fraud proof ID from request fields and log index.
///
/// Format: `fp-{receipt_hash[0..8]}-{submitter[0..8]}-{index:08x}`
///
/// Deterministic given the same sequence of submissions.
fn generate_fraud_proof_id(receipt_hash: &str, submitter: &str, index: usize) -> String {
    // Both receipt_hash and submitter are pre-validated hex, safe to slice.
    let rh = if receipt_hash.len() >= 8 {
        &receipt_hash[..8]
    } else {
        receipt_hash
    };
    let sa = if submitter.len() >= 8 {
        &submitter[..8]
    } else {
        submitter
    };
    format!("fp-{}-{}-{:08x}", rh, sa, index)
}

// ════════════════════════════════════════════════════════════════════════════
// FRAUD PROOF STATE (14C.C.26)
// ════════════════════════════════════════════════════════════════════════════

/// Shared state for fraud proof handlers.
///
/// Holds thread-safe reference to the fraud proof log and event logger.
/// Manual `Clone` — only clones `Arc`, does NOT require inner `Clone`.
pub struct FraudProofState {
    pub log: FraudProofLog,
    /// Receipt event logger for DA audit logging (14C.C.28).
    pub event_logger: Arc<ReceiptEventLogger>,
}

impl Clone for FraudProofState {
    fn clone(&self) -> Self {
        Self {
            log: Arc::clone(&self.log),
            event_logger: Arc::clone(&self.event_logger),
        }
    }
}

/// Create a new empty fraud proof log.
pub fn new_fraud_proof_log() -> FraudProofLog {
    Arc::new(RwLock::new(Vec::new()))
}

// ════════════════════════════════════════════════════════════════════════════
// HANDLER: POST /fraud-proof (14C.C.26)
// ════════════════════════════════════════════════════════════════════════════

/// Handle `POST /fraud-proof` — fraud proof submission (placeholder).
///
/// Validates all fields, logs the submission, and returns a placeholder response.
/// **No verification, arbitration, slashing, or challenge resolution is performed.**
///
/// ## HTTP Status Codes
///
/// | Code | Condition                     |
/// |------|-------------------------------|
/// | 200  | Accepted (placeholder)        |
/// | 400  | Validation error              |
/// | 500  | Internal lock error           |
pub async fn handle_fraud_proof_submit(
    State(state): State<FraudProofState>,
    Json(body): Json<FraudProofRequest>,
) -> axum::response::Response {
    // 1. Validate receipt_hash (64 hex)
    if let Err(reason) = validate_receipt_hash(&body.receipt_hash) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!("invalid receipt_hash: {}", reason),
            }),
        )
            .into_response();
    }

    // 2. Validate submitter_address (40 hex)
    if let Err(reason) = validate_address(&body.submitter_address) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!("invalid submitter_address: {}", reason),
            }),
        )
            .into_response();
    }

    // 3. Validate proof_type
    if let Err(reason) = validate_proof_type(&body.proof_type) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody { error: reason }),
        )
            .into_response();
    }

    // 4. Validate proof_data non-empty
    if body.proof_data.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "proof_data must not be empty".to_string(),
            }),
        )
            .into_response();
    }

    // 5. Lock log, generate ID, push entry, log structured event.
    let fraud_proof_id;
    match state.log.write() {
        Ok(mut log) => {
            let index = log.len();
            fraud_proof_id =
                generate_fraud_proof_id(&body.receipt_hash, &body.submitter_address, index);

            let entry = FraudProofLogEntry {
                receipt_hash: body.receipt_hash.clone(),
                proof_type: body.proof_type.clone(),
                proof_data: body.proof_data.clone(),
                submitter_address: body.submitter_address.clone(),
                challenge_id: body.challenge_id.clone(),
                fraud_proof_id: fraud_proof_id.clone(),
            };

            log.push(entry);
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("log lock error: {}", err),
                }),
            )
                .into_response();
        }
    }

    // 6. Structured logging
    info!(
        "[FRAUD_PROOF] SUBMITTED receipt={} type={} submitter={}",
        body.receipt_hash, body.proof_type, body.submitter_address
    );

    // 7. Log DA event (14C.C.28).
    state.event_logger.log_event(ReceiptEconomicEvent::FraudProofReceived {
        receipt_hash: body.receipt_hash.clone(),
        proof_type: body.proof_type.clone(),
        timestamp: crate::receipt_event_logger::current_timestamp_secs(),
    });

    // 8. Return placeholder response. No processing, verification, or arbitration.
    let resp = FraudProofResponse {
        accepted: true,
        fraud_proof_id,
        message: "fraud proof accepted (placeholder)".to_string(),
        note: FRAUD_PROOF_PLACEHOLDER_NOTE.to_string(),
    };
    (StatusCode::OK, Json(resp)).into_response()
}

// ════════════════════════════════════════════════════════════════════════════
// HANDLER: GET /fraud-proofs (14C.C.26)
// ════════════════════════════════════════════════════════════════════════════

/// Handle `GET /fraud-proofs` — list all logged fraud proof submissions.
///
/// Returns entries in insertion order (deterministic). Does not mutate state.
///
/// ## HTTP Status Codes
///
/// | Code | Condition                     |
/// |------|-------------------------------|
/// | 200  | Success                       |
/// | 500  | Internal lock error           |
pub async fn handle_fraud_proofs_list(
    State(state): State<FraudProofState>,
) -> axum::response::Response {
    match state.log.read() {
        Ok(log) => {
            let entries: Vec<FraudProofLogEntry> = log.clone();
            (StatusCode::OK, Json(entries)).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("log lock error: {}", err),
            }),
        )
            .into_response(),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CLAIM HANDLER TYPES (14C.C.28)
// ════════════════════════════════════════════════════════════════════════════

/// Response for `POST /claim`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRewardResponse {
    /// Whether the claim was accepted by the chain forwarder.
    pub success: bool,
    /// Human-readable message.
    pub message: String,
}

/// Shared state for claim handler.
///
/// Wraps a [`ChainForwarder`]-compatible service and event logger.
pub struct ClaimState {
    /// Chain forwarder for forwarding claim requests.
    pub forwarder: Arc<crate::economic_validation::ChainForwarder>,
    /// Receipt event logger for DA audit logging (14C.C.28).
    pub event_logger: Arc<ReceiptEventLogger>,
}

impl Clone for ClaimState {
    fn clone(&self) -> Self {
        Self {
            forwarder: Arc::clone(&self.forwarder),
            event_logger: Arc::clone(&self.event_logger),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HANDLER: POST /claim (14C.C.28)
// ════════════════════════════════════════════════════════════════════════════

/// Handle `POST /claim` — submit a reward claim.
///
/// 1. Validate request fields via [`crate::economic_validation::validate_claim_request`].
/// 2. Log `ClaimSubmitted` event.
/// 3. Forward to chain via [`ChainForwarder::forward_claim`].
/// 4. Log `ClaimAccepted` or `ClaimRejected` based on chain response.
/// 5. Return result.
///
/// ## HTTP Status Codes
///
/// | Code | Condition                     |
/// |------|-------------------------------|
/// | 200  | Claim accepted                |
/// | 400  | Validation error              |
/// | 500  | Chain forwarding error        |
pub async fn handle_claim_submit(
    State(state): State<ClaimState>,
    Json(body): Json<crate::economic_validation::ClaimRewardRequest>,
) -> axum::response::Response {
    // 1. Validate all fields (sanitize + check).
    if let Err(err) = crate::economic_validation::validate_claim_request(&body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!("{}", err),
            }),
        )
            .into_response();
    }

    let ts = crate::receipt_event_logger::current_timestamp_secs();

    // 2. Log ClaimSubmitted event.
    state.event_logger.log_event(ReceiptEconomicEvent::ClaimSubmitted {
        receipt_hash: body.receipt_hash.clone(),
        submitter: body.submitter_address.clone(),
        timestamp: ts,
    });

    // 3. Forward to chain.
    match state.forwarder.forward_claim(&body).await {
        Ok(chain_resp) => {
            if chain_resp.success {
                // 4a. Log ClaimAccepted.
                state.event_logger.log_event(ReceiptEconomicEvent::ClaimAccepted {
                    receipt_hash: body.receipt_hash.clone(),
                    status: "accepted".to_string(),
                    reward_amount: 0, // Stub — real amount from chain in future.
                    timestamp: crate::receipt_event_logger::current_timestamp_secs(),
                });

                let resp = ClaimRewardResponse {
                    success: true,
                    message: chain_resp.message,
                };
                (StatusCode::OK, Json(resp)).into_response()
            } else {
                // 4b. Log ClaimRejected.
                state.event_logger.log_event(ReceiptEconomicEvent::ClaimRejected {
                    receipt_hash: body.receipt_hash.clone(),
                    reason: chain_resp.message.clone(),
                    timestamp: crate::receipt_event_logger::current_timestamp_secs(),
                });

                let resp = ClaimRewardResponse {
                    success: false,
                    message: chain_resp.message,
                };
                (StatusCode::OK, Json(resp)).into_response()
            }
        }
        Err(err) => {
            // 4c. Log ClaimRejected on error.
            state.event_logger.log_event(ReceiptEconomicEvent::ClaimRejected {
                receipt_hash: body.receipt_hash.clone(),
                reason: err.clone(),
                timestamp: crate::receipt_event_logger::current_timestamp_secs(),
            });

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("chain forwarding error: {}", err),
                }),
            )
                .into_response()
        }
    }
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

    // ════════════════════════════════════════════════════════════════════════
    // MOCK REWARD QUERY SERVICE (14C.C.25)
    // ════════════════════════════════════════════════════════════════════════

    /// Mock implementation of [`RewardQueryService`].
    ///
    /// Deterministic, no network, no SystemTime, no sleep.
    /// Thread-safe via `Mutex`.
    struct MockRewardQuery {
        balances: Mutex<HashMap<String, ChainRewardInfo>>,
        validators: Mutex<Vec<ChainValidatorRewardInfo>>,
        treasury: Mutex<Option<ChainTreasuryInfo>>,
        force_error: Mutex<Option<String>>,
    }

    impl MockRewardQuery {
        fn new() -> Self {
            Self {
                balances: Mutex::new(HashMap::new()),
                validators: Mutex::new(Vec::new()),
                treasury: Mutex::new(None),
                force_error: Mutex::new(None),
            }
        }

        fn insert_balance(&self, address: &str, info: ChainRewardInfo) {
            if let Ok(mut map) = self.balances.lock() {
                map.insert(address.to_string(), info);
            }
        }

        fn set_validators(&self, vals: Vec<ChainValidatorRewardInfo>) {
            if let Ok(mut v) = self.validators.lock() {
                *v = vals;
            }
        }

        fn set_treasury(&self, info: ChainTreasuryInfo) {
            if let Ok(mut t) = self.treasury.lock() {
                *t = Some(info);
            }
        }

        fn set_force_error_reward(&self, err: &str) {
            if let Ok(mut e) = self.force_error.lock() {
                *e = Some(err.to_string());
            }
        }
    }

    impl RewardQueryService for MockRewardQuery {
        fn query_balance(
            &self,
            address: &str,
        ) -> Pin<Box<dyn Future<Output = Result<ChainRewardInfo, String>> + Send + '_>> {
            let addr = address.to_string();
            Box::pin(async move {
                if let Ok(guard) = self.force_error.lock() {
                    if let Some(ref err) = *guard {
                        return Err(err.clone());
                    }
                }
                if let Ok(map) = self.balances.lock() {
                    if let Some(info) = map.get(&addr) {
                        return Ok(info.clone());
                    }
                }
                // Default: zero balance, not validator, not node
                Ok(ChainRewardInfo {
                    balance: 0,
                    pending_rewards: 0,
                    claimed_rewards: 0,
                    node_earnings: 0,
                    is_validator: false,
                    is_node: false,
                })
            })
        }

        fn list_validator_rewards(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<ChainValidatorRewardInfo>, String>> + Send + '_>>
        {
            Box::pin(async move {
                if let Ok(guard) = self.force_error.lock() {
                    if let Some(ref err) = *guard {
                        return Err(err.clone());
                    }
                }
                if let Ok(v) = self.validators.lock() {
                    return Ok(v.clone());
                }
                Ok(Vec::new())
            })
        }

        fn query_treasury(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<ChainTreasuryInfo, String>> + Send + '_>> {
            Box::pin(async move {
                if let Ok(guard) = self.force_error.lock() {
                    if let Some(ref err) = *guard {
                        return Err(err.clone());
                    }
                }
                if let Ok(t) = self.treasury.lock() {
                    if let Some(ref info) = *t {
                        return Ok(info.clone());
                    }
                }
                // Default: zero treasury
                Ok(ChainTreasuryInfo {
                    treasury_balance: 0,
                    total_rewards_distributed: 0,
                    total_validator_rewards: 0,
                    total_node_rewards: 0,
                })
            })
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // REWARD TEST HELPERS
    // ────────────────────────────────────────────────────────────────────────

    /// Generate a valid 40-char hex address from a u8 seed.
    fn valid_address(seed: u8) -> String {
        format!("{:0>40x}", seed)
    }

    fn make_reward_state(mock: Arc<MockRewardQuery>) -> EconomicRewardState<MockRewardQuery> {
        EconomicRewardState { service: mock }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-1: valid_reward_balance_query
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn valid_reward_balance_query() {
        let mock = Arc::new(MockRewardQuery::new());
        let addr = valid_address(0xAB);
        mock.insert_balance(
            &addr,
            ChainRewardInfo {
                balance: 50000,
                pending_rewards: 1000,
                claimed_rewards: 4000,
                node_earnings: 3000,
                is_validator: true,
                is_node: true,
            },
        );

        let state = make_reward_state(mock);
        let resp = handle_reward_balance(Path(addr.clone()), State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        let parsed: Result<RewardBalanceResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(r) => {
                assert_eq!(r.address, addr);
                assert_eq!(r.balance, 50000);
                assert_eq!(r.pending_rewards, 1000);
                assert_eq!(r.claimed_rewards, 4000);
                assert_eq!(r.node_earnings, 3000);
                assert!(r.is_validator);
                assert!(r.is_node);
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-2: invalid_address_length
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn invalid_address_length() {
        // Too short
        assert!(validate_address("abcdef").is_err());
        // Too long (41 chars)
        assert!(validate_address(&"a".repeat(41)).is_err());
        // Empty
        assert!(validate_address("").is_err());
        // Exactly 39
        assert!(validate_address(&"b".repeat(39)).is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-3: invalid_address_hex
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn invalid_address_hex() {
        // Contains 'g'
        let with_g = format!("{}g", "a".repeat(39));
        assert!(validate_address(&with_g).is_err());

        // Contains space
        let with_space = format!("{} {}", "a".repeat(20), "b".repeat(19));
        assert!(validate_address(&with_space).is_err());

        // 0x prefix (makes total 42 chars, but prefix check fires first)
        let with_prefix = format!("0x{}", "a".repeat(40));
        assert!(validate_address(&with_prefix).is_err());

        // 0X prefix
        let with_upper_prefix = format!("0X{}", "a".repeat(40));
        assert!(validate_address(&with_upper_prefix).is_err());

        // Valid: uppercase hex
        let upper = "A".repeat(40);
        assert!(validate_address(&upper).is_ok());

        // Valid: mixed hex
        let mixed = "0123456789abcdefABCD".repeat(2);
        assert!(validate_address(&mixed).is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-4: validator_balance_fields_correct
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn validator_balance_fields_correct() {
        let mock = Arc::new(MockRewardQuery::new());
        let addr = valid_address(0x01);
        mock.insert_balance(
            &addr,
            ChainRewardInfo {
                balance: 100_000,
                pending_rewards: 25_000,
                claimed_rewards: 75_000,
                node_earnings: 0,
                is_validator: true,
                is_node: false,
            },
        );

        let state = make_reward_state(mock);
        let resp = handle_reward_balance(Path(addr.clone()), State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        let parsed: Result<RewardBalanceResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(r) => {
                assert!(r.is_validator);
                assert!(!r.is_node);
                assert_eq!(r.pending_rewards, 25_000);
                assert_eq!(r.claimed_rewards, 75_000);
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-5: node_balance_fields_correct
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn node_balance_fields_correct() {
        let mock = Arc::new(MockRewardQuery::new());
        let addr = valid_address(0x02);
        mock.insert_balance(
            &addr,
            ChainRewardInfo {
                balance: 8_000,
                pending_rewards: 0,
                claimed_rewards: 0,
                node_earnings: 8_000,
                is_validator: false,
                is_node: true,
            },
        );

        let state = make_reward_state(mock);
        let resp = handle_reward_balance(Path(addr.clone()), State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        let parsed: Result<RewardBalanceResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(r) => {
                assert!(!r.is_validator);
                assert!(r.is_node);
                assert_eq!(r.node_earnings, 8_000);
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-6: non_validator_non_node_balance
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn non_validator_non_node_balance() {
        let mock = Arc::new(MockRewardQuery::new());
        let addr = valid_address(0xFF);
        // Not inserted → default zero balance

        let state = make_reward_state(mock);
        let resp = handle_reward_balance(Path(addr.clone()), State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        let parsed: Result<RewardBalanceResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(r) => {
                assert!(!r.is_validator);
                assert!(!r.is_node);
                assert_eq!(r.balance, 0);
                assert_eq!(r.pending_rewards, 0);
                assert_eq!(r.claimed_rewards, 0);
                assert_eq!(r.node_earnings, 0);
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-7: validator_list_sorted
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn validator_list_sorted() {
        let mock = Arc::new(MockRewardQuery::new());
        // Insert in reverse order: c, a, b
        mock.set_validators(vec![
            ChainValidatorRewardInfo {
                validator_id: "cccc".to_string(),
                pending_rewards: 300,
                claimed_rewards: 0,
                total_earned: 300,
            },
            ChainValidatorRewardInfo {
                validator_id: "aaaa".to_string(),
                pending_rewards: 100,
                claimed_rewards: 0,
                total_earned: 100,
            },
            ChainValidatorRewardInfo {
                validator_id: "bbbb".to_string(),
                pending_rewards: 200,
                claimed_rewards: 0,
                total_earned: 200,
            },
        ]);

        let state = make_reward_state(mock);
        let resp = handle_validator_rewards(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        let parsed: Result<Vec<ValidatorRewardSummary>, _> = serde_json::from_str(&body);
        match parsed {
            Ok(list) => {
                assert_eq!(list.len(), 3);
                // Must be sorted: aaaa, bbbb, cccc
                assert_eq!(list[0].validator_id, "aaaa");
                assert_eq!(list[1].validator_id, "bbbb");
                assert_eq!(list[2].validator_id, "cccc");
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-8: validator_list_deterministic
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn validator_list_deterministic() {
        let mock = Arc::new(MockRewardQuery::new());
        mock.set_validators(vec![
            ChainValidatorRewardInfo {
                validator_id: "zzzz".to_string(),
                pending_rewards: 10,
                claimed_rewards: 5,
                total_earned: 15,
            },
            ChainValidatorRewardInfo {
                validator_id: "aaaa".to_string(),
                pending_rewards: 20,
                claimed_rewards: 10,
                total_earned: 30,
            },
        ]);

        let state = make_reward_state(mock);

        // Call twice, compare serialized output
        let resp1 = handle_validator_rewards(State(state.clone())).await;
        let body1 = body_string(resp1).await;

        let resp2 = handle_validator_rewards(State(state)).await;
        let body2 = body_string(resp2).await;

        assert_eq!(body1, body2, "deterministic: two calls must produce identical JSON");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-9: treasury_balance_query
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn treasury_balance_query() {
        let mock = Arc::new(MockRewardQuery::new());
        mock.set_treasury(ChainTreasuryInfo {
            treasury_balance: 1_000_000,
            total_rewards_distributed: 500_000,
            total_validator_rewards: 300_000,
            total_node_rewards: 200_000,
        });

        let state = make_reward_state(mock);
        let resp = handle_treasury_rewards(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        let parsed: Result<TreasuryRewardResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(t) => {
                assert_eq!(t.treasury_balance, 1_000_000);
                assert_eq!(t.total_rewards_distributed, 500_000);
                assert_eq!(t.total_validator_rewards, 300_000);
                assert_eq!(t.total_node_rewards, 200_000);
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-10: treasury_statistics_consistent
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn treasury_statistics_consistent() {
        let mock = Arc::new(MockRewardQuery::new());
        let val_rewards: u128 = 700_000;
        let node_rewards: u128 = 300_000;
        // total_rewards_distributed == total_validator_rewards + total_node_rewards
        let total_opt = val_rewards.checked_add(node_rewards);
        assert!(total_opt.is_some(), "overflow in test setup");
        let total = match total_opt {
            Some(v) => v,
            None => return,
        };

        mock.set_treasury(ChainTreasuryInfo {
            treasury_balance: 2_000_000,
            total_rewards_distributed: total,
            total_validator_rewards: val_rewards,
            total_node_rewards: node_rewards,
        });

        let state = make_reward_state(mock);
        let resp = handle_treasury_rewards(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        let parsed: Result<TreasuryRewardResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(t) => {
                // Consistency check: distributed == validator + node
                let sum_opt = t.total_validator_rewards.checked_add(t.total_node_rewards);
                assert!(sum_opt.is_some(), "overflow in consistency check");
                let sum = match sum_opt {
                    Some(v) => v,
                    None => return,
                };
                assert_eq!(t.total_rewards_distributed, sum);
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-11: large_balance_overflow_safe
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn large_balance_overflow_safe() {
        let mock = Arc::new(MockRewardQuery::new());
        let addr = valid_address(0xEE);
        mock.insert_balance(
            &addr,
            ChainRewardInfo {
                balance: u128::MAX,
                pending_rewards: u128::MAX,
                claimed_rewards: u128::MAX,
                node_earnings: u128::MAX,
                is_validator: true,
                is_node: true,
            },
        );

        let state = make_reward_state(mock);
        let resp = handle_reward_balance(Path(addr.clone()), State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        let parsed: Result<RewardBalanceResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(r) => {
                assert_eq!(r.balance, u128::MAX);
                assert_eq!(r.pending_rewards, u128::MAX);
                assert_eq!(r.claimed_rewards, u128::MAX);
                assert_eq!(r.node_earnings, u128::MAX);
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-12: zero_balance_response
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn zero_balance_response() {
        let mock = Arc::new(MockRewardQuery::new());
        let addr = valid_address(0x00);
        // Not inserted → default all-zeros

        let state = make_reward_state(mock);
        let resp = handle_reward_balance(Path(addr.clone()), State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        let parsed: Result<RewardBalanceResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(r) => {
                assert_eq!(r.balance, 0);
                assert_eq!(r.pending_rewards, 0);
                assert_eq!(r.claimed_rewards, 0);
                assert_eq!(r.node_earnings, 0);
                assert!(!r.is_validator);
                assert!(!r.is_node);
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-13: no_panic_invalid_json
    // ════════════════════════════════════════════════════════════════════════

    /// Test that malformed / edge-case address inputs produce 400, never panic.
    #[tokio::test]
    async fn no_panic_invalid_json() {
        let mock = Arc::new(MockRewardQuery::new());
        let state = make_reward_state(mock);

        // Various invalid addresses that must NOT panic
        let bad_addresses: Vec<String> = vec![
            String::new(),
            " ".to_string(),
            "0x".to_string(),
            format!("0x{}", "a".repeat(40)),
            "\n".to_string(),
            "\t".to_string(),
            "g".repeat(40),
            "!@#$%^&*()".to_string(),
            "<script>alert(1)</script>".to_string(),
        ];

        for bad in &bad_addresses {
            let resp = handle_reward_balance(
                Path(bad.clone()),
                State(state.clone()),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for input: {:?}",
                bad
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-14: deterministic_response_format
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn deterministic_response_format() {
        let mock = Arc::new(MockRewardQuery::new());
        let addr = valid_address(0x42);
        mock.insert_balance(
            &addr,
            ChainRewardInfo {
                balance: 9999,
                pending_rewards: 111,
                claimed_rewards: 222,
                node_earnings: 333,
                is_validator: false,
                is_node: true,
            },
        );

        let state = make_reward_state(mock);

        // Two identical calls must produce byte-identical JSON
        let resp1 = handle_reward_balance(Path(addr.clone()), State(state.clone())).await;
        let body1 = body_string(resp1).await;

        let resp2 = handle_reward_balance(Path(addr.clone()), State(state)).await;
        let body2 = body_string(resp2).await;

        assert_eq!(body1, body2, "deterministic: two calls must produce identical JSON");

        // Verify round-trip
        let parsed: Result<RewardBalanceResponse, _> = serde_json::from_str(&body1);
        match parsed {
            Ok(r) => {
                assert_eq!(r.address, addr);
                assert_eq!(r.balance, 9999);
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-15: reward_internal_error_returns_500
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn reward_internal_error_returns_500() {
        let mock = Arc::new(MockRewardQuery::new());
        mock.set_force_error_reward("database unavailable");
        let addr = valid_address(0xDD);

        let state = make_reward_state(mock);
        let resp = handle_reward_balance(Path(addr), State(state)).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-16: treasury_internal_error_returns_500
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn treasury_internal_error_returns_500() {
        let mock = Arc::new(MockRewardQuery::new());
        mock.set_force_error_reward("rpc timeout");

        let state = make_reward_state(mock);
        let resp = handle_treasury_rewards(State(state)).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-17: address_validation_edge_cases
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn address_validation_edge_cases() {
        // Valid: all zeros
        assert!(validate_address(&"0".repeat(40)).is_ok());

        // Valid: all F's
        assert!(validate_address(&"F".repeat(40)).is_ok());

        // Valid: mixed case (exactly 40 hex chars)
        assert!(validate_address("aAbBcCdDeEfF0123456789aAbBcCdDeEfF012345").is_ok());

        // Invalid: newline inside
        let with_nl = format!("{}\n{}", "a".repeat(19), "b".repeat(20));
        assert!(validate_address(&with_nl).is_err());

        // Invalid: tab inside
        let with_tab = format!("{}\t{}", "a".repeat(19), "b".repeat(20));
        assert!(validate_address(&with_tab).is_err());

        // Invalid: 0x prefix with exactly 40 hex after (total 42)
        assert!(validate_address(&format!("0x{}", "a".repeat(40))).is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.25-18: validator_list_empty
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn validator_list_empty() {
        let mock = Arc::new(MockRewardQuery::new());
        // No validators set → empty list

        let state = make_reward_state(mock);
        let resp = handle_validator_rewards(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        let parsed: Result<Vec<ValidatorRewardSummary>, _> = serde_json::from_str(&body);
        match parsed {
            Ok(list) => {
                assert!(list.is_empty());
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // FRAUD PROOF TEST HELPERS (14C.C.26)
    // ════════════════════════════════════════════════════════════════════════

    fn make_fraud_state() -> FraudProofState {
        FraudProofState {
            log: new_fraud_proof_log(),
            event_logger: Arc::new(ReceiptEventLogger::without_publisher(
                { let mut p = std::env::temp_dir(); p.push("dsdn_test_fraud_events.jsonl"); p.to_string_lossy().to_string() },
            )),
        }
    }

    fn valid_fraud_request() -> FraudProofRequest {
        FraudProofRequest {
            receipt_hash: valid_hash(0xAA),
            proof_type: "execution_mismatch".to_string(),
            proof_data: vec![1, 2, 3, 4],
            submitter_address: valid_address(0xBB),
            challenge_id: Some("challenge-001".to_string()),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-1: fraud_proof_valid_submission
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proof_valid_submission() {
        let state = make_fraud_state();
        let req = valid_fraud_request();
        let resp = handle_fraud_proof_submit(State(state), Json(req)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp).await;
        let parsed: Result<FraudProofResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(r) => {
                assert!(r.accepted);
                assert!(!r.fraud_proof_id.is_empty());
                assert_eq!(r.message, "fraud proof accepted (placeholder)");
                assert_eq!(r.note, FRAUD_PROOF_PLACEHOLDER_NOTE);
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-2: fraud_proof_invalid_hash
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proof_invalid_hash() {
        let state = make_fraud_state();

        // Too short
        let mut req = valid_fraud_request();
        req.receipt_hash = "abcd".to_string();
        let resp = handle_fraud_proof_submit(State(state.clone()), Json(req)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Empty
        let mut req2 = valid_fraud_request();
        req2.receipt_hash = String::new();
        let resp2 = handle_fraud_proof_submit(State(state.clone()), Json(req2)).await;
        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);

        // Non-hex
        let mut req3 = valid_fraud_request();
        req3.receipt_hash = "g".repeat(64);
        let resp3 = handle_fraud_proof_submit(State(state), Json(req3)).await;
        assert_eq!(resp3.status(), StatusCode::BAD_REQUEST);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-3: fraud_proof_invalid_address
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proof_invalid_address() {
        let state = make_fraud_state();

        // Too short
        let mut req = valid_fraud_request();
        req.submitter_address = "abc".to_string();
        let resp = handle_fraud_proof_submit(State(state.clone()), Json(req)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 0x prefix
        let mut req2 = valid_fraud_request();
        req2.submitter_address = format!("0x{}", "a".repeat(40));
        let resp2 = handle_fraud_proof_submit(State(state.clone()), Json(req2)).await;
        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);

        // Non-hex
        let mut req3 = valid_fraud_request();
        req3.submitter_address = "z".repeat(40);
        let resp3 = handle_fraud_proof_submit(State(state), Json(req3)).await;
        assert_eq!(resp3.status(), StatusCode::BAD_REQUEST);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-4: fraud_proof_invalid_type
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proof_invalid_type() {
        let state = make_fraud_state();

        let invalid_types = vec![
            "invalid",
            "EXECUTION_MISMATCH",
            "executionMismatch",
            "",
            "slash",
        ];

        for bad_type in invalid_types {
            let mut req = valid_fraud_request();
            req.proof_type = bad_type.to_string();
            let resp = handle_fraud_proof_submit(State(state.clone()), Json(req)).await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for proof_type: {:?}",
                bad_type
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-5: fraud_proof_empty_data
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proof_empty_data() {
        let state = make_fraud_state();
        let mut req = valid_fraud_request();
        req.proof_data = Vec::new();
        let resp = handle_fraud_proof_submit(State(state), Json(req)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = body_string(resp).await;
        assert!(body.contains("proof_data must not be empty"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-6: fraud_proof_response_placeholder_note
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proof_response_placeholder_note() {
        let state = make_fraud_state();
        let req = valid_fraud_request();
        let resp = handle_fraud_proof_submit(State(state), Json(req)).await;
        let body = body_string(resp).await;
        let parsed: Result<FraudProofResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(r) => {
                // Exact string match per contract
                assert_eq!(
                    r.note,
                    "placeholder \u{2014} not processed until Tahap 18.8"
                );
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-7: fraud_proof_logged
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proof_logged() {
        let state = make_fraud_state();
        let req = valid_fraud_request();
        let rh = req.receipt_hash.clone();
        let sa = req.submitter_address.clone();

        let resp = handle_fraud_proof_submit(State(state.clone()), Json(req)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify log contains the entry
        match state.log.read() {
            Ok(log) => {
                assert_eq!(log.len(), 1);
                assert_eq!(log[0].receipt_hash, rh);
                assert_eq!(log[0].submitter_address, sa);
                assert_eq!(log[0].proof_type, "execution_mismatch");
                assert!(!log[0].fraud_proof_id.is_empty());
            }
            Err(e) => {
                assert!(false, "lock error in test: {}", e);
            }
        };
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-8: fraud_proof_id_generated
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proof_id_generated() {
        let state = make_fraud_state();
        let req = valid_fraud_request();
        let resp = handle_fraud_proof_submit(State(state), Json(req)).await;
        let body = body_string(resp).await;
        let parsed: Result<FraudProofResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(r) => {
                // Must start with "fp-"
                assert!(r.fraud_proof_id.starts_with("fp-"));
                // Must contain receipt hash prefix
                let rh_prefix = &valid_hash(0xAA)[..8];
                assert!(r.fraud_proof_id.contains(rh_prefix));
                // Must be non-empty and have expected format parts
                let parts: Vec<&str> = r.fraud_proof_id.split('-').collect();
                assert!(parts.len() >= 4, "expected fp-XX-YY-ZZ format");
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-9: fraud_proofs_query_returns_list
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proofs_query_returns_list() {
        let state = make_fraud_state();

        // Submit 2 fraud proofs
        let mut req1 = valid_fraud_request();
        req1.receipt_hash = valid_hash(0x01);
        let r1 = handle_fraud_proof_submit(State(state.clone()), Json(req1)).await;
        assert_eq!(r1.status(), StatusCode::OK);

        let mut req2 = valid_fraud_request();
        req2.receipt_hash = valid_hash(0x02);
        let r2 = handle_fraud_proof_submit(State(state.clone()), Json(req2)).await;
        assert_eq!(r2.status(), StatusCode::OK);

        // Query list
        let list_resp = handle_fraud_proofs_list(State(state)).await;
        assert_eq!(list_resp.status(), StatusCode::OK);

        let body = body_string(list_resp).await;
        let parsed: Result<Vec<FraudProofLogEntry>, _> = serde_json::from_str(&body);
        match parsed {
            Ok(entries) => {
                assert_eq!(entries.len(), 2);
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-10: fraud_proofs_order_deterministic
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proofs_order_deterministic() {
        let state = make_fraud_state();

        // Submit A then B
        let mut req_a = valid_fraud_request();
        req_a.receipt_hash = valid_hash(0xAA);
        req_a.proof_type = "execution_mismatch".to_string();
        let _ = handle_fraud_proof_submit(State(state.clone()), Json(req_a)).await;

        let mut req_b = valid_fraud_request();
        req_b.receipt_hash = valid_hash(0xBB);
        req_b.proof_type = "invalid_commitment".to_string();
        let _ = handle_fraud_proof_submit(State(state.clone()), Json(req_b)).await;

        // Query twice, must be identical
        let list1 = handle_fraud_proofs_list(State(state.clone())).await;
        let body1 = body_string(list1).await;

        let list2 = handle_fraud_proofs_list(State(state)).await;
        let body2 = body_string(list2).await;

        assert_eq!(body1, body2, "deterministic: two calls must produce identical JSON");

        // Verify order: A first, B second
        let parsed: Result<Vec<FraudProofLogEntry>, _> = serde_json::from_str(&body1);
        match parsed {
            Ok(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].receipt_hash, valid_hash(0xAA));
                assert_eq!(entries[1].receipt_hash, valid_hash(0xBB));
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-11: no_processing_logic_present
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn no_processing_logic_present() {
        let state = make_fraud_state();
        let req = valid_fraud_request();
        let resp = handle_fraud_proof_submit(State(state.clone()), Json(req)).await;
        let body = body_string(resp).await;
        let parsed: Result<FraudProofResponse, _> = serde_json::from_str(&body);
        match parsed {
            Ok(r) => {
                // Placeholder: accepted = true, no verification result
                assert!(r.accepted);
                assert_eq!(r.message, "fraud proof accepted (placeholder)");
                assert!(r.note.contains("placeholder"));
                assert!(r.note.contains("not processed"));
            }
            Err(e) => {
                assert!(false, "deserialize failed in test: {}", e);
            }
        }

        // Verify the log entry exists but has no processed/verified fields
        // (FraudProofLogEntry only stores submission data, no result fields)
        match state.log.read() {
            Ok(log) => {
                assert_eq!(log.len(), 1);
                // Only submission fields present — no processing output stored
                assert_eq!(log[0].proof_type, "execution_mismatch");
            }
            Err(e) => {
                assert!(false, "lock error in test: {}", e);
            }
        };
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-12: no_panic_invalid_json
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn no_panic_invalid_json_fraud_proof() {
        let state = make_fraud_state();

        // All valid except individual fields made invalid
        let cases: Vec<FraudProofRequest> = vec![
            // Empty receipt_hash
            FraudProofRequest {
                receipt_hash: String::new(),
                proof_type: "execution_mismatch".to_string(),
                proof_data: vec![1],
                submitter_address: valid_address(0x01),
                challenge_id: None,
            },
            // Empty submitter_address
            FraudProofRequest {
                receipt_hash: valid_hash(0x01),
                proof_type: "execution_mismatch".to_string(),
                proof_data: vec![1],
                submitter_address: String::new(),
                challenge_id: None,
            },
            // Invalid proof_type
            FraudProofRequest {
                receipt_hash: valid_hash(0x01),
                proof_type: "not_a_real_type".to_string(),
                proof_data: vec![1],
                submitter_address: valid_address(0x01),
                challenge_id: None,
            },
            // Empty proof_data
            FraudProofRequest {
                receipt_hash: valid_hash(0x01),
                proof_type: "execution_mismatch".to_string(),
                proof_data: Vec::new(),
                submitter_address: valid_address(0x01),
                challenge_id: None,
            },
            // Whitespace in hash
            FraudProofRequest {
                receipt_hash: " ".repeat(64),
                proof_type: "execution_mismatch".to_string(),
                proof_data: vec![1],
                submitter_address: valid_address(0x01),
                challenge_id: None,
            },
        ];

        for (i, bad_req) in cases.into_iter().enumerate() {
            let resp = handle_fraud_proof_submit(State(state.clone()), Json(bad_req)).await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for test case {}",
                i
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-13: fraud_proof_all_valid_types
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proof_all_valid_types() {
        let state = make_fraud_state();
        let types = ["execution_mismatch", "invalid_commitment", "resource_inflation"];

        for (i, pt) in types.iter().enumerate() {
            let mut req = valid_fraud_request();
            req.proof_type = pt.to_string();
            req.receipt_hash = valid_hash(i as u8);
            let resp = handle_fraud_proof_submit(State(state.clone()), Json(req)).await;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "expected 200 for proof_type: {}",
                pt
            );
        }

        // Verify all 3 logged
        match state.log.read() {
            Ok(log) => {
                assert_eq!(log.len(), 3);
            }
            Err(e) => {
                assert!(false, "lock error in test: {}", e);
            }
        };
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14C.C.26-14: fraud_proof_challenge_id_optional
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn fraud_proof_challenge_id_optional() {
        let state = make_fraud_state();

        // With challenge_id
        let mut req1 = valid_fraud_request();
        req1.challenge_id = Some("ch-999".to_string());
        let r1 = handle_fraud_proof_submit(State(state.clone()), Json(req1)).await;
        assert_eq!(r1.status(), StatusCode::OK);

        // Without challenge_id
        let mut req2 = valid_fraud_request();
        req2.receipt_hash = valid_hash(0xCC);
        req2.challenge_id = None;
        let r2 = handle_fraud_proof_submit(State(state.clone()), Json(req2)).await;
        assert_eq!(r2.status(), StatusCode::OK);

        // Verify both logged correctly
        match state.log.read() {
            Ok(log) => {
                assert_eq!(log.len(), 2);
                assert_eq!(log[0].challenge_id, Some("ch-999".to_string()));
                assert_eq!(log[1].challenge_id, None);
            }
            Err(e) => {
                assert!(false, "lock error in test: {}", e);
            }
        };
    }
}
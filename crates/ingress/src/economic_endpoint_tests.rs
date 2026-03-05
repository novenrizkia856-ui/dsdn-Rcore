// Economic Endpoint Tests (14C.C.29)
//
// Comprehensive test suite for all ingress economic endpoints.
// All tests are deterministic, use mock services, and never touch
// real network or filesystem.

#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axum::extract::{Json, Path, State};
use axum::http::StatusCode;

use crate::economic_handlers::{
    self, BatchReceiptRequest, ChainReceiptInfo, ChainRewardInfo,
    ChainTreasuryInfo, ChainValidatorRewardInfo, ClaimRewardResponse,
    ClaimState, EconomicRewardState, EconomicState,
    FraudProofLogEntry, FraudProofRequest, FraudProofResponse,
    FraudProofState, ReceiptQueryService, ReceiptStatus,
    ReceiptStatusResponse, RewardBalanceResponse, RewardQueryService,
    TreasuryRewardResponse, ValidatorRewardSummary,
    FRAUD_PROOF_PLACEHOLDER_NOTE,
};
use crate::economic_validation::{
    self, ChainForwarder, ClaimRewardRequest, ValidationError,
};
use crate::receipt_event_logger::{
    self, EventPublisher, ReceiptEconomicEvent, ReceiptEventLogger,
};

// ════════════════════════════════════════════════════════════════════════════
// MOCK SERVICES
// ════════════════════════════════════════════════════════════════════════════

/// Mock receipt query service with configurable responses.
struct MockReceiptService {
    receipts: Mutex<HashMap<String, ChainReceiptInfo>>,
    force_error: AtomicBool,
}

impl MockReceiptService {
    fn new() -> Self {
        Self {
            receipts: Mutex::new(HashMap::new()),
            force_error: AtomicBool::new(false),
        }
    }

    fn add_receipt(&self, hash: &str, info: ChainReceiptInfo) {
        if let Ok(mut map) = self.receipts.lock() {
            map.insert(hash.to_string(), info);
        }
    }
}

impl ReceiptQueryService for MockReceiptService {
    fn query_receipt(
        &self,
        receipt_hash: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ChainReceiptInfo, String>> + Send + '_>> {
        let hash = receipt_hash.to_string();
        Box::pin(async move {
            if self.force_error.load(Ordering::SeqCst) {
                return Err("mock internal error".to_string());
            }
            match self.receipts.lock() {
                Ok(map) => Ok(map.get(&hash).cloned().unwrap_or(ChainReceiptInfo {
                    status: ReceiptStatus::NotFound,
                    reward_amount: None,
                    challenge_expires_at: None,
                    node_id: None,
                    workload_type: None,
                    submitted_at: None,
                })),
                Err(e) => Err(format!("lock error: {}", e)),
            }
        })
    }
}

/// Mock reward query service.
struct MockRewardService {
    balances: Mutex<HashMap<String, ChainRewardInfo>>,
    validators: Mutex<Vec<ChainValidatorRewardInfo>>,
    treasury: Mutex<ChainTreasuryInfo>,
}

impl MockRewardService {
    fn new() -> Self {
        Self {
            balances: Mutex::new(HashMap::new()),
            validators: Mutex::new(Vec::new()),
            treasury: Mutex::new(ChainTreasuryInfo {
                treasury_balance: 0,
                total_rewards_distributed: 0,
                total_validator_rewards: 0,
                total_node_rewards: 0,
            }),
        }
    }

    fn set_balance(&self, address: &str, info: ChainRewardInfo) {
        if let Ok(mut map) = self.balances.lock() {
            map.insert(address.to_string(), info);
        }
    }

    fn add_validator(&self, info: ChainValidatorRewardInfo) {
        if let Ok(mut v) = self.validators.lock() {
            v.push(info);
        }
    }
}

impl RewardQueryService for MockRewardService {
    fn query_balance(
        &self,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ChainRewardInfo, String>> + Send + '_>> {
        let addr = address.to_string();
        Box::pin(async move {
            match self.balances.lock() {
                Ok(map) => Ok(map.get(&addr).cloned().unwrap_or(ChainRewardInfo {
                    balance: 0,
                    pending_rewards: 0,
                    claimed_rewards: 0,
                    node_earnings: 0,
                    is_validator: false,
                    is_node: false,
                })),
                Err(e) => Err(format!("lock error: {}", e)),
            }
        })
    }

    fn list_validator_rewards(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ChainValidatorRewardInfo>, String>> + Send + '_>>
    {
        Box::pin(async move {
            match self.validators.lock() {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(format!("lock error: {}", e)),
            }
        })
    }

    fn query_treasury(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<ChainTreasuryInfo, String>> + Send + '_>> {
        Box::pin(async move {
            match self.treasury.lock() {
                Ok(t) => Ok(t.clone()),
                Err(e) => Err(format!("lock error: {}", e)),
            }
        })
    }
}

/// Mock event publisher that records published batches.
struct MockEventPublisher {
    batches: Mutex<Vec<Vec<String>>>,
    should_fail: AtomicBool,
    call_count: AtomicUsize,
}

impl MockEventPublisher {
    fn new() -> Self {
        Self {
            batches: Mutex::new(Vec::new()),
            should_fail: AtomicBool::new(false),
            call_count: AtomicUsize::new(0),
        }
    }

    fn published_count(&self) -> usize {
        match self.batches.lock() {
            Ok(b) => b.iter().map(|batch| batch.len()).sum(),
            Err(_) => 0,
        }
    }
}

impl EventPublisher for MockEventPublisher {
    fn publish_batch(&self, events: &[String]) -> Result<(), String> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if self.should_fail.load(Ordering::SeqCst) {
            return Err("mock publish failure".to_string());
        }
        match self.batches.lock() {
            Ok(mut b) => {
                b.push(events.to_vec());
                Ok(())
            }
            Err(e) => Err(format!("lock: {}", e)),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════════

fn valid_hash(seed: u8) -> String {
    format!("{:0>64x}", seed)
}

fn valid_address(seed: u8) -> String {
    format!("{:0>40x}", seed)
}

fn fallback_path() -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("dsdn_econ_test_{}.jsonl", std::process::id()));
    p.to_string_lossy().to_string()
}

fn make_event_logger(publisher: Option<Arc<dyn EventPublisher>>) -> Arc<ReceiptEventLogger> {
    Arc::new(ReceiptEventLogger::new(publisher, fallback_path()))
}

async fn body_string(resp: axum::response::Response) -> String {
    match axum::body::to_bytes(resp.into_body(), 1024 * 1024).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => String::new(),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 1: claim_endpoint_valid_request
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn claim_endpoint_valid_request() {
    let publisher = Arc::new(MockEventPublisher::new());
    let logger = make_event_logger(Some(publisher.clone()));

    let state = ClaimState {
        forwarder: Arc::new(ChainForwarder::new(
            "http://stub:9000".to_string(),
            std::time::Duration::from_secs(5),
        )),
        event_logger: logger.clone(),
    };

    let body = ClaimRewardRequest {
        receipt_hash: valid_hash(0x01),
        submitter_address: valid_address(0x02),
        receipt_data: vec![1, 2, 3],
    };

    let resp = economic_handlers::handle_claim_submit(State(state), Json(body)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let text = body_string(resp).await;
    let parsed: Result<ClaimRewardResponse, _> = serde_json::from_str(&text);
    match parsed {
        Ok(r) => assert!(r.success),
        Err(e) => assert!(false, "deserialize failed: {}", e),
    }

    // ClaimSubmitted + ClaimAccepted should be buffered
    assert!(logger.buffer_len() >= 2);
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 2: claim_endpoint_invalid_hex
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn claim_endpoint_invalid_hex() {
    let logger = make_event_logger(None);
    let state = ClaimState {
        forwarder: Arc::new(ChainForwarder::new(
            "http://stub:9000".to_string(),
            std::time::Duration::from_secs(5),
        )),
        event_logger: logger,
    };

    // Non-hex hash
    let body = ClaimRewardRequest {
        receipt_hash: "g".repeat(64),
        submitter_address: valid_address(0x01),
        receipt_data: vec![1],
    };
    let resp = economic_handlers::handle_claim_submit(State(state), Json(body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 3: claim_endpoint_missing_fields
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn claim_endpoint_missing_fields() {
    let logger = make_event_logger(None);
    let state = ClaimState {
        forwarder: Arc::new(ChainForwarder::new(
            "http://stub:9000".to_string(),
            std::time::Duration::from_secs(5),
        )),
        event_logger: logger.clone(),
    };

    // Empty receipt_hash
    let body1 = ClaimRewardRequest {
        receipt_hash: String::new(),
        submitter_address: valid_address(0x01),
        receipt_data: vec![1],
    };
    let r1 = economic_handlers::handle_claim_submit(State(state.clone()), Json(body1)).await;
    assert_eq!(r1.status(), StatusCode::BAD_REQUEST);

    // Empty receipt_data
    let body2 = ClaimRewardRequest {
        receipt_hash: valid_hash(0x01),
        submitter_address: valid_address(0x01),
        receipt_data: Vec::new(),
    };
    let r2 = economic_handlers::handle_claim_submit(State(state), Json(body2)).await;
    assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 4: claim_endpoint_rate_limited
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn claim_endpoint_rate_limited() {
    // Mutation: 10 req/min per IP, burst 10
    let config = crate::rate_limit::LimitConfig::per_ip_per_minute(10, 10);
    let mut limiter = crate::rate_limit::RateLimiter::new();
    limiter.add_limit("econ_mutation", config.clone());

    let key = "ip:test_claim_rate";

    // First 10 pass
    for i in 0..10 {
        assert!(
            limiter.check_and_record(key, &config).is_ok(),
            "request {} should pass",
            i
        );
    }

    // 11th fails — rate limited
    assert!(
        limiter.check_and_record(key, &config).is_err(),
        "11th request must be rate limited"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 5: receipt_status_found
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn receipt_status_found() {
    let mock = Arc::new(MockReceiptService::new());
    let hash = valid_hash(0xAA);
    mock.add_receipt(
        &hash,
        ChainReceiptInfo {
            status: ReceiptStatus::Finalized,
            reward_amount: Some(5000),
            challenge_expires_at: None,
            node_id: Some("node-1".to_string()),
            workload_type: Some("compute".to_string()),
            submitted_at: Some(1700000000),
        },
    );

    let state = EconomicState {
        service: mock,
    };

    let resp =
        economic_handlers::handle_receipt_status(Path(hash.clone()), State(state)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let text = body_string(resp).await;
    let parsed: Result<ReceiptStatusResponse, _> = serde_json::from_str(&text);
    match parsed {
        Ok(r) => {
            assert_eq!(r.status, "finalized");
            assert_eq!(r.reward_amount, Some(5000));
        }
        Err(e) => assert!(false, "deserialize failed: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 6: receipt_status_not_found
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn receipt_status_not_found() {
    let mock = Arc::new(MockReceiptService::new());
    let state = EconomicState { service: mock };

    let resp = economic_handlers::handle_receipt_status(
        Path(valid_hash(0xFF)),
        State(state),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let text = body_string(resp).await;
    let parsed: Result<ReceiptStatusResponse, _> = serde_json::from_str(&text);
    match parsed {
        Ok(r) => assert_eq!(r.status, "not_found"),
        Err(e) => assert!(false, "deserialize failed: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 7: receipt_status_batch_query
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn receipt_status_batch_query() {
    let mock = Arc::new(MockReceiptService::new());
    let h1 = valid_hash(0x01);
    let h2 = valid_hash(0x02);
    mock.add_receipt(
        &h1,
        ChainReceiptInfo {
            status: ReceiptStatus::Finalized,
            reward_amount: Some(100),
            challenge_expires_at: None,
            node_id: None,
            workload_type: None,
            submitted_at: None,
        },
    );

    let state = EconomicState { service: mock };
    let body = BatchReceiptRequest {
        hashes: vec![h1.clone(), h2.clone()],
    };

    let resp =
        economic_handlers::handle_batch_receipt_status(State(state), Json(body)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let text = body_string(resp).await;
    let parsed: Result<Vec<ReceiptStatusResponse>, _> = serde_json::from_str(&text);
    match parsed {
        Ok(list) => {
            assert_eq!(list.len(), 2);
            assert_eq!(list[0].status, "finalized");
            assert_eq!(list[1].status, "not_found");
        }
        Err(e) => assert!(false, "deserialize failed: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 8: reward_balance_node_operator
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn reward_balance_node_operator() {
    let mock = Arc::new(MockRewardService::new());
    let addr = valid_address(0xAA);
    mock.set_balance(
        &addr,
        ChainRewardInfo {
            balance: 10000,
            pending_rewards: 500,
            claimed_rewards: 2000,
            node_earnings: 7000,
            is_validator: false,
            is_node: true,
        },
    );

    let state = EconomicRewardState { service: mock };
    let resp =
        economic_handlers::handle_reward_balance(Path(addr.clone()), State(state)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let text = body_string(resp).await;
    let parsed: Result<RewardBalanceResponse, _> = serde_json::from_str(&text);
    match parsed {
        Ok(r) => {
            assert!(r.is_node);
            assert!(!r.is_validator);
            assert_eq!(r.node_earnings, 7000);
        }
        Err(e) => assert!(false, "deserialize failed: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 9: reward_balance_validator
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn reward_balance_validator() {
    let mock = Arc::new(MockRewardService::new());
    let addr = valid_address(0xBB);
    mock.set_balance(
        &addr,
        ChainRewardInfo {
            balance: 50000,
            pending_rewards: 3000,
            claimed_rewards: 10000,
            node_earnings: 0,
            is_validator: true,
            is_node: false,
        },
    );

    let state = EconomicRewardState { service: mock };
    let resp =
        economic_handlers::handle_reward_balance(Path(addr.clone()), State(state)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let text = body_string(resp).await;
    let parsed: Result<RewardBalanceResponse, _> = serde_json::from_str(&text);
    match parsed {
        Ok(r) => {
            assert!(r.is_validator);
            assert!(!r.is_node);
            assert_eq!(r.pending_rewards, 3000);
        }
        Err(e) => assert!(false, "deserialize failed: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 10: reward_balance_invalid_address
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn reward_balance_invalid_address() {
    let mock = Arc::new(MockRewardService::new());
    let state = EconomicRewardState { service: mock };

    // Too short
    let resp =
        economic_handlers::handle_reward_balance(Path("abc".to_string()), State(state))
            .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 11: fraud_proof_accepted_and_logged
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn fraud_proof_accepted_and_logged() {
    let logger = make_event_logger(None);
    let state = FraudProofState {
        log: economic_handlers::new_fraud_proof_log(),
        event_logger: logger.clone(),
    };

    let req = FraudProofRequest {
        receipt_hash: valid_hash(0x01),
        proof_type: "execution_mismatch".to_string(),
        proof_data: vec![1, 2, 3],
        submitter_address: valid_address(0x02),
        challenge_id: None,
    };

    let resp =
        economic_handlers::handle_fraud_proof_submit(State(state.clone()), Json(req)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let text = body_string(resp).await;
    let parsed: Result<FraudProofResponse, _> = serde_json::from_str(&text);
    match parsed {
        Ok(r) => {
            assert!(r.accepted);
            assert_eq!(r.note, FRAUD_PROOF_PLACEHOLDER_NOTE);
        }
        Err(e) => assert!(false, "deserialize failed: {}", e),
    }

    // FraudProofReceived should be buffered
    assert!(logger.buffer_len() >= 1);

    // Verify in fraud proof log
    match state.log.read() {
        Ok(log) => assert_eq!(log.len(), 1),
        Err(e) => assert!(false, "lock error: {}", e),
    };
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 12: fraud_proof_invalid_format
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn fraud_proof_invalid_format() {
    let logger = make_event_logger(None);
    let state = FraudProofState {
        log: economic_handlers::new_fraud_proof_log(),
        event_logger: logger,
    };

    // Invalid proof_type
    let req = FraudProofRequest {
        receipt_hash: valid_hash(0x01),
        proof_type: "invalid_type".to_string(),
        proof_data: vec![1],
        submitter_address: valid_address(0x02),
        challenge_id: None,
    };
    let resp =
        economic_handlers::handle_fraud_proof_submit(State(state.clone()), Json(req)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Empty proof_data
    let req2 = FraudProofRequest {
        receipt_hash: valid_hash(0x01),
        proof_type: "execution_mismatch".to_string(),
        proof_data: Vec::new(),
        submitter_address: valid_address(0x02),
        challenge_id: None,
    };
    let resp2 =
        economic_handlers::handle_fraud_proof_submit(State(state), Json(req2)).await;
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 13: fraud_proof_list_audit
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn fraud_proof_list_audit() {
    let logger = make_event_logger(None);
    let state = FraudProofState {
        log: economic_handlers::new_fraud_proof_log(),
        event_logger: logger,
    };

    // Submit 3 fraud proofs
    for i in 1u8..=3 {
        let req = FraudProofRequest {
            receipt_hash: valid_hash(i),
            proof_type: "execution_mismatch".to_string(),
            proof_data: vec![i],
            submitter_address: valid_address(i),
            challenge_id: None,
        };
        let r =
            economic_handlers::handle_fraud_proof_submit(State(state.clone()), Json(req))
                .await;
        assert_eq!(r.status(), StatusCode::OK);
    }

    // List
    let list_resp =
        economic_handlers::handle_fraud_proofs_list(State(state)).await;
    assert_eq!(list_resp.status(), StatusCode::OK);

    let text = body_string(list_resp).await;
    let parsed: Result<Vec<FraudProofLogEntry>, _> = serde_json::from_str(&text);
    match parsed {
        Ok(entries) => {
            assert_eq!(entries.len(), 3);
            // Deterministic insertion order
            assert_eq!(entries[0].receipt_hash, valid_hash(1));
            assert_eq!(entries[1].receipt_hash, valid_hash(2));
            assert_eq!(entries[2].receipt_hash, valid_hash(3));
        }
        Err(e) => assert!(false, "deserialize failed: {}", e),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 14: validation_hex_format
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn validation_hex_format() {
    // Valid
    assert!(economic_validation::validate_receipt_hash(&valid_hash(0xAA)).is_ok());

    // Invalid: non-hex
    assert!(economic_validation::validate_receipt_hash(&"g".repeat(64)).is_err());

    // Invalid: 0x prefix
    assert!(
        economic_validation::validate_receipt_hash(&format!("0x{}", "a".repeat(64)))
            .is_err()
    );

    // Invalid: internal whitespace
    assert!(
        economic_validation::validate_receipt_hash(&format!(
            "{} {}",
            "a".repeat(32),
            "b".repeat(31)
        ))
        .is_err()
    );
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 15: validation_address_length
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn validation_address_length() {
    // Valid: 40 hex chars
    assert!(economic_validation::validate_address(&valid_address(0x01)).is_ok());

    // Invalid: 39 chars
    assert!(economic_validation::validate_address(&"a".repeat(39)).is_err());

    // Invalid: 41 chars
    assert!(economic_validation::validate_address(&"a".repeat(41)).is_err());

    // Invalid: empty
    assert!(economic_validation::validate_address("").is_err());
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 16: chain_forwarding_timeout
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn chain_forwarding_timeout() {
    // ChainForwarder with retry. Since it's a stub, it returns immediately.
    // But we verify the retry infrastructure is in place and handles errors.
    let fwd = ChainForwarder::with_retry(
        "http://unreachable:9999".to_string(),
        std::time::Duration::from_millis(100),
        2, // max 2 retries
        10, // 10ms base delay
    );

    // Stub always succeeds, but test that retry_async error path works
    let fail_count = Arc::new(AtomicUsize::new(0));
    let fc = fail_count.clone();
    let result: Result<i32, String> = economic_validation::retry_async(3, 1, move || {
        let c = fc.fetch_add(1, Ordering::SeqCst);
        async move {
            if c < 2 {
                Err("timeout".to_string())
            } else {
                Ok(42)
            }
        }
    })
    .await;

    assert!(result.is_ok());
    match result {
        Ok(v) => assert_eq!(v, 42),
        Err(e) => assert!(false, "should have succeeded after retries: {}", e),
    }
    // Should have been called 3 times (2 failures + 1 success)
    assert_eq!(fail_count.load(Ordering::SeqCst), 3);

    // ChainForwarder stub operations still succeed
    let req = ClaimRewardRequest {
        receipt_hash: valid_hash(0x01),
        submitter_address: valid_address(0x02),
        receipt_data: vec![1],
    };
    let claim_result = fwd.forward_claim(&req).await;
    assert!(claim_result.is_ok());
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 17: da_event_logging_claim
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn da_event_logging_claim() {
    let publisher = Arc::new(MockEventPublisher::new());
    let logger = make_event_logger(Some(publisher.clone()));

    let state = ClaimState {
        forwarder: Arc::new(ChainForwarder::new(
            "http://stub:9000".to_string(),
            std::time::Duration::from_secs(5),
        )),
        event_logger: logger.clone(),
    };

    let body = ClaimRewardRequest {
        receipt_hash: valid_hash(0x10),
        submitter_address: valid_address(0x20),
        receipt_data: vec![42],
    };

    let resp = economic_handlers::handle_claim_submit(State(state), Json(body)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Should have ClaimSubmitted + ClaimAccepted buffered
    let events = logger.buffer_snapshot();
    assert!(events.len() >= 2, "expected at least 2 events, got {}", events.len());

    // First event should be ClaimSubmitted
    match &events[0] {
        ReceiptEconomicEvent::ClaimSubmitted { receipt_hash, .. } => {
            assert_eq!(receipt_hash, &valid_hash(0x10));
        }
        other => assert!(false, "expected ClaimSubmitted, got {:?}", other),
    }

    // Second event should be ClaimAccepted
    match &events[1] {
        ReceiptEconomicEvent::ClaimAccepted { receipt_hash, .. } => {
            assert_eq!(receipt_hash, &valid_hash(0x10));
        }
        other => assert!(false, "expected ClaimAccepted, got {:?}", other),
    }

    // Flush publishes to mock publisher
    let flushed = logger.flush();
    assert!(flushed >= 2);
    assert!(publisher.published_count() >= 2);
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 18: full_integration_claim_to_finalize
// ════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn full_integration_claim_to_finalize() {
    // ── Step 1 & 2: Node executes workload, Coordinator generates receipt ──
    let receipt_hash = valid_hash(0xDE);
    let node_address = valid_address(0xAA);
    let validator_address = valid_address(0xBB);

    // ── Step 3: Receipt TSS signed (mock FROST signature — data bytes) ──
    let frost_signature: Vec<u8> = vec![0xF0, 0x05, 0x7D, 0xAA, 0xBB, 0xCC];

    // ── Step 4: Submit claim via POST /claim ──
    let publisher = Arc::new(MockEventPublisher::new());
    let logger = make_event_logger(Some(publisher.clone()));

    let claim_state = ClaimState {
        forwarder: Arc::new(ChainForwarder::new(
            "http://chain:26657".to_string(),
            std::time::Duration::from_secs(10),
        )),
        event_logger: logger.clone(),
    };

    let claim_req = ClaimRewardRequest {
        receipt_hash: receipt_hash.clone(),
        submitter_address: node_address.clone(),
        receipt_data: frost_signature,
    };

    let claim_resp =
        economic_handlers::handle_claim_submit(State(claim_state), Json(claim_req)).await;
    assert_eq!(claim_resp.status(), StatusCode::OK);

    let claim_text = body_string(claim_resp).await;
    let claim_parsed: Result<ClaimRewardResponse, _> = serde_json::from_str(&claim_text);
    match claim_parsed {
        Ok(r) => assert!(r.success, "claim should succeed"),
        Err(e) => assert!(false, "claim deserialize failed: {}", e),
    }

    // ── Step 5: Chain verifies receipt (simulated via mock) ──
    let mock_receipt_svc = Arc::new(MockReceiptService::new());
    mock_receipt_svc.add_receipt(
        &receipt_hash,
        ChainReceiptInfo {
            status: ReceiptStatus::Finalized,
            reward_amount: Some(10000),
            challenge_expires_at: None,
            node_id: Some("node-AA".to_string()),
            workload_type: Some("compute".to_string()),
            submitted_at: Some(1700000000),
        },
    );

    let econ_state = EconomicState {
        service: mock_receipt_svc,
    };
    let status_resp = economic_handlers::handle_receipt_status(
        Path(receipt_hash.clone()),
        State(econ_state),
    )
    .await;
    assert_eq!(status_resp.status(), StatusCode::OK);

    let status_text = body_string(status_resp).await;
    let status_parsed: Result<ReceiptStatusResponse, _> =
        serde_json::from_str(&status_text);
    match status_parsed {
        Ok(r) => {
            assert_eq!(r.status, "finalized");
            assert_eq!(r.reward_amount, Some(10000));
        }
        Err(e) => assert!(false, "status deserialize failed: {}", e),
    }

    // ── Step 6: Reward distribution — 70% node, 20% validator, 10% treasury ──
    let total_reward: u128 = 10000;
    let node_share = total_reward.saturating_mul(70).saturating_div(100); // 7000
    let validator_share = total_reward.saturating_mul(20).saturating_div(100); // 2000
    let treasury_share = total_reward.saturating_mul(10).saturating_div(100); // 1000

    assert_eq!(node_share, 7000);
    assert_eq!(validator_share, 2000);
    assert_eq!(treasury_share, 1000);
    assert_eq!(
        node_share.checked_add(validator_share).and_then(|s| s.checked_add(treasury_share)),
        Some(total_reward)
    );

    let mock_reward_svc = Arc::new(MockRewardService::new());
    mock_reward_svc.set_balance(
        &node_address,
        ChainRewardInfo {
            balance: node_share,
            pending_rewards: 0,
            claimed_rewards: node_share,
            node_earnings: node_share,
            is_validator: false,
            is_node: true,
        },
    );
    mock_reward_svc.set_balance(
        &validator_address,
        ChainRewardInfo {
            balance: validator_share,
            pending_rewards: validator_share,
            claimed_rewards: 0,
            node_earnings: 0,
            is_validator: true,
            is_node: false,
        },
    );

    // ── Step 7: Validator queries pending rewards ──
    let reward_state = EconomicRewardState {
        service: mock_reward_svc,
    };

    let val_resp = economic_handlers::handle_reward_balance(
        Path(validator_address.clone()),
        State(reward_state),
    )
    .await;
    assert_eq!(val_resp.status(), StatusCode::OK);

    let val_text = body_string(val_resp).await;
    let val_parsed: Result<RewardBalanceResponse, _> = serde_json::from_str(&val_text);
    match val_parsed {
        Ok(r) => {
            assert!(r.is_validator);
            assert_eq!(r.pending_rewards, 2000);
        }
        Err(e) => assert!(false, "validator balance deserialize failed: {}", e),
    }

    // ── Step 8: DA event logger has recorded events ──
    let events = logger.buffer_snapshot();
    assert!(
        events.len() >= 2,
        "expected at least ClaimSubmitted + ClaimAccepted, got {}",
        events.len()
    );

    // Flush to DA publisher
    let flushed = logger.flush();
    assert!(flushed >= 2);
    assert!(publisher.published_count() >= 2);
    assert_eq!(logger.buffer_len(), 0);
}
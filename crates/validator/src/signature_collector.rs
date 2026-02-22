//! # Signature Collection Mechanism
//!
//! Mekanisme pengumpulan signature dari validator secara parallel
//! dengan early return ketika quorum tercapai.
//!
//! ## Parallelism Model
//!
//! `SignatureCollector` mengirim request ke semua validator secara bersamaan
//! menggunakan async/await dengan tokio. Request dikirim secara parallel,
//! bukan sequential.
//!
//! ## Early Return Semantics
//!
//! Begitu jumlah signature valid mencapai quorum threshold,
//! method `collect()` segera return tanpa menunggu validator lain.
//! Task yang masih pending akan di-drop secara aman.
//!
//! ## Timeout Behavior
//!
//! Setiap request ke validator memiliki timeout individual
//! berdasarkan `config.signature_timeout_ms`. Validator yang timeout
//! dianggap gagal tetapi tidak menggagalkan keseluruhan proses
//! selama quorum masih bisa tercapai.

use crate::quorum_da::{QuorumDAConfig, ValidatorSignature};
use std::fmt;
use std::time::Duration;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error yang dapat terjadi saat pengumpulan signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureCollectionError {
    /// Request ke validator timeout.
    Timeout {
        /// ID validator yang timeout.
        validator_id: String,
    },

    /// Response dari validator tidak valid.
    InvalidResponse {
        /// ID validator.
        validator_id: String,
        /// Detail error.
        message: String,
    },

    /// Error network saat menghubungi validator.
    NetworkError {
        /// ID validator (jika diketahui).
        validator_id: Option<String>,
        /// Detail error.
        message: String,
    },

    /// Quorum tidak tercapai setelah semua attempt selesai.
    QuorumNotReached {
        /// Jumlah signature yang berhasil dikumpulkan.
        collected: usize,
        /// Threshold yang diperlukan.
        required: usize,
    },

    /// Error internal.
    Internal(String),
}

impl fmt::Display for SignatureCollectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureCollectionError::Timeout { validator_id } => {
                write!(f, "timeout waiting for signature from validator {}", validator_id)
            }
            SignatureCollectionError::InvalidResponse { validator_id, message } => {
                write!(f, "invalid response from validator {}: {}", validator_id, message)
            }
            SignatureCollectionError::NetworkError { validator_id, message } => {
                match validator_id {
                    Some(id) => write!(f, "network error for validator {}: {}", id, message),
                    None => write!(f, "network error: {}", message),
                }
            }
            SignatureCollectionError::QuorumNotReached { collected, required } => {
                write!(f, "quorum not reached: collected {} signatures, required {}", collected, required)
            }
            SignatureCollectionError::Internal(msg) => {
                write!(f, "internal error: {}", msg)
            }
        }
    }
}

impl std::error::Error for SignatureCollectionError {}

// ════════════════════════════════════════════════════════════════════════════════
// VALIDATOR ENDPOINT
// ════════════════════════════════════════════════════════════════════════════════

/// Endpoint validator untuk pengumpulan signature.
///
/// ## Fields
///
/// - `id`: Identifier unik validator
/// - `url`: URL endpoint untuk request signature
/// - `public_key`: Public key validator (format opaque)
///
/// ## Invariants
///
/// - Tidak ada validasi kriptografi di struct ini
/// - Tidak ada parsing URL implisit
/// - Public key format adalah implementasi-specific
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorEndpoint {
    /// Unique identifier validator.
    pub id: String,

    /// URL endpoint untuk signature request.
    pub url: String,

    /// Public key validator dalam bytes.
    pub public_key: Vec<u8>,
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNATURE RESPONSE (INTERNAL)
// ════════════════════════════════════════════════════════════════════════════════

/// Response dari validator untuk signature request.
#[derive(Debug, Clone, serde::Deserialize)]
struct SignatureResponse {
    /// ID validator.
    validator_id: String,
    /// Signature bytes dalam hex.
    signature_hex: String,
    /// Timestamp saat signature dibuat.
    timestamp: u64,
}

/// Result dari satu attempt pengumpulan signature.
#[derive(Debug)]
enum CollectAttemptResult {
    /// Signature berhasil dikumpulkan.
    Success(ValidatorSignature),
    /// Request timeout.
    Timeout(String),
    /// Response tidak valid.
    InvalidResponse(String, String),
    /// Network error.
    NetworkError(String, String),
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNATURE COLLECTOR
// ════════════════════════════════════════════════════════════════════════════════

/// Collector untuk mengumpulkan signature dari validator secara parallel.
///
/// ## Parallelism
///
/// Request ke validator dikirim secara bersamaan menggunakan async tasks.
/// Tidak ada blocking wait atau busy loop.
///
/// ## Early Return
///
/// Method `collect()` akan return segera setelah quorum tercapai.
/// Task yang masih pending akan di-cancel secara aman.
///
/// ## Thread Safety
///
/// - Tidak ada shared mutable state
/// - Futures dapat di-drop dengan aman
/// - Deterministic terhadap input yang sama (jika response sama)
#[derive(Debug, Clone)]
pub struct SignatureCollector {
    /// Daftar validator endpoint.
    validators: Vec<ValidatorEndpoint>,

    /// Konfigurasi QuorumDA.
    config: QuorumDAConfig,

    /// HTTP client untuk request (injected, bukan global).
    client: reqwest::Client,
}

impl SignatureCollector {
    /// Membuat SignatureCollector baru.
    ///
    /// ## Parameters
    ///
    /// - `validators`: Daftar endpoint validator
    /// - `config`: Konfigurasi QuorumDA
    /// - `client`: HTTP client (di-inject untuk testability)
    #[must_use]
    pub fn new(
        validators: Vec<ValidatorEndpoint>,
        config: QuorumDAConfig,
        client: reqwest::Client,
    ) -> Self {
        Self {
            validators,
            config,
            client,
        }
    }

    /// Mengumpulkan signature dari validator secara parallel.
    ///
    /// ## Parameters
    ///
    /// - `data_hash`: SHA-256 hash dari data yang akan di-sign
    ///
    /// ## Returns
    ///
    /// - `Ok(Vec<ValidatorSignature>)`: Signature yang berhasil dikumpulkan (>= threshold)
    /// - `Err(SignatureCollectionError)`: Jika quorum tidak tercapai
    ///
    /// ## Behavior
    ///
    /// 1. Hitung quorum threshold
    /// 2. Jika threshold == 0, return empty vec
    /// 3. Kirim request ke semua validator secara parallel
    /// 4. Begitu quorum tercapai, return immediately
    /// 5. Jika semua selesai dan quorum belum tercapai, return error
    ///
    /// ## Timeout
    ///
    /// Setiap validator request memiliki timeout individual
    /// berdasarkan `config.signature_timeout_ms`.
    pub async fn collect(
        &self,
        data_hash: &[u8; 32],
    ) -> Result<Vec<ValidatorSignature>, SignatureCollectionError> {
        // Step 1: Calculate quorum threshold
        let threshold = self.config.calculate_quorum_threshold(self.validators.len());

        // Step 2: If threshold is 0, return empty vec
        if threshold == 0 {
            return Ok(Vec::new());
        }

        // Step 3: Spawn parallel requests to all validators
        let timeout_duration = Duration::from_millis(self.config.signature_timeout_ms);
        let data_hash_hex = hex::encode(data_hash);

        // Create futures for all validator requests
        let mut futures: Vec<_> = self
            .validators
            .iter()
            .map(|validator| {
                let client = self.client.clone();
                let url = validator.url.clone();
                let validator_id = validator.id.clone();
                let hash = data_hash_hex.clone();
                let timeout = timeout_duration;

                async move {
                    Self::request_signature(client, &url, &validator_id, &hash, timeout).await
                }
            })
            .collect();

        // Step 4 & 5: Collect signatures with early return
        let mut collected_signatures: Vec<ValidatorSignature> = Vec::new();
        let mut failures: Vec<CollectAttemptResult> = Vec::new();

        // Use tokio::select! pattern with FuturesUnordered for early return
        use futures::stream::{FuturesUnordered, StreamExt};

        let mut pending: FuturesUnordered<_> = futures.drain(..).collect();

        while let Some(result) = pending.next().await {
            match result {
                CollectAttemptResult::Success(sig) => {
                    collected_signatures.push(sig);

                    // Early return if quorum reached
                    if collected_signatures.len() >= threshold {
                        // Drop remaining futures by returning early
                        return Ok(collected_signatures);
                    }
                }
                failure => {
                    failures.push(failure);
                }
            }

            // Check if it's still possible to reach quorum
            let remaining = pending.len();
            let max_possible = collected_signatures.len() + remaining;
            if max_possible < threshold {
                // Cannot reach quorum even if all remaining succeed
                break;
            }
        }

        // Step 6: Quorum not reached
        Err(SignatureCollectionError::QuorumNotReached {
            collected: collected_signatures.len(),
            required: threshold,
        })
    }

    /// Request signature dari satu validator.
    async fn request_signature(
        client: reqwest::Client,
        url: &str,
        validator_id: &str,
        data_hash_hex: &str,
        timeout: Duration,
    ) -> CollectAttemptResult {
        // Build request
        let request_result: Result<reqwest::Response, reqwest::Error> = client
            .post(url)
            .json(&serde_json::json!({
                "data_hash": data_hash_hex
            }))
            .timeout(timeout)
            .send()
            .await;

        let response: reqwest::Response = match request_result {
            Ok(resp) => resp,
            Err(e) => {
                if e.is_timeout() {
                    return CollectAttemptResult::Timeout(validator_id.to_string());
                }
                return CollectAttemptResult::NetworkError(
                    validator_id.to_string(),
                    e.to_string(),
                );
            }
        };

        // Check status
        if !response.status().is_success() {
            return CollectAttemptResult::InvalidResponse(
                validator_id.to_string(),
                format!("HTTP status {}", response.status()),
            );
        }

        // Parse response
        let body_result = response.json::<SignatureResponse>().await;
        let body = match body_result {
            Ok(b) => b,
            Err(e) => {
                return CollectAttemptResult::InvalidResponse(
                    validator_id.to_string(),
                    format!("failed to parse response: {}", e),
                );
            }
        };

        // Decode signature from hex
        let signature_bytes = match hex::decode(&body.signature_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                return CollectAttemptResult::InvalidResponse(
                    validator_id.to_string(),
                    format!("invalid signature hex: {}", e),
                );
            }
        };

        CollectAttemptResult::Success(ValidatorSignature {
            validator_id: body.validator_id,
            signature: signature_bytes,
            timestamp: body.timestamp,
        })
    }

    /// Returns the number of validators.
    #[must_use]
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Returns the quorum threshold for current validators.
    #[must_use]
    pub fn quorum_threshold(&self) -> usize {
        self.config.calculate_quorum_threshold(self.validators.len())
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};

    fn create_test_config(min_validators: usize, quorum_fraction: f64) -> QuorumDAConfig {
        QuorumDAConfig {
            min_validators,
            quorum_fraction,
            signature_timeout_ms: 1000, // 1 second for tests
            max_blob_size: 1024,
            validator_endpoints: Vec::new(),
            retry_count: 0,
        }
    }

    fn create_test_endpoint(id: &str, url: &str) -> ValidatorEndpoint {
        ValidatorEndpoint {
            id: id.to_string(),
            url: url.to_string(),
            public_key: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn test_signature_collection_error_display() {
        let err = SignatureCollectionError::QuorumNotReached {
            collected: 1,
            required: 2,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("quorum not reached"));
        assert!(msg.contains("collected 1"));
        assert!(msg.contains("required 2"));
    }

    #[test]
    fn test_validator_endpoint_construction() {
        let endpoint = ValidatorEndpoint {
            id: "v1".to_string(),
            url: "http://localhost:45831".to_string(),
            public_key: vec![0xDE, 0xAD],
        };
        assert_eq!(endpoint.id, "v1");
        assert_eq!(endpoint.url, "http://localhost:45831");
        assert_eq!(endpoint.public_key, vec![0xDE, 0xAD]);
    }

    #[test]
    fn test_signature_collector_new() {
        let config = create_test_config(2, 0.67);
        let client = reqwest::Client::new();
        let validators = vec![
            create_test_endpoint("v1", "http://a:1"),
            create_test_endpoint("v2", "http://b:2"),
        ];

        let collector = SignatureCollector::new(validators.clone(), config, client);
        assert_eq!(collector.validator_count(), 2);
    }

    #[test]
    fn test_signature_collector_quorum_threshold() {
        let config = create_test_config(1, 0.67);
        let client = reqwest::Client::new();
        let validators = vec![
            create_test_endpoint("v1", "http://a:1"),
            create_test_endpoint("v2", "http://b:2"),
            create_test_endpoint("v3", "http://c:3"),
        ];

        let collector = SignatureCollector::new(validators, config, client);
        // 3 validators * 0.67 = 2.01 -> ceil = 3
        assert_eq!(collector.quorum_threshold(), 3);
    }

    #[tokio::test]
    async fn test_collect_with_zero_validators_returns_empty() {
        let config = create_test_config(1, 0.67);
        let client = reqwest::Client::new();
        let validators: Vec<ValidatorEndpoint> = Vec::new();

        let collector = SignatureCollector::new(validators, config, client);
        let data_hash = [0u8; 32];

        let result = collector.collect(&data_hash).await;
        assert!(result.is_ok());
        assert!(result.as_ref().ok().map(|v| v.is_empty()).unwrap_or(false));
    }

    #[tokio::test]
    async fn test_collect_success_with_mock_validators() {
        // Start mock servers
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;
        let server3 = MockServer::start().await;

        // Setup responses
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "validator_id": "v1",
                "signature_hex": "deadbeef",
                "timestamp": 1700000000
            })))
            .mount(&server1)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "validator_id": "v2",
                "signature_hex": "cafebabe",
                "timestamp": 1700000001
            })))
            .mount(&server2)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "validator_id": "v3",
                "signature_hex": "12345678",
                "timestamp": 1700000002
            })))
            .mount(&server3)
            .await;

        // Setup collector with low min_validators and fraction to ensure quorum = 2
        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 2.0 / 3.0, // 3 * 0.666 = 2
            signature_timeout_ms: 5000,
            ..Default::default()
        };

        let client = reqwest::Client::new();
        let validators = vec![
            create_test_endpoint("v1", &server1.uri()),
            create_test_endpoint("v2", &server2.uri()),
            create_test_endpoint("v3", &server3.uri()),
        ];

        let collector = SignatureCollector::new(validators, config, client);
        let data_hash = [0u8; 32];

        let result = collector.collect(&data_hash).await;
        assert!(result.is_ok());
        let signatures = result.unwrap();
        // Should have at least 2 signatures (quorum)
        assert!(signatures.len() >= 2);
    }

    #[tokio::test]
    async fn test_collect_one_timeout_still_reaches_quorum() {
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;
        let server3 = MockServer::start().await;

        // Server 1: responds quickly
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "validator_id": "v1",
                "signature_hex": "deadbeef",
                "timestamp": 1700000000
            })))
            .mount(&server1)
            .await;

        // Server 2: responds quickly
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "validator_id": "v2",
                "signature_hex": "cafebabe",
                "timestamp": 1700000001
            })))
            .mount(&server2)
            .await;

        // Server 3: delays (simulating timeout)
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "validator_id": "v3",
                    "signature_hex": "12345678",
                    "timestamp": 1700000002
                }))
                .set_delay(Duration::from_secs(10))) // Long delay
            .mount(&server3)
            .await;

        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 2.0 / 3.0,
            signature_timeout_ms: 500, // Short timeout
            ..Default::default()
        };

        let client = reqwest::Client::new();
        let validators = vec![
            create_test_endpoint("v1", &server1.uri()),
            create_test_endpoint("v2", &server2.uri()),
            create_test_endpoint("v3", &server3.uri()),
        ];

        let collector = SignatureCollector::new(validators, config, client);
        let data_hash = [0u8; 32];

        let result = collector.collect(&data_hash).await;
        // Should succeed because v1 and v2 respond quickly
        assert!(result.is_ok());
        let signatures = result.unwrap();
        assert!(signatures.len() >= 2);
    }

    #[tokio::test]
    async fn test_collect_all_timeout_returns_quorum_not_reached() {
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;

        // Both servers delay too long
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "validator_id": "v1",
                    "signature_hex": "deadbeef",
                    "timestamp": 1700000000
                }))
                .set_delay(Duration::from_secs(10)))
            .mount(&server1)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "validator_id": "v2",
                    "signature_hex": "cafebabe",
                    "timestamp": 1700000001
                }))
                .set_delay(Duration::from_secs(10)))
            .mount(&server2)
            .await;

        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 0.5,
            signature_timeout_ms: 100, // Very short timeout
            ..Default::default()
        };

        let client = reqwest::Client::new();
        let validators = vec![
            create_test_endpoint("v1", &server1.uri()),
            create_test_endpoint("v2", &server2.uri()),
        ];

        let collector = SignatureCollector::new(validators, config, client);
        let data_hash = [0u8; 32];

        let result = collector.collect(&data_hash).await;
        assert!(result.is_err());
        match result {
            Err(SignatureCollectionError::QuorumNotReached { collected, required }) => {
                assert_eq!(collected, 0);
                assert!(required > 0);
            }
            _ => panic!("Expected QuorumNotReached error"),
        }
    }

    #[tokio::test]
    async fn test_collect_early_return_after_quorum() {
        // Track how many requests each server receives
        let call_count = Arc::new(AtomicUsize::new(0));

        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;
        let server3 = MockServer::start().await;

        // Servers 1 and 2 respond quickly
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "validator_id": "v1",
                "signature_hex": "deadbeef",
                "timestamp": 1700000000
            })))
            .mount(&server1)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "validator_id": "v2",
                "signature_hex": "cafebabe",
                "timestamp": 1700000001
            })))
            .mount(&server2)
            .await;

        // Server 3 delays significantly
        let count_clone = call_count.clone();
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "validator_id": "v3",
                    "signature_hex": "12345678",
                    "timestamp": 1700000002
                }))
                .set_delay(Duration::from_secs(5)))
            .mount(&server3)
            .await;

        let config = QuorumDAConfig {
            min_validators: 1,
            quorum_fraction: 2.0 / 3.0, // Threshold = 2
            signature_timeout_ms: 10000,
            ..Default::default()
        };

        let client = reqwest::Client::new();
        let validators = vec![
            create_test_endpoint("v1", &server1.uri()),
            create_test_endpoint("v2", &server2.uri()),
            create_test_endpoint("v3", &server3.uri()),
        ];

        let collector = SignatureCollector::new(validators, config, client);
        let data_hash = [0u8; 32];

        let start = std::time::Instant::now();
        let result = collector.collect(&data_hash).await;
        let elapsed = start.elapsed();

        // Should succeed quickly (not waiting for server3's 5s delay)
        assert!(result.is_ok());
        assert!(elapsed < Duration::from_secs(2), "Should return early, took {:?}", elapsed);

        let signatures = result.unwrap();
        assert_eq!(signatures.len(), 2);
    }

    #[test]
    fn test_error_variants() {
        let errors = vec![
            SignatureCollectionError::Timeout { validator_id: "v1".to_string() },
            SignatureCollectionError::InvalidResponse {
                validator_id: "v2".to_string(),
                message: "bad response".to_string(),
            },
            SignatureCollectionError::NetworkError {
                validator_id: Some("v3".to_string()),
                message: "connection refused".to_string(),
            },
            SignatureCollectionError::NetworkError {
                validator_id: None,
                message: "dns error".to_string(),
            },
            SignatureCollectionError::QuorumNotReached {
                collected: 1,
                required: 3,
            },
            SignatureCollectionError::Internal("something went wrong".to_string()),
        ];

        for err in errors {
            // All variants should implement Display
            let _ = format!("{}", err);
        }
    }
}
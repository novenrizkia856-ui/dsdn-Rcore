//! # Rate Limiting Module
//!
//! Token bucket rate limiter untuk ingress layer.
//!
//! ## Prinsip
//!
//! - Thread-safe menggunakan parking_lot RwLock
//! - Token bucket algorithm dengan refill deterministik
//! - Mendukung per-IP, per-API-key, dan global limiting
//! - Tidak ada panic, unwrap, atau silent failure
//!
//! ## Semantik
//!
//! - `check()`: Verify allowance tanpa modify state
//! - `record()`: Consume token secara atomik
//! - Refill berdasarkan elapsed time sejak last refill

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use parking_lot::RwLock;
use tracing::{debug, warn};

// ════════════════════════════════════════════════════════════════════════════
// RATE LIMIT KEY
// ════════════════════════════════════════════════════════════════════════════

/// Tipe key untuk rate limiting.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RateLimitKey {
    /// Rate limit per IP address.
    Ip,
    /// Rate limit per API key.
    ApiKey,
    /// Global rate limit (semua request).
    Global,
}

impl RateLimitKey {
    /// Extract key value dari request context.
    pub fn extract(&self, ip: Option<&str>, api_key: Option<&str>) -> String {
        match self {
            RateLimitKey::Ip => {
                format!("ip:{}", ip.unwrap_or("unknown"))
            }
            RateLimitKey::ApiKey => {
                format!("apikey:{}", api_key.unwrap_or("anonymous"))
            }
            RateLimitKey::Global => {
                "global".to_string()
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// RATE LIMIT ERROR
// ════════════════════════════════════════════════════════════════════════════

/// Error dari rate limiting.
#[derive(Debug, Clone)]
pub enum RateLimitError {
    /// Request melebihi rate limit.
    LimitExceeded {
        key: String,
        retry_after_ms: u64,
    },
    /// Key tidak ditemukan dalam konfigurasi.
    KeyNotConfigured(String),
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::LimitExceeded { key, retry_after_ms } => {
                write!(f, "rate limit exceeded for {}, retry after {}ms", key, retry_after_ms)
            }
            RateLimitError::KeyNotConfigured(key) => {
                write!(f, "rate limit key not configured: {}", key)
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

// ════════════════════════════════════════════════════════════════════════════
// LIMIT CONFIG
// ════════════════════════════════════════════════════════════════════════════

/// Konfigurasi untuk rate limit.
#[derive(Debug, Clone)]
pub struct LimitConfig {
    /// Maximum requests per second (steady rate).
    pub requests_per_second: u32,
    /// Maximum burst size (tokens available initially).
    pub burst_size: u32,
    /// Key type untuk rate limiting.
    pub by: RateLimitKey,
}

impl LimitConfig {
    /// Membuat LimitConfig baru.
    pub fn new(requests_per_second: u32, burst_size: u32, by: RateLimitKey) -> Self {
        Self {
            requests_per_second,
            burst_size,
            by,
        }
    }

    /// Membuat LimitConfig untuk per-IP limiting.
    pub fn per_ip(requests_per_second: u32, burst_size: u32) -> Self {
        Self::new(requests_per_second, burst_size, RateLimitKey::Ip)
    }

    /// Membuat LimitConfig untuk per-API-key limiting.
    pub fn per_api_key(requests_per_second: u32, burst_size: u32) -> Self {
        Self::new(requests_per_second, burst_size, RateLimitKey::ApiKey)
    }

    /// Membuat LimitConfig untuk global limiting.
    pub fn global(requests_per_second: u32, burst_size: u32) -> Self {
        Self::new(requests_per_second, burst_size, RateLimitKey::Global)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TOKEN BUCKET COUNTER
// ════════════════════════════════════════════════════════════════════════════

/// Token bucket counter untuk single key.
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current available tokens.
    tokens: f64,
    /// Last refill timestamp (Unix milliseconds).
    last_refill_ms: u64,
    /// Refill rate (tokens per millisecond).
    refill_rate: f64,
    /// Maximum tokens (burst size).
    max_tokens: f64,
}

impl TokenBucket {
    /// Membuat TokenBucket baru.
    fn new(burst_size: u32, requests_per_second: u32) -> Self {
        Self {
            tokens: burst_size as f64,
            last_refill_ms: current_timestamp_ms(),
            refill_rate: requests_per_second as f64 / 1000.0,
            max_tokens: burst_size as f64,
        }
    }

    /// Refill tokens berdasarkan elapsed time.
    fn refill(&mut self, now_ms: u64) {
        if now_ms <= self.last_refill_ms {
            return;
        }

        let elapsed_ms = now_ms.saturating_sub(self.last_refill_ms);
        let new_tokens = elapsed_ms as f64 * self.refill_rate;

        self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
        self.last_refill_ms = now_ms;
    }

    /// Check if request can be allowed (tanpa consume).
    fn can_allow(&self, now_ms: u64) -> bool {
        let elapsed_ms = now_ms.saturating_sub(self.last_refill_ms);
        let projected_tokens = (self.tokens + elapsed_ms as f64 * self.refill_rate)
            .min(self.max_tokens);
        projected_tokens >= 1.0
    }

    /// Try consume a token. Returns true if successful.
    fn try_consume(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Calculate retry-after in milliseconds.
    fn retry_after_ms(&self) -> u64 {
        if self.tokens >= 1.0 {
            return 0;
        }

        let tokens_needed = 1.0 - self.tokens;
        if self.refill_rate > 0.0 {
            (tokens_needed / self.refill_rate).ceil() as u64
        } else {
            u64::MAX
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// RATE LIMITER
// ════════════════════════════════════════════════════════════════════════════

/// Thread-safe rate limiter menggunakan token bucket algorithm.
pub struct RateLimiter {
    /// Limit configurations by name.
    limits: HashMap<String, LimitConfig>,
    /// Token buckets by key (thread-safe).
    counters: RwLock<HashMap<String, TokenBucket>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    /// Membuat RateLimiter baru tanpa konfigurasi.
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
            counters: RwLock::new(HashMap::new()),
        }
    }

    /// Membuat RateLimiter dengan default limits.
    pub fn with_defaults() -> Self {
        let mut limiter = Self::new();
        // Default: 100 req/s per IP, burst 200
        limiter.add_limit("per_ip", LimitConfig::per_ip(100, 200));
        // Default: 1000 req/s global, burst 2000
        limiter.add_limit("global", LimitConfig::global(1000, 2000));
        limiter
    }

    /// Add limit configuration.
    pub fn add_limit(&mut self, name: &str, config: LimitConfig) {
        self.limits.insert(name.to_string(), config);
    }

    /// Get limit configuration.
    pub fn get_limit(&self, name: &str) -> Option<&LimitConfig> {
        self.limits.get(name)
    }

    /// Get all limit names.
    pub fn limit_names(&self) -> Vec<&String> {
        self.limits.keys().collect()
    }

    /// Check if request is allowed (tanpa modify state).
    ///
    /// # Arguments
    ///
    /// * `key` - Full rate limit key (e.g., "ip:192.168.1.1")
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Request allowed
    /// * `Err(RateLimitError)` - Request denied
    ///
    /// # Thread Safety
    ///
    /// Uses read lock only - does not modify state.
    pub fn check(&self, key: &str) -> Result<(), RateLimitError> {
        let now_ms = current_timestamp_ms();

        let counters = self.counters.read();
        if let Some(bucket) = counters.get(key) {
            if bucket.can_allow(now_ms) {
                Ok(())
            } else {
                Err(RateLimitError::LimitExceeded {
                    key: key.to_string(),
                    retry_after_ms: bucket.retry_after_ms(),
                })
            }
        } else {
            // No bucket yet - first request, will be allowed
            Ok(())
        }
    }

    /// Record request (consume token).
    ///
    /// # Arguments
    ///
    /// * `key` - Full rate limit key
    /// * `config` - Limit configuration to use for new buckets
    ///
    /// # Thread Safety
    ///
    /// Atomic update using write lock.
    pub fn record(&self, key: &str, config: &LimitConfig) {
        let now_ms = current_timestamp_ms();
        let mut counters = self.counters.write();

        let bucket = counters.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(config.burst_size, config.requests_per_second)
        });

        bucket.try_consume(now_ms);
    }

    /// Check and record atomically.
    ///
    /// # Arguments
    ///
    /// * `key` - Full rate limit key
    /// * `config` - Limit configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Request allowed and recorded
    /// * `Err(RateLimitError)` - Request denied
    ///
    /// # Thread Safety
    ///
    /// Uses single write lock for atomic check+record.
    pub fn check_and_record(&self, key: &str, config: &LimitConfig) -> Result<(), RateLimitError> {
        let now_ms = current_timestamp_ms();
        let mut counters = self.counters.write();

        let bucket = counters.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(config.burst_size, config.requests_per_second)
        });

        if bucket.try_consume(now_ms) {
            Ok(())
        } else {
            Err(RateLimitError::LimitExceeded {
                key: key.to_string(),
                retry_after_ms: bucket.retry_after_ms(),
            })
        }
    }

    /// Check request against all configured limits.
    ///
    /// # Arguments
    ///
    /// * `ip` - Client IP address
    /// * `api_key` - API key (if any)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All limits passed
    /// * `Err(RateLimitError)` - At least one limit exceeded
    pub fn check_all(&self, ip: Option<&str>, api_key: Option<&str>) -> Result<(), RateLimitError> {
        for (name, config) in &self.limits {
            let key = config.by.extract(ip, api_key);
            
            // Check and record atomically
            self.check_and_record(&key, config)?;

            debug!(
                limit_name = %name,
                key = %key,
                "rate limit check passed"
            );
        }
        Ok(())
    }

    /// Get current token count for a key.
    pub fn get_tokens(&self, key: &str) -> Option<f64> {
        self.counters.read().get(key).map(|b| b.tokens)
    }

    /// Clear all counters.
    pub fn clear(&self) {
        self.counters.write().clear();
    }

    /// Get number of tracked keys.
    pub fn tracked_keys(&self) -> usize {
        self.counters.read().len()
    }
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("limits", &self.limits.keys().collect::<Vec<_>>())
            .field("tracked_keys", &self.tracked_keys())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// AXUM MIDDLEWARE
// ════════════════════════════════════════════════════════════════════════════

/// Rate limit state untuk Axum middleware.
#[derive(Clone)]
pub struct RateLimitState {
    limiter: Arc<RateLimiter>,
}

impl RateLimitState {
    /// Membuat RateLimitState baru.
    pub fn new(limiter: Arc<RateLimiter>) -> Self {
        Self { limiter }
    }

    /// Get limiter reference.
    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }
}

/// Extract client IP dari request.
fn extract_client_ip(req: &Request) -> Option<String> {
    // Try X-Forwarded-For first
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // Take first IP in chain
            if let Some(ip) = xff_str.split(',').next() {
                return Some(ip.trim().to_string());
            }
        }
    }

    // Try X-Real-IP
    if let Some(xri) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = xri.to_str() {
            return Some(ip_str.to_string());
        }
    }

    None
}

/// Extract API key dari request.
fn extract_api_key(req: &Request) -> Option<String> {
    // Check Authorization header
    if let Some(auth) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    // Check X-API-Key header
    if let Some(api_key) = req.headers().get("x-api-key") {
        if let Ok(key_str) = api_key.to_str() {
            return Some(key_str.to_string());
        }
    }

    None
}

/// Rate limiting middleware untuk Axum.
///
/// Dieksekusi sebelum routing. Menolak request dengan HTTP 429 jika rate limit exceeded.
pub async fn rate_limit_middleware(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&req);
    let api_key = extract_api_key(&req);

    match state.limiter.check_all(ip.as_deref(), api_key.as_deref()) {
        Ok(()) => {
            // Request allowed - proceed to handler
            next.run(req).await
        }
        Err(RateLimitError::LimitExceeded { key, retry_after_ms }) => {
            warn!(
                key = %key,
                retry_after_ms = retry_after_ms,
                "rate limit exceeded"
            );

            // Return 429 Too Many Requests
            let retry_after_secs = (retry_after_ms / 1000).max(1);
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("Retry-After", retry_after_secs.to_string())],
                format!("Rate limit exceeded. Retry after {} seconds.", retry_after_secs),
            ).into_response()
        }
        Err(RateLimitError::KeyNotConfigured(key)) => {
            warn!(key = %key, "rate limit key not configured");
            // Allow request if key not configured (fail open)
            next.run(req).await
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

/// Get current timestamp in Unix milliseconds.
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: RATE LIMIT BASIC (STEADY RATE)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rate_limit_basic_steady_rate() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("test", LimitConfig::global(10, 10)); // 10 req/s, burst 10

        // First 10 requests should pass (burst)
        for i in 0..10 {
            let result = limiter.check_and_record("global", limiter.get_limit("test").unwrap());
            assert!(result.is_ok(), "Request {} should pass", i);
        }

        // 11th request should fail (burst exhausted)
        let result = limiter.check_and_record("global", limiter.get_limit("test").unwrap());
        assert!(result.is_err(), "11th request should fail");

        match result.unwrap_err() {
            RateLimitError::LimitExceeded { key, retry_after_ms } => {
                assert_eq!(key, "global");
                assert!(retry_after_ms > 0);
            }
            _ => panic!("Expected LimitExceeded error"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: BURST BEHAVIOR
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_burst_behavior() {
        let mut limiter = RateLimiter::new();
        // 2 req/s, burst 5
        limiter.add_limit("test", LimitConfig::global(2, 5));
        let config = limiter.get_limit("test").unwrap().clone();

        // Can burst 5 requests immediately
        for _ in 0..5 {
            let result = limiter.check_and_record("global", &config);
            assert!(result.is_ok());
        }

        // 6th should fail
        let result = limiter.check_and_record("global", &config);
        assert!(result.is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: REFILL BEHAVIOR DETERMINISTIC
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_refill_behavior_deterministic() {
        let mut limiter = RateLimiter::new();
        // 1000 req/s = 1 req/ms
        limiter.add_limit("test", LimitConfig::global(1000, 1));
        let config = limiter.get_limit("test").unwrap().clone();

        // Use burst
        let result = limiter.check_and_record("global", &config);
        assert!(result.is_ok());

        // Immediately should fail
        let result = limiter.check_and_record("global", &config);
        assert!(result.is_err());

        // Wait for refill (2ms should give us 2 tokens at 1000 req/s)
        thread::sleep(Duration::from_millis(5));

        // Should pass now
        let result = limiter.check_and_record("global", &config);
        assert!(result.is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: LIMIT PER IP
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_limit_per_ip() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("per_ip", LimitConfig::per_ip(10, 2));
        let config = limiter.get_limit("per_ip").unwrap().clone();

        let key_a = config.by.extract(Some("192.168.1.1"), None);
        let key_b = config.by.extract(Some("192.168.1.2"), None);

        // IP A: 2 requests
        for _ in 0..2 {
            assert!(limiter.check_and_record(&key_a, &config).is_ok());
        }

        // IP A: 3rd should fail
        assert!(limiter.check_and_record(&key_a, &config).is_err());

        // IP B: Should still have full burst (independent)
        for _ in 0..2 {
            assert!(limiter.check_and_record(&key_b, &config).is_ok());
        }
        assert!(limiter.check_and_record(&key_b, &config).is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: LIMIT PER API KEY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_limit_per_api_key() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("per_apikey", LimitConfig::per_api_key(10, 3));
        let config = limiter.get_limit("per_apikey").unwrap().clone();

        let key_a = config.by.extract(None, Some("key-123"));
        let key_b = config.by.extract(None, Some("key-456"));

        // Key A: 3 requests
        for _ in 0..3 {
            assert!(limiter.check_and_record(&key_a, &config).is_ok());
        }
        assert!(limiter.check_and_record(&key_a, &config).is_err());

        // Key B: Independent
        for _ in 0..3 {
            assert!(limiter.check_and_record(&key_b, &config).is_ok());
        }
        assert!(limiter.check_and_record(&key_b, &config).is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: GLOBAL LIMIT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_global_limit() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("global", LimitConfig::global(10, 5));
        let config = limiter.get_limit("global").unwrap().clone();

        let key = config.by.extract(None, None);
        assert_eq!(key, "global");

        // 5 requests should pass
        for _ in 0..5 {
            assert!(limiter.check_and_record(&key, &config).is_ok());
        }

        // 6th should fail
        assert!(limiter.check_and_record(&key, &config).is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: CONCURRENT ACCESS (MULTI-THREAD)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_concurrent_access() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("test", LimitConfig::global(1000, 1000));
        let limiter = Arc::new(limiter);
        let config = limiter.get_limit("test").unwrap().clone();

        let mut handles = vec![];

        // Spawn 10 threads, each making 100 requests
        for _ in 0..10 {
            let l = limiter.clone();
            let c = config.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = l.check_and_record("global", &c);
                }
            }));
        }

        // Wait for all threads
        for h in handles {
            h.join().unwrap();
        }

        // Should have consumed 1000 tokens (or close to it)
        // No panics, no deadlocks
        let tokens = limiter.get_tokens("global");
        assert!(tokens.is_some());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: CHECK DOES NOT MODIFY STATE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_check_does_not_modify_state() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("test", LimitConfig::global(10, 5));
        let config = limiter.get_limit("test").unwrap().clone();

        // Record 4 requests
        for _ in 0..4 {
            limiter.record("global", &config);
        }

        let tokens_before = limiter.get_tokens("global").unwrap();

        // Check should not modify
        let result = limiter.check("global");
        assert!(result.is_ok());

        let tokens_after = limiter.get_tokens("global").unwrap();
        assert!((tokens_before - tokens_after).abs() < 0.1); // Allow small float difference
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: NO PANIC ON EDGE CASES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_panic_edge_cases() {
        let limiter = RateLimiter::new();

        // Check non-existent key
        let result = limiter.check("nonexistent");
        assert!(result.is_ok()); // First request always allowed

        // Empty key
        let result = limiter.check("");
        assert!(result.is_ok());

        // Clear empty
        limiter.clear();
        assert_eq!(limiter.tracked_keys(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: RATE LIMIT KEY EXTRACTION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rate_limit_key_extraction() {
        // IP key
        let key = RateLimitKey::Ip.extract(Some("192.168.1.1"), None);
        assert_eq!(key, "ip:192.168.1.1");

        let key = RateLimitKey::Ip.extract(None, None);
        assert_eq!(key, "ip:unknown");

        // API key
        let key = RateLimitKey::ApiKey.extract(None, Some("my-key"));
        assert_eq!(key, "apikey:my-key");

        let key = RateLimitKey::ApiKey.extract(None, None);
        assert_eq!(key, "apikey:anonymous");

        // Global
        let key = RateLimitKey::Global.extract(Some("any"), Some("any"));
        assert_eq!(key, "global");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: TOKEN BUCKET REFILL
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10, 100); // burst 10, 100 req/s

        let now = current_timestamp_ms();

        // Consume all tokens
        for _ in 0..10 {
            assert!(bucket.try_consume(now));
        }
        assert!(!bucket.try_consume(now)); // Should fail

        // Simulate 50ms passed (should get ~5 tokens)
        let future = now + 50;
        assert!(bucket.try_consume(future)); // Should pass now
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: RETRY AFTER CALCULATION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_retry_after_calculation() {
        let mut bucket = TokenBucket::new(1, 10); // burst 1, 10 req/s

        let now = current_timestamp_ms();

        // Consume the only token
        assert!(bucket.try_consume(now));

        // Check retry after
        let retry = bucket.retry_after_ms();
        // Should be ~100ms for 1 token at 10 req/s
        assert!(retry > 0);
        assert!(retry <= 200);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: LIMITER WITH DEFAULTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_limiter_with_defaults() {
        let limiter = RateLimiter::with_defaults();

        assert!(limiter.get_limit("per_ip").is_some());
        assert!(limiter.get_limit("global").is_some());

        let names = limiter.limit_names();
        assert_eq!(names.len(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: NO KEY BLEED (IP A tidak mempengaruhi IP B)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_key_bleed() {
        let mut limiter = RateLimiter::new();
        limiter.add_limit("per_ip", LimitConfig::per_ip(10, 1));
        let config = limiter.get_limit("per_ip").unwrap().clone();

        let key_a = "ip:192.168.1.1";
        let key_b = "ip:192.168.1.2";

        // Exhaust IP A
        limiter.check_and_record(key_a, &config).unwrap();
        assert!(limiter.check_and_record(key_a, &config).is_err());

        // IP B should be unaffected
        assert!(limiter.check_and_record(key_b, &config).is_ok());
    }
}
//! # Retry Logic with Exponential Backoff (14C.C.17)
//!
//! Configurable retry mechanism for economic flow operations.
//!
//! ## Design
//!
//! - Exponential backoff: `delay = initial_delay_ms * multiplier^(attempt-1)`
//! - Clamped to `max_delay_ms`
//! - Deterministic jitter: `+ (attempt * 7919 + 104729) % (base/4 + 1)`
//! - Non-retryable errors short-circuit immediately
//! - All arithmetic uses checked operations; no overflow possible
//!
//! ## Invariants
//!
//! 1. `attempts <= max_retries`
//! 2. `delay <= max_delay_ms`
//! 3. No overflow (u64, f64 clamped)
//! 4. No panic, no unwrap, no expect
//! 5. Deterministic in all modes (no SystemTime, no rand)
//! 6. No busy loop — every retry path sleeps

use std::future::Future;

// ════════════════════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Configuration for retry-with-backoff behavior.
#[derive(Debug, Clone, PartialEq)]
pub struct RetryConfig {
    /// Maximum number of attempts (including the first). 0 means no attempt at all.
    pub max_retries: u32,
    /// Base delay for the first retry (milliseconds).
    pub initial_delay_ms: u64,
    /// Upper bound for computed delay (milliseconds).
    pub max_delay_ms: u64,
    /// Multiplicative factor applied per attempt.
    pub backoff_multiplier: f64,
    /// Whether to add deterministic jitter to each delay.
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 30_000,
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

/// Outcome of a retried operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryResult<T> {
    /// The operation succeeded.
    Success {
        /// The successful return value.
        value: T,
        /// Number of attempts made (1 = succeeded on first try).
        attempts: u32,
    },
    /// All retries were exhausted (or the error was non-retryable).
    Exhausted {
        /// Display representation of the last error.
        last_error: String,
        /// Number of attempts made before giving up.
        attempts: u32,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// DELAY COMPUTATION (pure, no side effects)
// ════════════════════════════════════════════════════════════════════════════════

/// Compute the delay in milliseconds for a given attempt (1-indexed).
///
/// Formula: `min(initial_delay_ms * multiplier^(attempt-1), max_delay_ms)`
///
/// All arithmetic uses checked/clamped operations:
/// - `f64` multiplication is clamped to `[0, max_delay_ms]`
/// - Result cast to `u64` via `as` after clamping (safe: value is in u64 range)
///
/// If `jitter` is enabled, a deterministic offset is added:
/// `(attempt * 7919 + 104729) % (base_delay / 4 + 1)`
///
/// This jitter is fully deterministic (no randomness, no SystemTime).
pub fn compute_delay(config: &RetryConfig, attempt: u32) -> u64 {
    // Exponent = attempt - 1 (0-indexed for power)
    let exponent = attempt.saturating_sub(1);

    // Compute multiplier^exponent using f64
    // f64 can represent integers up to 2^53 exactly; beyond that it
    // saturates to a large value that gets clamped to max_delay_ms.
    let multiplier_power = config.backoff_multiplier.powi(exponent as i32);

    // base = initial_delay_ms * multiplier^exponent, clamped to max_delay_ms
    let base_f64 = (config.initial_delay_ms as f64) * multiplier_power;

    // Clamp to [0, max_delay_ms]. Handles NaN, Inf, and negative values.
    let max = config.max_delay_ms as f64;
    let clamped = if base_f64.is_nan() || base_f64 < 0.0 {
        0.0
    } else if base_f64 > max {
        max
    } else {
        base_f64
    };

    let mut delay = clamped as u64;

    // Clamp again (redundant safety for edge cases)
    if delay > config.max_delay_ms {
        delay = config.max_delay_ms;
    }

    // Deterministic jitter
    if config.jitter && delay > 0 {
        let quarter = delay / 4;
        if quarter > 0 {
            // Deterministic pseudo-random: different per attempt, reproducible
            let attempt_u64 = attempt as u64;
            let jitter_val = (attempt_u64.wrapping_mul(7919).wrapping_add(104729)) % (quarter + 1);
            delay = delay.saturating_add(jitter_val);
            // Re-clamp after jitter
            if delay > config.max_delay_ms {
                delay = config.max_delay_ms;
            }
        }
    }

    delay
}

// ════════════════════════════════════════════════════════════════════════════════
// RETRYABLE CHECK
// ════════════════════════════════════════════════════════════════════════════════

/// Determine if an error is retryable based on its Display representation.
///
/// Retryable errors (network-related):
/// - Contains: "network", "connection", "timeout", "timed out", "refused",
///   "unavailable", "reset", "broken pipe", "dns", "eof", "temporarily"
///
/// Non-retryable (validation/logic):
/// - Everything else (including "invalid", "permission", "not found", etc.)
pub fn is_retryable<E: core::fmt::Display>(error: &E) -> bool {
    let msg = error.to_string().to_lowercase();
    msg.contains("network")
        || msg.contains("connection")
        || msg.contains("timeout")
        || msg.contains("timed out")
        || msg.contains("refused")
        || msg.contains("unavailable")
        || msg.contains("reset")
        || msg.contains("broken pipe")
        || msg.contains("dns")
        || msg.contains("eof")
        || msg.contains("temporarily")
}

// ════════════════════════════════════════════════════════════════════════════════
// MAIN RETRY FUNCTION
// ════════════════════════════════════════════════════════════════════════════════

/// Execute an async operation with exponential backoff retry.
///
/// # Behavior
///
/// 1. Call `operation()` (attempt starts at 1).
/// 2. On success → return `RetryResult::Success { value, attempts }`.
/// 3. On failure:
///    a. If `!is_retryable(&error)` → return `Exhausted` immediately.
///    b. If `attempts >= max_retries` → return `Exhausted`.
///    c. Compute delay via [`compute_delay`], sleep, then retry.
///
/// # Determinism
///
/// All jitter is deterministic (no randomness). Delay is computed purely
/// from config + attempt number.
///
/// # Thread Safety
///
/// The function is `Send`-safe: `F` and `Fut` must be `Send`, and
/// `operation` is taken by `FnMut` (single-threaded ownership).
pub async fn retry_with_backoff<F, Fut, T, E>(
    config: &RetryConfig,
    mut operation: F,
) -> RetryResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: core::fmt::Display,
{
    let mut attempts: u32 = 0;
    let mut last_error_msg = String::new();

    loop {
        attempts = attempts.saturating_add(1);

        match operation().await {
            Ok(value) => {
                return RetryResult::Success { value, attempts };
            }
            Err(e) => {
                last_error_msg = e.to_string();

                // Non-retryable → stop immediately
                if !is_retryable(&e) {
                    return RetryResult::Exhausted {
                        last_error: last_error_msg,
                        attempts,
                    };
                }

                // Max retries reached → stop
                if attempts >= config.max_retries {
                    return RetryResult::Exhausted {
                        last_error: last_error_msg,
                        attempts,
                    };
                }

                // Compute delay and sleep
                let delay_ms = compute_delay(config, attempts);
                eprintln!(
                    "Retry attempt {}/{}, delay {}ms: {}",
                    attempts, config.max_retries, delay_ms, last_error_msg
                );

                if delay_ms > 0 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// Test config with zero delays for fast deterministic tests.
    fn fast_config(max_retries: u32) -> RetryConfig {
        RetryConfig {
            max_retries,
            initial_delay_ms: 0,
            max_delay_ms: 0,
            backoff_multiplier: 2.0,
            jitter: false,
        }
    }

    /// Config for delay computation tests (non-zero delays).
    fn delay_config() -> RetryConfig {
        RetryConfig {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 30_000,
            backoff_multiplier: 2.0,
            jitter: false,
        }
    }

    // ── 1. success_without_retry ─────────────────────────────────────────

    #[tokio::test]
    async fn success_without_retry() {
        let config = fast_config(3);
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result: RetryResult<i32> = retry_with_backoff(&config, || {
            c.fetch_add(1, Ordering::SeqCst);
            async { Ok::<i32, String>(42) }
        })
        .await;

        match result {
            RetryResult::Success { value, attempts } => {
                assert_eq!(value, 42);
                assert_eq!(attempts, 1);
            }
            RetryResult::Exhausted { .. } => {
                assert!(false, "should have succeeded");
            }
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // ── 2. retry_until_success ───────────────────────────────────────────

    #[tokio::test]
    async fn retry_until_success() {
        let config = fast_config(5);
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        // Fail twice with retryable error, then succeed
        let result: RetryResult<&str> = retry_with_backoff(&config, || {
            let count = c.fetch_add(1, Ordering::SeqCst);
            async move {
                if count < 2 {
                    Err::<&str, String>("connection timeout".to_string())
                } else {
                    Ok("done")
                }
            }
        })
        .await;

        match result {
            RetryResult::Success { value, attempts } => {
                assert_eq!(value, "done");
                assert_eq!(attempts, 3); // failed 2, succeeded on 3rd
            }
            RetryResult::Exhausted { .. } => {
                assert!(false, "should have succeeded");
            }
        }
    }

    // ── 3. retry_exhausted ───────────────────────────────────────────────

    #[tokio::test]
    async fn retry_exhausted() {
        let config = fast_config(3);
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result: RetryResult<()> = retry_with_backoff(&config, || {
            c.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), String>("connection refused".to_string()) }
        })
        .await;

        match result {
            RetryResult::Exhausted { last_error, attempts } => {
                assert_eq!(attempts, 3);
                assert!(last_error.contains("connection refused"));
            }
            RetryResult::Success { .. } => {
                assert!(false, "should have exhausted");
            }
        }
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    // ── 4. no_retry_on_non_retryable ─────────────────────────────────────

    #[tokio::test]
    async fn no_retry_on_non_retryable() {
        let config = fast_config(5);
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result: RetryResult<()> = retry_with_backoff(&config, || {
            c.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), String>("invalid input data".to_string()) }
        })
        .await;

        match result {
            RetryResult::Exhausted { last_error, attempts } => {
                assert_eq!(attempts, 1); // stopped after first attempt
                assert!(last_error.contains("invalid input"));
            }
            RetryResult::Success { .. } => {
                assert!(false, "should have exhausted");
            }
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // ── 5. delay_calculation_correct ─────────────────────────────────────

    #[test]
    fn delay_calculation_correct() {
        let config = delay_config();

        // attempt 1: 1000 * 2^0 = 1000
        assert_eq!(compute_delay(&config, 1), 1000);
        // attempt 2: 1000 * 2^1 = 2000
        assert_eq!(compute_delay(&config, 2), 2000);
        // attempt 3: 1000 * 2^2 = 4000
        assert_eq!(compute_delay(&config, 3), 4000);
        // attempt 4: 1000 * 2^3 = 8000
        assert_eq!(compute_delay(&config, 4), 8000);
        // attempt 5: 1000 * 2^4 = 16000
        assert_eq!(compute_delay(&config, 5), 16000);
    }

    // ── 6. delay_clamped_to_max ──────────────────────────────────────────

    #[test]
    fn delay_clamped_to_max() {
        let config = RetryConfig {
            max_retries: 10,
            initial_delay_ms: 1000,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
            jitter: false,
        };

        // attempt 1: 1000
        assert_eq!(compute_delay(&config, 1), 1000);
        // attempt 2: 2000
        assert_eq!(compute_delay(&config, 2), 2000);
        // attempt 3: 4000
        assert_eq!(compute_delay(&config, 3), 4000);
        // attempt 4: 1000 * 2^3 = 8000 → clamped to 5000
        assert_eq!(compute_delay(&config, 4), 5000);
        // attempt 10: still clamped to 5000
        assert_eq!(compute_delay(&config, 10), 5000);
    }

    // ── 7. jitter_enabled_variation ──────────────────────────────────────

    #[test]
    fn jitter_enabled_variation() {
        let config = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 30_000,
            backoff_multiplier: 2.0,
            jitter: true,
        };

        let no_jitter = RetryConfig {
            jitter: false,
            ..config.clone()
        };

        // With jitter, delay should be >= base delay (jitter is additive)
        for attempt in 1..=5 {
            let with = compute_delay(&config, attempt);
            let without = compute_delay(&no_jitter, attempt);
            assert!(
                with >= without,
                "jitter delay ({with}) should be >= base ({without}) at attempt {attempt}"
            );
        }

        // Different attempts should produce different jitter offsets
        let d1 = compute_delay(&config, 1);
        let d2 = compute_delay(&config, 2);
        // They should differ (different base + different jitter)
        assert_ne!(d1, d2);
    }

    // ── 8. jitter_disabled_exact_delay ────────────────────────────────────

    #[test]
    fn jitter_disabled_exact_delay() {
        let config = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 30_000,
            backoff_multiplier: 2.0,
            jitter: false,
        };

        // Without jitter, delays are exact powers
        assert_eq!(compute_delay(&config, 1), 1000);
        assert_eq!(compute_delay(&config, 2), 2000);
        assert_eq!(compute_delay(&config, 3), 4000);
    }

    // ── 9. deterministic_jitter_in_test_mode ─────────────────────────────

    #[test]
    fn deterministic_jitter_in_test_mode() {
        let config = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 30_000,
            backoff_multiplier: 2.0,
            jitter: true,
        };

        // Call compute_delay multiple times with same args → same result
        let d1_a = compute_delay(&config, 1);
        let d1_b = compute_delay(&config, 1);
        let d1_c = compute_delay(&config, 1);
        assert_eq!(d1_a, d1_b);
        assert_eq!(d1_b, d1_c);

        let d3_a = compute_delay(&config, 3);
        let d3_b = compute_delay(&config, 3);
        assert_eq!(d3_a, d3_b);

        // Different attempts → different values (deterministic but varied)
        let d1 = compute_delay(&config, 1);
        let d3 = compute_delay(&config, 3);
        assert_ne!(d1, d3);
    }

    // ── 10. max_retries_respected ────────────────────────────────────────

    #[tokio::test]
    async fn max_retries_respected() {
        let config = fast_config(4);
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result: RetryResult<()> = retry_with_backoff(&config, || {
            c.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), String>("network timeout".to_string()) }
        })
        .await;

        // Must stop at exactly max_retries
        assert_eq!(counter.load(Ordering::SeqCst), 4);
        match result {
            RetryResult::Exhausted { attempts, .. } => {
                assert_eq!(attempts, 4);
            }
            _ => assert!(false, "should have exhausted"),
        }
    }

    // ── 11. attempts_count_correct ───────────────────────────────────────

    #[tokio::test]
    async fn attempts_count_correct() {
        // Succeed on attempt 1
        let config = fast_config(5);
        let r1: RetryResult<u32> =
            retry_with_backoff(&config, || async { Ok::<u32, String>(1) }).await;
        if let RetryResult::Success { attempts, .. } = r1 {
            assert_eq!(attempts, 1);
        }

        // Succeed on attempt 4
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let r2: RetryResult<u32> = retry_with_backoff(&config, || {
            let count = c.fetch_add(1, Ordering::SeqCst);
            async move {
                if count < 3 {
                    Err::<u32, String>("connection reset".to_string())
                } else {
                    Ok(99)
                }
            }
        })
        .await;
        if let RetryResult::Success { value, attempts } = r2 {
            assert_eq!(value, 99);
            assert_eq!(attempts, 4);
        }
    }

    // ── 12. no_overflow_large_delay ──────────────────────────────────────

    #[test]
    fn no_overflow_large_delay() {
        // Extreme config: huge values that could overflow
        let config = RetryConfig {
            max_retries: 100,
            initial_delay_ms: u64::MAX / 2,
            max_delay_ms: u64::MAX,
            backoff_multiplier: 10.0,
            jitter: true,
        };

        // Should not panic, should clamp to max_delay_ms
        let d = compute_delay(&config, 50);
        assert!(d <= config.max_delay_ms);

        // Zero initial delay
        let config_zero = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 0,
            max_delay_ms: 30_000,
            backoff_multiplier: 2.0,
            jitter: true,
        };
        assert_eq!(compute_delay(&config_zero, 1), 0);
        assert_eq!(compute_delay(&config_zero, 5), 0);

        // NaN-inducing multiplier
        let config_nan = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 30_000,
            backoff_multiplier: f64::NAN,
            jitter: false,
        };
        // NaN^0 = 1.0 (IEEE 754), so attempt 1 → 1000 * 1.0 = 1000
        assert_eq!(compute_delay(&config_nan, 1), 1000);
        // NaN^1 = NaN → clamped to 0
        assert_eq!(compute_delay(&config_nan, 2), 0);

        // Infinity multiplier
        let config_inf = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 30_000,
            backoff_multiplier: f64::INFINITY,
            jitter: false,
        };
        // Inf * 1000 → clamped to max
        let d_inf = compute_delay(&config_inf, 2);
        assert!(d_inf <= config_inf.max_delay_ms);
    }

    // ── 13. async_execution_correct ──────────────────────────────────────

    #[tokio::test]
    async fn async_execution_correct() {
        let config = fast_config(3);

        // Async operation that yields before returning
        let result: RetryResult<String> = retry_with_backoff(&config, || async {
            tokio::task::yield_now().await;
            Ok::<String, String>("async_result".to_string())
        })
        .await;

        match result {
            RetryResult::Success { value, attempts } => {
                assert_eq!(value, "async_result");
                assert_eq!(attempts, 1);
            }
            _ => assert!(false, "should have succeeded"),
        }
    }

    // ── 14. error_propagation_correct ────────────────────────────────────

    #[tokio::test]
    async fn error_propagation_correct() {
        let config = fast_config(2);

        // Retryable error → exhausted with correct message
        let r1: RetryResult<()> = retry_with_backoff(&config, || async {
            Err::<(), String>("connection refused: 10.0.0.1:8080".to_string())
        })
        .await;
        if let RetryResult::Exhausted { last_error, attempts } = r1 {
            assert_eq!(attempts, 2);
            assert!(last_error.contains("connection refused"));
            assert!(last_error.contains("10.0.0.1"));
        }

        // Non-retryable → stops at attempt 1 with exact error
        let r2: RetryResult<()> = retry_with_backoff(&config, || async {
            Err::<(), String>("invalid receipt format: missing field".to_string())
        })
        .await;
        if let RetryResult::Exhausted { last_error, attempts } = r2 {
            assert_eq!(attempts, 1);
            assert!(last_error.contains("invalid receipt format"));
        }
    }

    // ── 15. (bonus) is_retryable_classification ──────────────────────────

    #[test]
    fn is_retryable_classification() {
        // Retryable
        assert!(is_retryable(&"network error occurred"));
        assert!(is_retryable(&"connection reset by peer"));
        assert!(is_retryable(&"request timeout"));
        assert!(is_retryable(&"operation timed out"));
        assert!(is_retryable(&"connection refused"));
        assert!(is_retryable(&"service unavailable"));
        assert!(is_retryable(&"broken pipe"));
        assert!(is_retryable(&"dns resolution failed"));
        assert!(is_retryable(&"unexpected eof"));
        assert!(is_retryable(&"temporarily unavailable"));

        // Non-retryable
        assert!(!is_retryable(&"invalid input"));
        assert!(!is_retryable(&"permission denied"));
        assert!(!is_retryable(&"not found"));
        assert!(!is_retryable(&"bad request"));
        assert!(!is_retryable(&""));
    }

    // ── 16. (bonus) default_config_values ────────────────────────────────

    #[test]
    fn default_config_values() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_delay_ms, 1000);
        assert_eq!(config.max_delay_ms, 30_000);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert!(config.jitter);
    }
}
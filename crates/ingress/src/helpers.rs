use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::da_router::DEFAULT_CACHE_TTL_MS;

// ════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

/// Get current timestamp in Unix milliseconds.
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Simple config via env
pub fn coordinator_base_from_env() -> String {
    env::var("COORDINATOR_BASE").unwrap_or_else(|_| "http://127.0.0.1:45831".to_string())
}

/// DA router TTL config via env (default 30 seconds)
pub fn da_router_ttl_from_env() -> u64 {
    env::var("DA_ROUTER_TTL_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_CACHE_TTL_MS)
}
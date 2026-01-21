//! Node Fallback Metrics Module (14A.1A.49)
//!
//! Provides lock-free, thread-safe metrics tracking for fallback operations.
//!
//! ## Design Principles
//!
//! - **Lock-free**: All operations use atomic primitives only
//! - **Thread-safe**: All fields are AtomicU64, struct is Send + Sync
//! - **Deterministic**: Same inputs produce same outputs
//! - **Prometheus-compatible**: `to_prometheus()` outputs valid exposition format
//!
//! ## Metrics Tracked
//!
//! | Metric | Description |
//! |--------|-------------|
//! | source_switches | Number of DA source transitions |
//! | events_from_primary | Events processed from primary DA |
//! | events_from_fallback | Events processed from fallback DA |
//! | fallback_duration_total_secs | Total time spent in fallback mode |
//! | transition_failures | Number of failed source transitions |
//!
//! ## Thread Safety Guarantee
//!
//! - No mutex or RwLock used
//! - All fields are AtomicU64
//! - Send + Sync auto-derived from AtomicU64 (which is Send + Sync)
//!
//! ## Usage
//!
//! ```ignore
//! use dsdn_node::metrics::NodeFallbackMetrics;
//!
//! let metrics = NodeFallbackMetrics::new();
//! metrics.record_source_switch();
//! metrics.record_event_from_primary();
//! println!("{}", metrics.to_prometheus());
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

// ════════════════════════════════════════════════════════════════════════════════
// NODE FALLBACK METRICS
// ════════════════════════════════════════════════════════════════════════════════

/// Metrics for fallback operations on a DSDN storage node.
///
/// All fields are atomic for lock-free, thread-safe access.
/// This struct is guaranteed Send + Sync by construction (AtomicU64 is Send + Sync).
///
/// ## Memory Ordering
///
/// - Increments use `Ordering::Relaxed` (sufficient for monotonic counters)
/// - Reads in `to_prometheus()` use `Ordering::SeqCst` for snapshot consistency
///
/// ## Overflow Handling
///
/// All increment operations use `fetch_add` with wrapping semantics.
/// At 2^64 events, overflow is not a practical concern for counters.
///
/// ## No Hidden State
///
/// - No mutex
/// - No RwLock
/// - No RefCell
/// - No non-atomic shadow state
/// - Only 5 AtomicU64 fields
#[derive(Debug)]
pub struct NodeFallbackMetrics {
    /// Number of DA source transitions (primary ↔ fallback).
    ///
    /// Incremented each time the node switches between DA sources.
    pub source_switches: AtomicU64,

    /// Number of events processed from the primary DA source.
    ///
    /// Incremented for each event successfully processed from primary.
    pub events_from_primary: AtomicU64,

    /// Number of events processed from fallback DA sources.
    ///
    /// Incremented for each event successfully processed from secondary/emergency.
    pub events_from_fallback: AtomicU64,

    /// Total duration spent in fallback mode, in seconds.
    ///
    /// Accumulated each time fallback mode is deactivated.
    /// Represents the sum of all fallback periods.
    pub fallback_duration_total_secs: AtomicU64,

    /// Number of failed source transitions.
    ///
    /// Incremented when a transition attempt fails and is rolled back.
    pub transition_failures: AtomicU64,
}

impl NodeFallbackMetrics {
    /// Create a new NodeFallbackMetrics instance with all counters at zero.
    ///
    /// ## Guarantees
    ///
    /// - All fields initialized to 0
    /// - No heap allocation beyond the struct itself
    /// - Never panics
    #[must_use]
    pub fn new() -> Self {
        Self {
            source_switches: AtomicU64::new(0),
            events_from_primary: AtomicU64::new(0),
            events_from_fallback: AtomicU64::new(0),
            fallback_duration_total_secs: AtomicU64::new(0),
            transition_failures: AtomicU64::new(0),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // INCREMENT METHODS (Single)
    // ════════════════════════════════════════════════════════════════════════════

    /// Record a source switch event.
    ///
    /// Call when the node transitions between DA sources.
    ///
    /// ## Thread Safety
    ///
    /// Lock-free, uses atomic fetch_add with Relaxed ordering.
    pub fn record_source_switch(&self) {
        self.source_switches.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an event processed from the primary DA source.
    ///
    /// ## Thread Safety
    ///
    /// Lock-free, uses atomic fetch_add with Relaxed ordering.
    pub fn record_event_from_primary(&self) {
        self.events_from_primary.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an event processed from a fallback DA source.
    ///
    /// ## Thread Safety
    ///
    /// Lock-free, uses atomic fetch_add with Relaxed ordering.
    pub fn record_event_from_fallback(&self) {
        self.events_from_fallback.fetch_add(1, Ordering::Relaxed);
    }

    /// Add duration to the total fallback duration.
    ///
    /// ## Arguments
    ///
    /// * `seconds` - Duration to add in seconds
    ///
    /// ## Thread Safety
    ///
    /// Lock-free, uses atomic fetch_add with Relaxed ordering.
    pub fn add_fallback_duration(&self, seconds: u64) {
        self.fallback_duration_total_secs.fetch_add(seconds, Ordering::Relaxed);
    }

    /// Record a transition failure.
    ///
    /// Call when a source transition fails and is rolled back.
    ///
    /// ## Thread Safety
    ///
    /// Lock-free, uses atomic fetch_add with Relaxed ordering.
    pub fn record_transition_failure(&self) {
        self.transition_failures.fetch_add(1, Ordering::Relaxed);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // INCREMENT METHODS (Bulk)
    // ════════════════════════════════════════════════════════════════════════════

    /// Add multiple events from primary at once.
    ///
    /// ## Arguments
    ///
    /// * `count` - Number of events to add
    ///
    /// ## Thread Safety
    ///
    /// Lock-free, uses atomic fetch_add with Relaxed ordering.
    pub fn add_events_from_primary(&self, count: u64) {
        self.events_from_primary.fetch_add(count, Ordering::Relaxed);
    }

    /// Add multiple events from fallback at once.
    ///
    /// ## Arguments
    ///
    /// * `count` - Number of events to add
    ///
    /// ## Thread Safety
    ///
    /// Lock-free, uses atomic fetch_add with Relaxed ordering.
    pub fn add_events_from_fallback(&self, count: u64) {
        self.events_from_fallback.fetch_add(count, Ordering::Relaxed);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // READ METHODS
    // ════════════════════════════════════════════════════════════════════════════

    /// Get the current count of source switches.
    ///
    /// ## Thread Safety
    ///
    /// Uses SeqCst ordering for consistency across threads.
    #[must_use]
    pub fn get_source_switches(&self) -> u64 {
        self.source_switches.load(Ordering::SeqCst)
    }

    /// Get the current count of events from primary.
    ///
    /// ## Thread Safety
    ///
    /// Uses SeqCst ordering for consistency across threads.
    #[must_use]
    pub fn get_events_from_primary(&self) -> u64 {
        self.events_from_primary.load(Ordering::SeqCst)
    }

    /// Get the current count of events from fallback.
    ///
    /// ## Thread Safety
    ///
    /// Uses SeqCst ordering for consistency across threads.
    #[must_use]
    pub fn get_events_from_fallback(&self) -> u64 {
        self.events_from_fallback.load(Ordering::SeqCst)
    }

    /// Get the total fallback duration in seconds.
    ///
    /// ## Thread Safety
    ///
    /// Uses SeqCst ordering for consistency across threads.
    #[must_use]
    pub fn get_fallback_duration_total_secs(&self) -> u64 {
        self.fallback_duration_total_secs.load(Ordering::SeqCst)
    }

    /// Get the current count of transition failures.
    ///
    /// ## Thread Safety
    ///
    /// Uses SeqCst ordering for consistency across threads.
    #[must_use]
    pub fn get_transition_failures(&self) -> u64 {
        self.transition_failures.load(Ordering::SeqCst)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // PROMETHEUS EXPORT
    // ════════════════════════════════════════════════════════════════════════════

    /// Export metrics in Prometheus exposition format.
    ///
    /// Returns a string containing all metrics in valid Prometheus text format.
    /// Each metric includes a HELP comment and TYPE declaration.
    ///
    /// ## Format
    ///
    /// ```text
    /// # HELP dsdn_node_fallback_source_switches_total Number of DA source transitions
    /// # TYPE dsdn_node_fallback_source_switches_total counter
    /// dsdn_node_fallback_source_switches_total 0
    /// ...
    /// ```
    ///
    /// ## Guarantees
    ///
    /// - Output is valid Prometheus exposition format
    /// - Deterministic: same state produces same output
    /// - Never panics
    /// - Uses SeqCst ordering for all reads (snapshot consistency)
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        // Read all values with SeqCst ordering for snapshot consistency
        let source_switches = self.source_switches.load(Ordering::SeqCst);
        let events_from_primary = self.events_from_primary.load(Ordering::SeqCst);
        let events_from_fallback = self.events_from_fallback.load(Ordering::SeqCst);
        let fallback_duration_total_secs = self.fallback_duration_total_secs.load(Ordering::SeqCst);
        let transition_failures = self.transition_failures.load(Ordering::SeqCst);

        // Build output string with proper Prometheus format
        format!(
            "# HELP dsdn_node_fallback_source_switches_total Number of DA source transitions\n\
             # TYPE dsdn_node_fallback_source_switches_total counter\n\
             dsdn_node_fallback_source_switches_total {}\n\
             # HELP dsdn_node_fallback_events_from_primary_total Events processed from primary DA\n\
             # TYPE dsdn_node_fallback_events_from_primary_total counter\n\
             dsdn_node_fallback_events_from_primary_total {}\n\
             # HELP dsdn_node_fallback_events_from_fallback_total Events processed from fallback DA\n\
             # TYPE dsdn_node_fallback_events_from_fallback_total counter\n\
             dsdn_node_fallback_events_from_fallback_total {}\n\
             # HELP dsdn_node_fallback_duration_seconds_total Total time spent in fallback mode\n\
             # TYPE dsdn_node_fallback_duration_seconds_total counter\n\
             dsdn_node_fallback_duration_seconds_total {}\n\
             # HELP dsdn_node_fallback_transition_failures_total Number of failed source transitions\n\
             # TYPE dsdn_node_fallback_transition_failures_total counter\n\
             dsdn_node_fallback_transition_failures_total {}\n",
            source_switches,
            events_from_primary,
            events_from_fallback,
            fallback_duration_total_secs,
            transition_failures,
        )
    }

    /// Reset all metrics to zero.
    ///
    /// Useful for testing or periodic resets.
    ///
    /// ## Thread Safety
    ///
    /// Each store uses SeqCst ordering.
    /// Note: Not atomic across all fields (each field reset independently).
    pub fn reset(&self) {
        self.source_switches.store(0, Ordering::SeqCst);
        self.events_from_primary.store(0, Ordering::SeqCst);
        self.events_from_fallback.store(0, Ordering::SeqCst);
        self.fallback_duration_total_secs.store(0, Ordering::SeqCst);
        self.transition_failures.store(0, Ordering::SeqCst);
    }
}

impl Default for NodeFallbackMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    // ════════════════════════════════════════════════════════════════════════════
    // A. CONSTRUCTION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_new_initializes_to_zero() {
        let metrics = NodeFallbackMetrics::new();

        assert_eq!(metrics.get_source_switches(), 0);
        assert_eq!(metrics.get_events_from_primary(), 0);
        assert_eq!(metrics.get_events_from_fallback(), 0);
        assert_eq!(metrics.get_fallback_duration_total_secs(), 0);
        assert_eq!(metrics.get_transition_failures(), 0);
    }

    #[test]
    fn test_default_equals_new() {
        let new_metrics = NodeFallbackMetrics::new();
        let default_metrics = NodeFallbackMetrics::default();

        assert_eq!(new_metrics.get_source_switches(), default_metrics.get_source_switches());
        assert_eq!(new_metrics.get_events_from_primary(), default_metrics.get_events_from_primary());
        assert_eq!(new_metrics.get_events_from_fallback(), default_metrics.get_events_from_fallback());
        assert_eq!(new_metrics.get_fallback_duration_total_secs(), default_metrics.get_fallback_duration_total_secs());
        assert_eq!(new_metrics.get_transition_failures(), default_metrics.get_transition_failures());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // B. INCREMENT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_record_source_switch() {
        let metrics = NodeFallbackMetrics::new();

        metrics.record_source_switch();
        assert_eq!(metrics.get_source_switches(), 1);

        metrics.record_source_switch();
        assert_eq!(metrics.get_source_switches(), 2);

        metrics.record_source_switch();
        assert_eq!(metrics.get_source_switches(), 3);
    }

    #[test]
    fn test_record_event_from_primary() {
        let metrics = NodeFallbackMetrics::new();

        metrics.record_event_from_primary();
        assert_eq!(metrics.get_events_from_primary(), 1);

        metrics.record_event_from_primary();
        metrics.record_event_from_primary();
        assert_eq!(metrics.get_events_from_primary(), 3);
    }

    #[test]
    fn test_record_event_from_fallback() {
        let metrics = NodeFallbackMetrics::new();

        metrics.record_event_from_fallback();
        assert_eq!(metrics.get_events_from_fallback(), 1);

        metrics.record_event_from_fallback();
        metrics.record_event_from_fallback();
        assert_eq!(metrics.get_events_from_fallback(), 3);
    }

    #[test]
    fn test_add_fallback_duration() {
        let metrics = NodeFallbackMetrics::new();

        metrics.add_fallback_duration(10);
        assert_eq!(metrics.get_fallback_duration_total_secs(), 10);

        metrics.add_fallback_duration(25);
        assert_eq!(metrics.get_fallback_duration_total_secs(), 35);

        metrics.add_fallback_duration(5);
        assert_eq!(metrics.get_fallback_duration_total_secs(), 40);
    }

    #[test]
    fn test_record_transition_failure() {
        let metrics = NodeFallbackMetrics::new();

        metrics.record_transition_failure();
        assert_eq!(metrics.get_transition_failures(), 1);

        metrics.record_transition_failure();
        assert_eq!(metrics.get_transition_failures(), 2);
    }

    #[test]
    fn test_add_events_from_primary_bulk() {
        let metrics = NodeFallbackMetrics::new();

        metrics.add_events_from_primary(100);
        assert_eq!(metrics.get_events_from_primary(), 100);

        metrics.add_events_from_primary(50);
        assert_eq!(metrics.get_events_from_primary(), 150);
    }

    #[test]
    fn test_add_events_from_fallback_bulk() {
        let metrics = NodeFallbackMetrics::new();

        metrics.add_events_from_fallback(200);
        assert_eq!(metrics.get_events_from_fallback(), 200);

        metrics.add_events_from_fallback(100);
        assert_eq!(metrics.get_events_from_fallback(), 300);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // C. RESET TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_reset() {
        let metrics = NodeFallbackMetrics::new();

        // Populate with data
        metrics.record_source_switch();
        metrics.record_source_switch();
        metrics.record_event_from_primary();
        metrics.record_event_from_fallback();
        metrics.add_fallback_duration(100);
        metrics.record_transition_failure();

        // Verify non-zero
        assert!(metrics.get_source_switches() > 0);
        assert!(metrics.get_events_from_primary() > 0);

        // Reset
        metrics.reset();

        // Verify all zero
        assert_eq!(metrics.get_source_switches(), 0);
        assert_eq!(metrics.get_events_from_primary(), 0);
        assert_eq!(metrics.get_events_from_fallback(), 0);
        assert_eq!(metrics.get_fallback_duration_total_secs(), 0);
        assert_eq!(metrics.get_transition_failures(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // D. PROMETHEUS FORMAT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_to_prometheus_format_zero_values() {
        let metrics = NodeFallbackMetrics::new();
        let output = metrics.to_prometheus();

        // Check all metrics are present
        assert!(output.contains("dsdn_node_fallback_source_switches_total"));
        assert!(output.contains("dsdn_node_fallback_events_from_primary_total"));
        assert!(output.contains("dsdn_node_fallback_events_from_fallback_total"));
        assert!(output.contains("dsdn_node_fallback_duration_seconds_total"));
        assert!(output.contains("dsdn_node_fallback_transition_failures_total"));

        // Check HELP comments
        assert!(output.contains("# HELP dsdn_node_fallback_source_switches_total"));
        assert!(output.contains("# HELP dsdn_node_fallback_events_from_primary_total"));
        assert!(output.contains("# HELP dsdn_node_fallback_events_from_fallback_total"));
        assert!(output.contains("# HELP dsdn_node_fallback_duration_seconds_total"));
        assert!(output.contains("# HELP dsdn_node_fallback_transition_failures_total"));

        // Check TYPE declarations
        assert!(output.contains("# TYPE dsdn_node_fallback_source_switches_total counter"));
        assert!(output.contains("# TYPE dsdn_node_fallback_events_from_primary_total counter"));
        assert!(output.contains("# TYPE dsdn_node_fallback_events_from_fallback_total counter"));
        assert!(output.contains("# TYPE dsdn_node_fallback_duration_seconds_total counter"));
        assert!(output.contains("# TYPE dsdn_node_fallback_transition_failures_total counter"));

        // Check zero values
        assert!(output.contains("dsdn_node_fallback_source_switches_total 0\n"));
        assert!(output.contains("dsdn_node_fallback_events_from_primary_total 0\n"));
        assert!(output.contains("dsdn_node_fallback_events_from_fallback_total 0\n"));
        assert!(output.contains("dsdn_node_fallback_duration_seconds_total 0\n"));
        assert!(output.contains("dsdn_node_fallback_transition_failures_total 0\n"));
    }

    #[test]
    fn test_to_prometheus_format_with_values() {
        let metrics = NodeFallbackMetrics::new();

        metrics.record_source_switch();
        metrics.record_source_switch();
        metrics.record_source_switch();
        metrics.add_events_from_primary(1000);
        metrics.add_events_from_fallback(500);
        metrics.add_fallback_duration(3600);
        metrics.record_transition_failure();

        let output = metrics.to_prometheus();

        // Check specific values
        assert!(output.contains("dsdn_node_fallback_source_switches_total 3\n"));
        assert!(output.contains("dsdn_node_fallback_events_from_primary_total 1000\n"));
        assert!(output.contains("dsdn_node_fallback_events_from_fallback_total 500\n"));
        assert!(output.contains("dsdn_node_fallback_duration_seconds_total 3600\n"));
        assert!(output.contains("dsdn_node_fallback_transition_failures_total 1\n"));
    }

    #[test]
    fn test_to_prometheus_deterministic() {
        let metrics = NodeFallbackMetrics::new();

        metrics.record_source_switch();
        metrics.add_events_from_primary(42);

        let output1 = metrics.to_prometheus();
        let output2 = metrics.to_prometheus();

        // Same input state should produce same output
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_to_prometheus_valid_format() {
        let metrics = NodeFallbackMetrics::new();
        metrics.add_events_from_primary(123456789);

        let output = metrics.to_prometheus();

        // Each line should be valid Prometheus format
        for line in output.lines() {
            // Lines should either be comments or metrics
            assert!(
                line.starts_with('#') || 
                line.starts_with("dsdn_node_fallback_") ||
                line.is_empty(),
                "Invalid line format: {}",
                line
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // E. THREAD SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_concurrent_increments() {
        let metrics = Arc::new(NodeFallbackMetrics::new());
        let mut handles = vec![];

        // Spawn 10 threads, each incrementing 1000 times
        for _ in 0..10 {
            let m = Arc::clone(&metrics);
            let handle = thread::spawn(move || {
                for _ in 0..1000 {
                    m.record_source_switch();
                    m.record_event_from_primary();
                    m.record_event_from_fallback();
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Verify counts - no lost updates
        assert_eq!(metrics.get_source_switches(), 10_000);
        assert_eq!(metrics.get_events_from_primary(), 10_000);
        assert_eq!(metrics.get_events_from_fallback(), 10_000);
    }

    #[test]
    fn test_concurrent_read_write() {
        let metrics = Arc::new(NodeFallbackMetrics::new());
        let mut handles = vec![];

        // Writer threads
        for _ in 0..5 {
            let m = Arc::clone(&metrics);
            let handle = thread::spawn(move || {
                for _ in 0..1000 {
                    m.record_source_switch();
                    m.add_fallback_duration(1);
                }
            });
            handles.push(handle);
        }

        // Reader threads
        for _ in 0..5 {
            let m = Arc::clone(&metrics);
            let handle = thread::spawn(move || {
                for _ in 0..1000 {
                    let _ = m.to_prometheus();
                    let _ = m.get_source_switches();
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Verify final state
        assert_eq!(metrics.get_source_switches(), 5_000);
        assert_eq!(metrics.get_fallback_duration_total_secs(), 5_000);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // F. INDEPENDENCE TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_metrics_independent() {
        let metrics = NodeFallbackMetrics::new();

        // Increment only source_switches
        metrics.record_source_switch();
        metrics.record_source_switch();

        // Other metrics should still be zero
        assert_eq!(metrics.get_source_switches(), 2);
        assert_eq!(metrics.get_events_from_primary(), 0);
        assert_eq!(metrics.get_events_from_fallback(), 0);
        assert_eq!(metrics.get_fallback_duration_total_secs(), 0);
        assert_eq!(metrics.get_transition_failures(), 0);
    }

    #[test]
    fn test_large_values() {
        let metrics = NodeFallbackMetrics::new();

        // Add large values
        metrics.add_events_from_primary(u64::MAX / 2);
        metrics.add_events_from_fallback(u64::MAX / 2);

        assert_eq!(metrics.get_events_from_primary(), u64::MAX / 2);
        assert_eq!(metrics.get_events_from_fallback(), u64::MAX / 2);

        // Verify prometheus output handles large values
        let output = metrics.to_prometheus();
        assert!(output.contains(&(u64::MAX / 2).to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // G. DEBUG FORMAT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_debug_format() {
        let metrics = NodeFallbackMetrics::new();
        metrics.record_source_switch();

        let debug_str = format!("{:?}", metrics);

        assert!(debug_str.contains("NodeFallbackMetrics"));
        assert!(debug_str.contains("source_switches"));
        assert!(debug_str.contains("events_from_primary"));
        assert!(debug_str.contains("events_from_fallback"));
        assert!(debug_str.contains("fallback_duration_total_secs"));
        assert!(debug_str.contains("transition_failures"));
    }
}
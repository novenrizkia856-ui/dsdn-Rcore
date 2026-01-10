//! # Metrics & Observability Module
//!
//! Module ini menyediakan metrics dan observability untuk ingress layer.
//!
//! ## Prinsip
//!
//! - Semua metrics thread-safe (atomic operations)
//! - Tidak ada double-counting atau lost updates
//! - Prometheus exposition format yang valid
//! - Deterministic per-request tracing
//!
//! ## Metrics
//!
//! - `requests_total`: Total request masuk
//! - `requests_by_status`: Request per HTTP status code
//! - `routing_latency_histogram`: Latency routing decision
//! - `cache_hits/misses`: Cache routing statistics
//! - `fallback_triggered`: Fallback events
//! - `da_sync_latency`: DA interaction latency

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use std::fmt::Write;

use parking_lot::RwLock;

// ════════════════════════════════════════════════════════════════════════════
// COUNTER
// ════════════════════════════════════════════════════════════════════════════

/// Thread-safe counter menggunakan atomic operations.
#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    /// Membuat counter baru dengan nilai 0.
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    /// Increment counter by 1.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::SeqCst);
    }

    /// Increment counter by n.
    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::SeqCst);
    }

    /// Get current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }

    /// Reset counter to 0.
    pub fn reset(&self) {
        self.value.store(0, Ordering::SeqCst);
    }
}

impl Clone for Counter {
    fn clone(&self) -> Self {
        Self {
            value: AtomicU64::new(self.get()),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// GAUGE
// ════════════════════════════════════════════════════════════════════════════

/// Thread-safe gauge untuk nilai yang bisa naik turun.
#[derive(Debug, Default)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    /// Membuat gauge baru dengan nilai 0.
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    /// Set gauge value.
    pub fn set(&self, v: u64) {
        self.value.store(v, Ordering::SeqCst);
    }

    /// Get current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }
}

impl Clone for Gauge {
    fn clone(&self) -> Self {
        Self {
            value: AtomicU64::new(self.get()),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HISTOGRAM
// ════════════════════════════════════════════════════════════════════════════

/// Thread-safe histogram untuk latency tracking.
///
/// Menggunakan bucket-based approach untuk efisiensi.
/// Buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1000ms, +Inf
pub struct Histogram {
    /// Bucket counts (index corresponds to bucket)
    buckets: [AtomicU64; 10],
    /// Sum of all observed values
    sum: AtomicU64,
    /// Count of observations
    count: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    /// Bucket boundaries in milliseconds.
    pub const BUCKET_BOUNDS: [u64; 9] = [1, 5, 10, 25, 50, 100, 250, 500, 1000];

    /// Membuat histogram baru.
    pub fn new() -> Self {
        Self {
            buckets: [
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Observe a value (in milliseconds).
    pub fn observe(&self, value_ms: u64) {
        // Update sum and count
        self.sum.fetch_add(value_ms, Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);

        // Find bucket and increment
        let bucket_idx = Self::find_bucket(value_ms);
        self.buckets[bucket_idx].fetch_add(1, Ordering::SeqCst);
    }

    /// Find bucket index for a value.
    fn find_bucket(value_ms: u64) -> usize {
        for (i, &bound) in Self::BUCKET_BOUNDS.iter().enumerate() {
            if value_ms <= bound {
                return i;
            }
        }
        9 // +Inf bucket
    }

    /// Get bucket count at index.
    pub fn get_bucket(&self, idx: usize) -> u64 {
        if idx < 10 {
            self.buckets[idx].load(Ordering::SeqCst)
        } else {
            0
        }
    }

    /// Get cumulative count up to and including bucket.
    pub fn get_cumulative(&self, idx: usize) -> u64 {
        let mut total = 0;
        for i in 0..=idx.min(9) {
            total += self.buckets[i].load(Ordering::SeqCst);
        }
        total
    }

    /// Get sum of all observations.
    pub fn get_sum(&self) -> u64 {
        self.sum.load(Ordering::SeqCst)
    }

    /// Get count of observations.
    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for Histogram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Histogram")
            .field("count", &self.get_count())
            .field("sum", &self.get_sum())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STATUS CODE COUNTERS
// ════════════════════════════════════════════════════════════════════════════

/// Thread-safe counters per HTTP status code.
pub struct StatusCodeCounters {
    counters: RwLock<HashMap<u16, Counter>>,
}

impl Default for StatusCodeCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusCodeCounters {
    /// Membuat status code counters baru.
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
        }
    }

    /// Increment counter for status code.
    pub fn inc(&self, status: u16) {
        // Try read lock first
        {
            let counters = self.counters.read();
            if let Some(counter) = counters.get(&status) {
                counter.inc();
                return;
            }
        }

        // Need write lock to insert
        let mut counters = self.counters.write();
        counters
            .entry(status)
            .or_insert_with(Counter::new)
            .inc();
    }

    /// Get counter value for status code.
    pub fn get(&self, status: u16) -> u64 {
        self.counters
            .read()
            .get(&status)
            .map(|c| c.get())
            .unwrap_or(0)
    }

    /// Get all status codes and their counts.
    pub fn get_all(&self) -> Vec<(u16, u64)> {
        self.counters
            .read()
            .iter()
            .map(|(&k, v)| (k, v.get()))
            .collect()
    }
}

impl std::fmt::Debug for StatusCodeCounters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusCodeCounters")
            .field("counters", &self.get_all())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TRACE ID
// ════════════════════════════════════════════════════════════════════════════

/// Unique trace ID untuk setiap request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceId(String);

impl TraceId {
    /// Generate new trace ID.
    ///
    /// Format: `{timestamp_ms}-{counter}-{random}`
    /// Deterministik per-request, tidak global.
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        let count = COUNTER.fetch_add(1, Ordering::SeqCst);

        // Use thread ID as additional entropy
        let thread_id = std::thread::current().id();
        let thread_hash = format!("{:?}", thread_id).len() as u64;

        Self(format!("{:x}-{:04x}-{:02x}", ts, count, thread_hash % 256))
    }

    /// Get trace ID as string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// INGRESS METRICS
// ════════════════════════════════════════════════════════════════════════════

/// Metrics untuk ingress layer.
///
/// Thread-safe dan dapat diakses dari multiple handlers.
pub struct IngressMetrics {
    /// Total requests received.
    pub requests_total: Counter,
    /// Requests by HTTP status code.
    pub requests_by_status: StatusCodeCounters,
    /// Routing decision latency histogram.
    pub routing_latency_histogram: Histogram,
    /// Cache hits counter.
    pub cache_hits: Counter,
    /// Cache misses counter.
    pub cache_misses: Counter,
    /// Fallback triggered counter.
    pub fallback_triggered: Counter,
    /// DA sync latency (last observed, in ms).
    pub da_sync_latency: Gauge,
}

impl Default for IngressMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl IngressMetrics {
    /// Membuat IngressMetrics baru.
    pub fn new() -> Self {
        Self {
            requests_total: Counter::new(),
            requests_by_status: StatusCodeCounters::new(),
            routing_latency_histogram: Histogram::new(),
            cache_hits: Counter::new(),
            cache_misses: Counter::new(),
            fallback_triggered: Counter::new(),
            da_sync_latency: Gauge::new(),
        }
    }

    /// Record request start.
    pub fn record_request(&self) {
        self.requests_total.inc();
    }

    /// Record request completion with status.
    pub fn record_status(&self, status: u16) {
        self.requests_by_status.inc(status);
    }

    /// Record routing latency.
    pub fn record_routing_latency(&self, latency_ms: u64) {
        self.routing_latency_histogram.observe(latency_ms);
    }

    /// Record cache hit.
    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }

    /// Record cache miss.
    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }

    /// Record fallback triggered.
    pub fn record_fallback(&self) {
        self.fallback_triggered.inc();
    }

    /// Record DA sync latency.
    pub fn record_da_sync_latency(&self, latency_ms: u64) {
        self.da_sync_latency.set(latency_ms);
    }

    /// Export metrics in Prometheus exposition format.
    pub fn to_prometheus(&self) -> String {
        let mut output = String::with_capacity(4096);

        // requests_total
        let _ = writeln!(output, "# HELP ingress_requests_total Total number of requests received");
        let _ = writeln!(output, "# TYPE ingress_requests_total counter");
        let _ = writeln!(output, "ingress_requests_total {}", self.requests_total.get());
        let _ = writeln!(output);

        // requests_by_status
        let _ = writeln!(output, "# HELP ingress_requests_by_status Requests by HTTP status code");
        let _ = writeln!(output, "# TYPE ingress_requests_by_status counter");
        let mut status_codes: Vec<_> = self.requests_by_status.get_all();
        status_codes.sort_by_key(|(k, _)| *k);
        for (status, count) in status_codes {
            let _ = writeln!(output, "ingress_requests_by_status{{status=\"{}\"}} {}", status, count);
        }
        let _ = writeln!(output);

        // routing_latency_histogram
        let _ = writeln!(output, "# HELP ingress_routing_latency_ms Routing decision latency in milliseconds");
        let _ = writeln!(output, "# TYPE ingress_routing_latency_ms histogram");
        for (i, &bound) in Histogram::BUCKET_BOUNDS.iter().enumerate() {
            let cumulative = self.routing_latency_histogram.get_cumulative(i);
            let _ = writeln!(output, "ingress_routing_latency_ms_bucket{{le=\"{}\"}} {}", bound, cumulative);
        }
        let _ = writeln!(output, "ingress_routing_latency_ms_bucket{{le=\"+Inf\"}} {}", 
            self.routing_latency_histogram.get_cumulative(9));
        let _ = writeln!(output, "ingress_routing_latency_ms_sum {}", 
            self.routing_latency_histogram.get_sum());
        let _ = writeln!(output, "ingress_routing_latency_ms_count {}", 
            self.routing_latency_histogram.get_count());
        let _ = writeln!(output);

        // cache_hits
        let _ = writeln!(output, "# HELP ingress_cache_hits Total cache hits");
        let _ = writeln!(output, "# TYPE ingress_cache_hits counter");
        let _ = writeln!(output, "ingress_cache_hits {}", self.cache_hits.get());
        let _ = writeln!(output);

        // cache_misses
        let _ = writeln!(output, "# HELP ingress_cache_misses Total cache misses");
        let _ = writeln!(output, "# TYPE ingress_cache_misses counter");
        let _ = writeln!(output, "ingress_cache_misses {}", self.cache_misses.get());
        let _ = writeln!(output);

        // fallback_triggered
        let _ = writeln!(output, "# HELP ingress_fallback_triggered Total fallback events");
        let _ = writeln!(output, "# TYPE ingress_fallback_triggered counter");
        let _ = writeln!(output, "ingress_fallback_triggered {}", self.fallback_triggered.get());
        let _ = writeln!(output);

        // da_sync_latency
        let _ = writeln!(output, "# HELP ingress_da_sync_latency_ms DA sync latency in milliseconds");
        let _ = writeln!(output, "# TYPE ingress_da_sync_latency_ms gauge");
        let _ = writeln!(output, "ingress_da_sync_latency_ms {}", self.da_sync_latency.get());

        output
    }
}

impl std::fmt::Debug for IngressMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngressMetrics")
            .field("requests_total", &self.requests_total.get())
            .field("cache_hits", &self.cache_hits.get())
            .field("cache_misses", &self.cache_misses.get())
            .field("fallback_triggered", &self.fallback_triggered.get())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// REQUEST CONTEXT
// ════════════════════════════════════════════════════════════════════════════

/// Context untuk single request dengan tracing.
pub struct RequestContext {
    /// Unique trace ID untuk request ini.
    pub trace_id: TraceId,
    /// Start time untuk latency calculation.
    pub start_time: Instant,
    /// Target node (jika sudah ditentukan).
    pub target_node: Option<String>,
    /// Routing strategy used.
    pub routing_strategy: Option<String>,
    /// Whether fallback was used.
    pub used_fallback: bool,
    /// Cache hit status.
    pub cache_hit: Option<bool>,
}

impl RequestContext {
    /// Membuat RequestContext baru.
    pub fn new() -> Self {
        Self {
            trace_id: TraceId::generate(),
            start_time: Instant::now(),
            target_node: None,
            routing_strategy: None,
            used_fallback: false,
            cache_hit: None,
        }
    }

    /// Get elapsed time since start in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    /// Set target node.
    pub fn set_target_node(&mut self, node: &str) {
        self.target_node = Some(node.to_string());
    }

    /// Set routing strategy.
    pub fn set_routing_strategy(&mut self, strategy: &str) {
        self.routing_strategy = Some(strategy.to_string());
    }

    /// Set fallback used.
    pub fn set_fallback_used(&mut self, used: bool) {
        self.used_fallback = used;
    }

    /// Set cache hit status.
    pub fn set_cache_hit(&mut self, hit: bool) {
        self.cache_hit = Some(hit);
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::collections::HashSet;

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: COUNTER INCREMENT CORRECTNESS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_counter_increment_correctness() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);

        counter.inc();
        assert_eq!(counter.get(), 1);

        counter.inc_by(10);
        assert_eq!(counter.get(), 11);

        counter.reset();
        assert_eq!(counter.get(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: HISTOGRAM UPDATE CORRECTNESS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_histogram_update_correctness() {
        let hist = Histogram::new();

        // Observe values
        hist.observe(1);   // bucket 0 (<=1ms)
        hist.observe(3);   // bucket 1 (<=5ms)
        hist.observe(50);  // bucket 4 (<=50ms)
        hist.observe(1500); // bucket 9 (+Inf)

        assert_eq!(hist.get_count(), 4);
        assert_eq!(hist.get_sum(), 1 + 3 + 50 + 1500);

        // Check buckets
        assert_eq!(hist.get_bucket(0), 1); // 1ms
        assert_eq!(hist.get_bucket(1), 1); // 5ms
        assert_eq!(hist.get_bucket(4), 1); // 50ms
        assert_eq!(hist.get_bucket(9), 1); // +Inf

        // Check cumulative
        assert_eq!(hist.get_cumulative(0), 1);
        assert_eq!(hist.get_cumulative(1), 2);
        assert_eq!(hist.get_cumulative(4), 3);
        assert_eq!(hist.get_cumulative(9), 4);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: CACHE HIT VS MISS METRICS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cache_hit_miss_metrics() {
        let metrics = IngressMetrics::new();

        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_miss();

        assert_eq!(metrics.cache_hits.get(), 2);
        assert_eq!(metrics.cache_misses.get(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: FALLBACK COUNTER TRIGGERED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fallback_counter_triggered() {
        let metrics = IngressMetrics::new();

        assert_eq!(metrics.fallback_triggered.get(), 0);

        metrics.record_fallback();
        metrics.record_fallback();
        metrics.record_fallback();

        assert_eq!(metrics.fallback_triggered.get(), 3);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: PROMETHEUS OUTPUT VALID
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_prometheus_output_valid() {
        let metrics = IngressMetrics::new();

        // Add some data
        metrics.record_request();
        metrics.record_request();
        metrics.record_status(200);
        metrics.record_status(404);
        metrics.record_routing_latency(5);
        metrics.record_cache_hit();

        let output = metrics.to_prometheus();

        // Check required elements
        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
        assert!(output.contains("ingress_requests_total 2"));
        assert!(output.contains("ingress_requests_by_status"));
        assert!(output.contains("status=\"200\""));
        assert!(output.contains("status=\"404\""));
        assert!(output.contains("ingress_routing_latency_ms_bucket"));
        assert!(output.contains("le=\"+Inf\""));
        assert!(output.contains("ingress_cache_hits 1"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: TRACE ID UNIQUENESS PER REQUEST
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_trace_id_uniqueness() {
        let mut ids = HashSet::new();

        // Generate many trace IDs
        for _ in 0..1000 {
            let id = TraceId::generate();
            assert!(ids.insert(id.0.clone()), "Duplicate trace ID: {}", id);
        }

        assert_eq!(ids.len(), 1000);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: THREAD-SAFETY UNDER CONCURRENT ACCESS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_thread_safety_concurrent() {
        use std::sync::Arc;

        let metrics = Arc::new(IngressMetrics::new());
        let mut handles = vec![];

        // Spawn multiple threads incrementing counters
        for _ in 0..10 {
            let m = metrics.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    m.record_request();
                    m.record_status(200);
                    m.record_routing_latency(5);
                    m.record_cache_hit();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Should have exactly 10 * 100 = 1000 increments
        assert_eq!(metrics.requests_total.get(), 1000);
        assert_eq!(metrics.requests_by_status.get(200), 1000);
        assert_eq!(metrics.routing_latency_histogram.get_count(), 1000);
        assert_eq!(metrics.cache_hits.get(), 1000);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: STATUS CODE COUNTERS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_status_code_counters() {
        let counters = StatusCodeCounters::new();

        counters.inc(200);
        counters.inc(200);
        counters.inc(404);
        counters.inc(500);

        assert_eq!(counters.get(200), 2);
        assert_eq!(counters.get(404), 1);
        assert_eq!(counters.get(500), 1);
        assert_eq!(counters.get(201), 0); // non-existent

        let all = counters.get_all();
        assert_eq!(all.len(), 3);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: REQUEST CONTEXT
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_request_context() {
        let mut ctx = RequestContext::new();

        // Check trace ID is set
        assert!(!ctx.trace_id.as_str().is_empty());

        // Set values
        ctx.set_target_node("node-1");
        ctx.set_routing_strategy("ZoneAffinity");
        ctx.set_fallback_used(true);
        ctx.set_cache_hit(true);

        assert_eq!(ctx.target_node, Some("node-1".to_string()));
        assert_eq!(ctx.routing_strategy, Some("ZoneAffinity".to_string()));
        assert!(ctx.used_fallback);
        assert_eq!(ctx.cache_hit, Some(true));

        // Elapsed should be >= 0
        assert!(ctx.elapsed_ms() < 1000);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: GAUGE SET AND GET
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_gauge_set_get() {
        let gauge = Gauge::new();
        assert_eq!(gauge.get(), 0);

        gauge.set(100);
        assert_eq!(gauge.get(), 100);

        gauge.set(50);
        assert_eq!(gauge.get(), 50);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: HISTOGRAM BUCKET BOUNDARIES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_histogram_bucket_boundaries() {
        // Test exact boundaries
        assert_eq!(Histogram::find_bucket(0), 0);
        assert_eq!(Histogram::find_bucket(1), 0);
        assert_eq!(Histogram::find_bucket(2), 1);
        assert_eq!(Histogram::find_bucket(5), 1);
        assert_eq!(Histogram::find_bucket(6), 2);
        assert_eq!(Histogram::find_bucket(10), 2);
        assert_eq!(Histogram::find_bucket(1000), 8);
        assert_eq!(Histogram::find_bucket(1001), 9);
        assert_eq!(Histogram::find_bucket(u64::MAX), 9);
    }
}
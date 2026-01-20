//! Multi-DA Source abstraction for node follower mode (14A.1A.41-42)
//!
//! Provides explicit abstraction for reading data from multiple DA sources
//! with deterministic, thread-safe, and memory-safe fallback mechanism.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       MultiDASource                             │
//! │                                                                 │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
//! │  │   Primary   │  │  Secondary  │  │  Emergency  │            │
//! │  │  (Celestia) │  │  (QuorumDA) │  │    (Mock)   │            │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘            │
//! │         │                │                │                    │
//! │         └────────────────┴────────────────┘                    │
//! │                          │                                     │
//! │              current_source: RwLock<DASourceType>              │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Fallback Behavior (14A.1A.42)
//!
//! When reading blobs via `get_blob` or subscribing via `subscribe_blobs`:
//! 1. Try `current_source` first
//! 2. If fails, try fixed priority order: Primary → Secondary → Emergency
//! 3. Skip sources already tried
//! 4. Update `current_source` on successful fallback (thread-safe via RwLock)
//! 5. Return last error if all sources fail
//!
//! ## Thread Safety
//!
//! All components are `Send + Sync`:
//! - `Arc<dyn DALayer>` is Send + Sync (DALayer: Send + Sync)
//! - `parking_lot::RwLock<DASourceType>` is Send + Sync
//! - `MultiDAConfig` contains only primitives (auto Send + Sync)
//!
//! ## Usage
//!
//! ```ignore
//! use std::sync::Arc;
//! use dsdn_node::multi_da_source::{MultiDASource, MultiDAConfig, DASourceType};
//!
//! // Primary only
//! let source = MultiDASource::new(primary_da);
//!
//! // With fallbacks
//! let source = MultiDASource::with_fallbacks(
//!     primary_da,
//!     Some(secondary_da),
//!     Some(emergency_da),
//!     MultiDAConfig::default(),
//! );
//!
//! // Get blob with automatic fallback
//! let data = source.get_blob(&blob_ref).await?;
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use parking_lot::RwLock;
use dsdn_common::{BlobRef, BlobStream, DAError, DALayer};

// ════════════════════════════════════════════════════════════════════════════════
// DA SOURCE TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Enum representing the current DA source type.
///
/// Used to track which DA layer is currently active for reading operations.
/// Transitions between sources are deterministic and explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DASourceType {
    /// Primary DA source (Celestia).
    /// This is the default and preferred source.
    Primary,

    /// Secondary DA source (QuorumDA fallback).
    /// Used when Primary is unavailable.
    Secondary,

    /// Emergency DA source (Mock/local fallback).
    /// Used when both Primary and Secondary are unavailable.
    Emergency,
}

impl Default for DASourceType {
    fn default() -> Self {
        Self::Primary
    }
}

impl std::fmt::Display for DASourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Primary => write!(f, "Primary"),
            Self::Secondary => write!(f, "Secondary"),
            Self::Emergency => write!(f, "Emergency"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MULTI DA CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Configuration for MultiDASource behavior.
///
/// All fields have explicit defaults. No environment variable dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiDAConfig {
    /// Whether automatic fallback to secondary/emergency is enabled.
    ///
    /// When true, source switching can happen automatically based on health.
    /// When false, source must be switched explicitly.
    ///
    /// Default: `true`
    pub auto_fallback_enabled: bool,

    /// Whether to prefer primary even when secondary is healthy.
    ///
    /// When true, always try primary first before falling back.
    /// When false, may stay on secondary if it's healthy.
    ///
    /// Default: `true`
    pub prefer_primary: bool,
}

impl Default for MultiDAConfig {
    fn default() -> Self {
        Self {
            auto_fallback_enabled: true,
            prefer_primary: true,
        }
    }
}

impl MultiDAConfig {
    /// Create a new config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a config with auto-fallback disabled.
    #[must_use]
    pub fn no_auto_fallback() -> Self {
        Self {
            auto_fallback_enabled: false,
            prefer_primary: true,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FALLBACK ORDER CONSTANT
// ════════════════════════════════════════════════════════════════════════════════

/// Fixed priority order for fallback: Primary → Secondary → Emergency.
/// This order is deterministic and MUST NOT change.
const FALLBACK_PRIORITY_ORDER: [DASourceType; 3] = [
    DASourceType::Primary,
    DASourceType::Secondary,
    DASourceType::Emergency,
];

// ════════════════════════════════════════════════════════════════════════════════
// MULTI DA SOURCE
// ════════════════════════════════════════════════════════════════════════════════

/// Multi-DA source abstraction for reading from multiple DA sources with fallback.
///
/// This struct provides a unified interface for reading from multiple DA layers
/// with explicit source tracking and deterministic fallback behavior.
///
/// ## Fields
///
/// - `primary`: The primary DA layer (required, typically Celestia)
/// - `secondary`: Optional secondary DA layer (fallback, typically QuorumDA)
/// - `emergency`: Optional emergency DA layer (last resort, typically Mock)
/// - `current_source`: Current active source type, protected by RwLock
/// - `config`: Configuration for fallback behavior
///
/// ## Thread Safety
///
/// This struct is `Send + Sync` because:
/// - `Arc<dyn DALayer>` is Send + Sync (DALayer trait requires Send + Sync)
/// - `parking_lot::RwLock` is Send + Sync
/// - `MultiDAConfig` contains only Copy types
///
/// ## Ownership
///
/// All DA layers are held via `Arc`, allowing shared ownership across threads.
/// The `current_source` field uses interior mutability via `RwLock` for
/// thread-safe source switching.
pub struct MultiDASource {
    /// Primary DA layer (required).
    ///
    /// This is the main DA source, typically Celestia.
    pub primary: Arc<dyn DALayer>,

    /// Secondary DA layer (optional).
    ///
    /// Fallback DA source, typically QuorumDA.
    /// Used when primary is unavailable.
    pub secondary: Option<Arc<dyn DALayer>>,

    /// Emergency DA layer (optional).
    ///
    /// Last-resort DA source, typically a Mock implementation.
    /// Used when both primary and secondary are unavailable.
    pub emergency: Option<Arc<dyn DALayer>>,

    /// Current active DA source type.
    ///
    /// Protected by RwLock for thread-safe reads and writes.
    /// Defaults to Primary.
    pub current_source: RwLock<DASourceType>,

    /// Configuration for fallback behavior.
    pub config: MultiDAConfig,
}

impl MultiDASource {
    /// Create a new MultiDASource with only primary DA.
    ///
    /// This is the simplest configuration with no fallback layers.
    /// The current source is set to Primary.
    ///
    /// # Arguments
    ///
    /// * `primary` - The primary DA layer (required)
    ///
    /// # Returns
    ///
    /// A new `MultiDASource` instance with default config and no fallbacks.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let source = MultiDASource::new(primary_da);
    /// assert_eq!(source.get_current_source(), DASourceType::Primary);
    /// ```
    #[must_use]
    pub fn new(primary: Arc<dyn DALayer>) -> Self {
        Self {
            primary,
            secondary: None,
            emergency: None,
            current_source: RwLock::new(DASourceType::Primary),
            config: MultiDAConfig::default(),
        }
    }

    /// Create a MultiDASource with fallback DA layers.
    ///
    /// This configuration allows for fallback to secondary and/or emergency
    /// DA layers when the primary is unavailable.
    ///
    /// # Arguments
    ///
    /// * `primary` - The primary DA layer (required)
    /// * `secondary` - Optional secondary DA layer for fallback
    /// * `emergency` - Optional emergency DA layer as last resort
    /// * `config` - Configuration for fallback behavior
    ///
    /// # Returns
    ///
    /// A new `MultiDASource` instance with the specified configuration.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let source = MultiDASource::with_fallbacks(
    ///     primary_da,
    ///     Some(secondary_da),
    ///     Some(emergency_da),
    ///     MultiDAConfig::default(),
    /// );
    /// ```
    #[must_use]
    pub fn with_fallbacks(
        primary: Arc<dyn DALayer>,
        secondary: Option<Arc<dyn DALayer>>,
        emergency: Option<Arc<dyn DALayer>>,
        config: MultiDAConfig,
    ) -> Self {
        Self {
            primary,
            secondary,
            emergency,
            current_source: RwLock::new(DASourceType::Primary),
            config,
        }
    }

    /// Get the current active DA source type.
    ///
    /// This method acquires a read lock on `current_source`.
    ///
    /// # Returns
    ///
    /// The current `DASourceType`.
    #[must_use]
    pub fn get_current_source(&self) -> DASourceType {
        *self.current_source.read()
    }

    /// Set the current active DA source type.
    ///
    /// This method acquires a write lock on `current_source`.
    ///
    /// # Arguments
    ///
    /// * `source_type` - The new source type to set
    ///
    /// # Returns
    ///
    /// `true` if the source was changed, `false` if it was already set to the requested type.
    pub fn set_current_source(&self, source_type: DASourceType) -> bool {
        let mut current = self.current_source.write();
        if *current != source_type {
            *current = source_type;
            true
        } else {
            false
        }
    }

    /// Check if secondary DA layer is configured.
    #[must_use]
    pub fn has_secondary(&self) -> bool {
        self.secondary.is_some()
    }

    /// Check if emergency DA layer is configured.
    #[must_use]
    pub fn has_emergency(&self) -> bool {
        self.emergency.is_some()
    }

    /// Get reference to the currently active DA layer.
    ///
    /// Returns the DA layer corresponding to the current source type.
    /// Falls back to primary if the requested source is not configured.
    ///
    /// # Returns
    ///
    /// `Arc<dyn DALayer>` for the active source.
    #[must_use]
    pub fn get_active_da(&self) -> Arc<dyn DALayer> {
        let source_type = self.get_current_source();
        match source_type {
            DASourceType::Primary => Arc::clone(&self.primary),
            DASourceType::Secondary => {
                self.secondary.as_ref()
                    .map(Arc::clone)
                    .unwrap_or_else(|| Arc::clone(&self.primary))
            }
            DASourceType::Emergency => {
                self.emergency.as_ref()
                    .map(Arc::clone)
                    .unwrap_or_else(|| {
                        // Fall back to secondary if available, else primary
                        self.secondary.as_ref()
                            .map(Arc::clone)
                            .unwrap_or_else(|| Arc::clone(&self.primary))
                    })
            }
        }
    }

    /// Check if auto-fallback is enabled.
    #[must_use]
    pub fn is_auto_fallback_enabled(&self) -> bool {
        self.config.auto_fallback_enabled
    }

    /// Check if primary is preferred.
    #[must_use]
    pub fn is_prefer_primary(&self) -> bool {
        self.config.prefer_primary
    }

    // ════════════════════════════════════════════════════════════════════════════
    // FALLBACK BLOB READING (14A.1A.42)
    // ════════════════════════════════════════════════════════════════════════════

    /// Get DA layer for a specific source type.
    ///
    /// Returns `None` if the source is not configured (except Primary which is always configured).
    ///
    /// # Arguments
    ///
    /// * `source_type` - The source type to retrieve
    ///
    /// # Returns
    ///
    /// * `Some(Arc<dyn DALayer>)` - The DA layer if configured
    /// * `None` - If the source is not configured (Secondary/Emergency only)
    #[must_use]
    pub fn get_da_for_source(&self, source_type: DASourceType) -> Option<Arc<dyn DALayer>> {
        match source_type {
            DASourceType::Primary => Some(Arc::clone(&self.primary)),
            DASourceType::Secondary => self.secondary.as_ref().map(Arc::clone),
            DASourceType::Emergency => self.emergency.as_ref().map(Arc::clone),
        }
    }

    /// Get blob from DA with deterministic fallback logic.
    ///
    /// ## Behavior (DETERMINISTIC, FIXED ORDER)
    ///
    /// 1. Try `current_source` first
    /// 2. If fails, try remaining sources in fixed priority order:
    ///    Primary → Secondary → Emergency (skipping already tried)
    /// 3. On success from fallback source:
    ///    - Update `current_source` atomically via RwLock
    ///    - Return blob data
    /// 4. If ALL sources fail:
    ///    - Return the last error encountered
    ///    - NO panic, NO silent failure
    ///
    /// ## Thread Safety
    ///
    /// - `current_source` read uses RwLock (non-blocking readers)
    /// - `current_source` write uses RwLock (exclusive lock)
    /// - Lock NOT held during async I/O operations
    ///
    /// # Arguments
    ///
    /// * `ref_` - Reference to the blob to retrieve
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Blob data on success
    /// * `Err(DAError)` - Last error if all sources fail
    ///
    /// # Example
    ///
    /// ```ignore
    /// let data = source.get_blob(&blob_ref).await?;
    /// ```
    pub fn get_blob<'a>(
        &'a self,
        ref_: &'a BlobRef,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + 'a>> {
        Box::pin(async move {
            // Read current_source (RwLock read, released immediately)
            let current = self.get_current_source();

            // Try current source first
            if let Some(da) = self.get_da_for_source(current) {
                match da.get_blob(ref_).await {
                    Ok(data) => return Ok(data),
                    Err(_e) => {
                        // Current source failed, continue to fallback
                    }
                }
            }

            // Fallback: try remaining sources in fixed priority order
            let mut last_error = DAError::Unavailable;

            for &source_type in &FALLBACK_PRIORITY_ORDER {
                // Skip if we already tried this source
                if source_type == current {
                    continue;
                }

                // Try this source if configured
                if let Some(da) = self.get_da_for_source(source_type) {
                    match da.get_blob(ref_).await {
                        Ok(data) => {
                            // Success! Update current_source (RwLock write)
                            self.set_current_source(source_type);
                            return Ok(data);
                        }
                        Err(e) => {
                            // Track error and continue to next source
                            last_error = e;
                        }
                    }
                }
            }

            // All sources failed - return last error
            Err(last_error)
        })
    }

    /// Subscribe to blob stream with deterministic fallback logic.
    ///
    /// ## Behavior (DETERMINISTIC, FIXED ORDER)
    ///
    /// 1. Try `current_source` first
    /// 2. If subscription fails, try remaining sources in fixed priority order:
    ///    Primary → Secondary → Emergency (skipping already tried)
    /// 3. On success from fallback source:
    ///    - Update `current_source` atomically via RwLock
    ///    - Return the stream
    /// 4. If ALL sources fail:
    ///    - Return the last error encountered
    ///    - NO panic, NO silent failure
    ///
    /// ## Important Note on Mid-Stream Failures
    ///
    /// This method handles fallback at subscription time only.
    /// If the returned stream fails mid-stream (during polling),
    /// the caller is responsible for:
    /// 1. Handling the error from the stream
    /// 2. Calling `subscribe_blobs` again to get a new stream
    ///
    /// The subsequent call will use the current (possibly updated) source.
    ///
    /// ## Thread Safety
    ///
    /// - `current_source` read/write uses RwLock
    /// - Lock NOT held during async I/O operations
    ///
    /// # Arguments
    ///
    /// * `from_height` - Optional height to start subscription from
    ///
    /// # Returns
    ///
    /// * `Ok(BlobStream)` - Stream of blobs on success
    /// * `Err(DAError)` - Last error if all sources fail
    ///
    /// # Example
    ///
    /// ```ignore
    /// let stream = source.subscribe_blobs(Some(100)).await?;
    /// while let Some(result) = stream.next().await {
    ///     match result {
    ///         Ok(blob) => { /* process blob */ }
    ///         Err(e) => {
    ///             // Handle error, possibly re-subscribe
    ///             stream = source.subscribe_blobs(Some(last_height)).await?;
    ///         }
    ///     }
    /// }
    /// ```
    pub fn subscribe_blobs<'a>(
        &'a self,
        from_height: Option<u64>,
    ) -> Pin<Box<dyn Future<Output = Result<BlobStream, DAError>> + Send + 'a>> {
        Box::pin(async move {
            // Read current_source (RwLock read, released immediately)
            let current = self.get_current_source();

            // Try current source first
            if let Some(da) = self.get_da_for_source(current) {
                match da.subscribe_blobs(from_height).await {
                    Ok(stream) => return Ok(stream),
                    Err(_e) => {
                        // Current source failed, continue to fallback
                    }
                }
            }

            // Fallback: try remaining sources in fixed priority order
            let mut last_error = DAError::Unavailable;

            for &source_type in &FALLBACK_PRIORITY_ORDER {
                // Skip if we already tried this source
                if source_type == current {
                    continue;
                }

                // Try this source if configured
                if let Some(da) = self.get_da_for_source(source_type) {
                    match da.subscribe_blobs(from_height).await {
                        Ok(stream) => {
                            // Success! Update current_source (RwLock write)
                            self.set_current_source(source_type);
                            return Ok(stream);
                        }
                        Err(e) => {
                            // Track error and continue to next source
                            last_error = e;
                        }
                    }
                }
            }

            // All sources failed - return last error
            Err(last_error)
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use dsdn_common::DAHealthStatus;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    // ────────────────────────────────────────────────────────────────────────────
    // Test Mock: Configurable DA Layer
    // ────────────────────────────────────────────────────────────────────────────

    /// Mock DA layer with configurable success/failure behavior.
    struct MockDALayer {
        #[allow(dead_code)]
        name: String,
        /// Whether operations should succeed
        should_succeed: AtomicBool,
        /// Data to return on get_blob success
        blob_data: Vec<u8>,
        /// Counter for get_blob calls
        get_blob_calls: AtomicU32,
        /// Counter for subscribe_blobs calls
        subscribe_calls: AtomicU32,
    }

    impl MockDALayer {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                should_succeed: AtomicBool::new(true),
                blob_data: vec![1, 2, 3, 4],
                get_blob_calls: AtomicU32::new(0),
                subscribe_calls: AtomicU32::new(0),
            }
        }

        fn new_failing(name: &str) -> Self {
            Self {
                name: name.to_string(),
                should_succeed: AtomicBool::new(false),
                blob_data: vec![],
                get_blob_calls: AtomicU32::new(0),
                subscribe_calls: AtomicU32::new(0),
            }
        }

        fn new_with_data(name: &str, data: Vec<u8>) -> Self {
            Self {
                name: name.to_string(),
                should_succeed: AtomicBool::new(true),
                blob_data: data,
                get_blob_calls: AtomicU32::new(0),
                subscribe_calls: AtomicU32::new(0),
            }
        }

        fn get_blob_call_count(&self) -> u32 {
            self.get_blob_calls.load(Ordering::SeqCst)
        }

        fn get_subscribe_call_count(&self) -> u32 {
            self.subscribe_calls.load(Ordering::SeqCst)
        }
    }

    impl DALayer for MockDALayer {
        fn post_blob(
            &self,
            _data: &[u8],
        ) -> Pin<Box<dyn Future<Output = Result<BlobRef, DAError>> + Send + '_>> {
            Box::pin(async move {
                Ok(BlobRef {
                    height: 1,
                    commitment: [0u8; 32],
                    namespace: [0u8; 29],
                })
            })
        }

        fn get_blob(
            &self,
            _ref_: &BlobRef,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>> {
            self.get_blob_calls.fetch_add(1, Ordering::SeqCst);
            let should_succeed = self.should_succeed.load(Ordering::SeqCst);
            let data = self.blob_data.clone();

            Box::pin(async move {
                if should_succeed {
                    Ok(data)
                } else {
                    Err(DAError::Unavailable)
                }
            })
        }

        fn subscribe_blobs(
            &self,
            _from_height: Option<u64>,
        ) -> Pin<Box<dyn Future<Output = Result<BlobStream, DAError>> + Send + '_>> {
            self.subscribe_calls.fetch_add(1, Ordering::SeqCst);
            let should_succeed = self.should_succeed.load(Ordering::SeqCst);

            Box::pin(async move {
                if should_succeed {
                    // Return empty stream for testing
                    let stream: BlobStream = Box::pin(futures::stream::empty());
                    Ok(stream)
                } else {
                    Err(DAError::Unavailable)
                }
            })
        }

        fn health_check(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<DAHealthStatus, DAError>> + Send + '_>> {
            Box::pin(async move {
                Ok(DAHealthStatus::Healthy)
            })
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DASourceType Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_da_source_type_default() {
        let source_type = DASourceType::default();
        assert_eq!(source_type, DASourceType::Primary);
    }

    #[test]
    fn test_da_source_type_display() {
        assert_eq!(format!("{}", DASourceType::Primary), "Primary");
        assert_eq!(format!("{}", DASourceType::Secondary), "Secondary");
        assert_eq!(format!("{}", DASourceType::Emergency), "Emergency");
    }

    #[test]
    fn test_da_source_type_equality() {
        assert_eq!(DASourceType::Primary, DASourceType::Primary);
        assert_ne!(DASourceType::Primary, DASourceType::Secondary);
        assert_ne!(DASourceType::Secondary, DASourceType::Emergency);
    }

    #[test]
    fn test_da_source_type_clone() {
        let original = DASourceType::Secondary;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // MultiDAConfig Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_multi_da_config_default() {
        let config = MultiDAConfig::default();
        assert!(config.auto_fallback_enabled);
        assert!(config.prefer_primary);
    }

    #[test]
    fn test_multi_da_config_new() {
        let config = MultiDAConfig::new();
        assert!(config.auto_fallback_enabled);
        assert!(config.prefer_primary);
    }

    #[test]
    fn test_multi_da_config_no_auto_fallback() {
        let config = MultiDAConfig::no_auto_fallback();
        assert!(!config.auto_fallback_enabled);
        assert!(config.prefer_primary);
    }

    #[test]
    fn test_multi_da_config_clone() {
        let config = MultiDAConfig {
            auto_fallback_enabled: false,
            prefer_primary: false,
        };
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // MultiDASource Creation Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_multi_da_source_new_primary_only() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let source = MultiDASource::new(primary);

        assert_eq!(source.get_current_source(), DASourceType::Primary);
        assert!(!source.has_secondary());
        assert!(!source.has_emergency());
        assert!(source.is_auto_fallback_enabled());
        assert!(source.is_prefer_primary());
    }

    #[test]
    fn test_multi_da_source_with_fallbacks_all() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let secondary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("secondary"));
        let emergency: Arc<dyn DALayer> = Arc::new(MockDALayer::new("emergency"));

        let source = MultiDASource::with_fallbacks(
            primary,
            Some(secondary),
            Some(emergency),
            MultiDAConfig::default(),
        );

        assert_eq!(source.get_current_source(), DASourceType::Primary);
        assert!(source.has_secondary());
        assert!(source.has_emergency());
    }

    #[test]
    fn test_multi_da_source_with_fallbacks_secondary_only() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let secondary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("secondary"));

        let source = MultiDASource::with_fallbacks(
            primary,
            Some(secondary),
            None,
            MultiDAConfig::default(),
        );

        assert!(source.has_secondary());
        assert!(!source.has_emergency());
    }

    #[test]
    fn test_multi_da_source_with_fallbacks_emergency_only() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let emergency: Arc<dyn DALayer> = Arc::new(MockDALayer::new("emergency"));

        let source = MultiDASource::with_fallbacks(
            primary,
            None,
            Some(emergency),
            MultiDAConfig::default(),
        );

        assert!(!source.has_secondary());
        assert!(source.has_emergency());
    }

    #[test]
    fn test_multi_da_source_with_custom_config() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let config = MultiDAConfig::no_auto_fallback();

        let source = MultiDASource::with_fallbacks(
            primary,
            None,
            None,
            config,
        );

        assert!(!source.is_auto_fallback_enabled());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Source Switching Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_multi_da_source_set_current_source() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let source = MultiDASource::new(primary);

        assert_eq!(source.get_current_source(), DASourceType::Primary);

        let changed = source.set_current_source(DASourceType::Secondary);
        assert!(changed);
        assert_eq!(source.get_current_source(), DASourceType::Secondary);

        let changed = source.set_current_source(DASourceType::Emergency);
        assert!(changed);
        assert_eq!(source.get_current_source(), DASourceType::Emergency);

        let changed = source.set_current_source(DASourceType::Emergency);
        assert!(!changed);
        assert_eq!(source.get_current_source(), DASourceType::Emergency);

        let changed = source.set_current_source(DASourceType::Primary);
        assert!(changed);
        assert_eq!(source.get_current_source(), DASourceType::Primary);
    }

    #[test]
    fn test_multi_da_source_get_active_da_primary() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let source = MultiDASource::new(Arc::clone(&primary));

        let active = source.get_active_da();
        assert!(source.get_current_source() == DASourceType::Primary);
        drop(active);
    }

    #[test]
    fn test_multi_da_source_get_active_da_secondary() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let secondary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("secondary"));

        let source = MultiDASource::with_fallbacks(
            primary,
            Some(secondary),
            None,
            MultiDAConfig::default(),
        );

        source.set_current_source(DASourceType::Secondary);
        let active = source.get_active_da();
        assert!(source.get_current_source() == DASourceType::Secondary);
        drop(active);
    }

    #[test]
    fn test_multi_da_source_get_active_da_fallback_to_primary() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));

        let source = MultiDASource::new(primary);

        source.set_current_source(DASourceType::Secondary);
        let _active = source.get_active_da();
    }

    #[test]
    fn test_multi_da_source_get_active_da_emergency_fallback_chain() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let secondary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("secondary"));

        let source = MultiDASource::with_fallbacks(
            primary,
            Some(secondary),
            None,
            MultiDAConfig::default(),
        );

        source.set_current_source(DASourceType::Emergency);
        let _active = source.get_active_da();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // get_da_for_source Tests (14A.1A.42)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_get_da_for_source_primary_always_exists() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let source = MultiDASource::new(primary);

        assert!(source.get_da_for_source(DASourceType::Primary).is_some());
        assert!(source.get_da_for_source(DASourceType::Secondary).is_none());
        assert!(source.get_da_for_source(DASourceType::Emergency).is_none());
    }

    #[test]
    fn test_get_da_for_source_all_configured() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let secondary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("secondary"));
        let emergency: Arc<dyn DALayer> = Arc::new(MockDALayer::new("emergency"));

        let source = MultiDASource::with_fallbacks(
            primary,
            Some(secondary),
            Some(emergency),
            MultiDAConfig::default(),
        );

        assert!(source.get_da_for_source(DASourceType::Primary).is_some());
        assert!(source.get_da_for_source(DASourceType::Secondary).is_some());
        assert!(source.get_da_for_source(DASourceType::Emergency).is_some());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // get_blob Fallback Tests (14A.1A.42)
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_blob_primary_success() {
        let primary = Arc::new(MockDALayer::new_with_data("primary", vec![10, 20, 30]));
        let primary_da: Arc<dyn DALayer> = primary.clone();
        let source = MultiDASource::new(primary_da);

        let blob_ref = BlobRef {
            height: 1,
            commitment: [0u8; 32],
            namespace: [0u8; 29],
        };

        let result = source.get_blob(&blob_ref).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![10, 20, 30]);
        assert_eq!(source.get_current_source(), DASourceType::Primary);
        assert_eq!(primary.get_blob_call_count(), 1);
    }

    #[tokio::test]
    async fn test_get_blob_fallback_primary_to_secondary() {
        let primary = Arc::new(MockDALayer::new_failing("primary"));
        let secondary = Arc::new(MockDALayer::new_with_data("secondary", vec![40, 50, 60]));

        let primary_da: Arc<dyn DALayer> = primary.clone();
        let secondary_da: Arc<dyn DALayer> = secondary.clone();

        let source = MultiDASource::with_fallbacks(
            primary_da,
            Some(secondary_da),
            None,
            MultiDAConfig::default(),
        );

        let blob_ref = BlobRef {
            height: 1,
            commitment: [0u8; 32],
            namespace: [0u8; 29],
        };

        let result = source.get_blob(&blob_ref).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![40, 50, 60]);
        // current_source should be updated to Secondary
        assert_eq!(source.get_current_source(), DASourceType::Secondary);
        assert_eq!(primary.get_blob_call_count(), 1);
        assert_eq!(secondary.get_blob_call_count(), 1);
    }

    #[tokio::test]
    async fn test_get_blob_fallback_primary_to_emergency() {
        let primary = Arc::new(MockDALayer::new_failing("primary"));
        let secondary = Arc::new(MockDALayer::new_failing("secondary"));
        let emergency = Arc::new(MockDALayer::new_with_data("emergency", vec![70, 80, 90]));

        let primary_da: Arc<dyn DALayer> = primary.clone();
        let secondary_da: Arc<dyn DALayer> = secondary.clone();
        let emergency_da: Arc<dyn DALayer> = emergency.clone();

        let source = MultiDASource::with_fallbacks(
            primary_da,
            Some(secondary_da),
            Some(emergency_da),
            MultiDAConfig::default(),
        );

        let blob_ref = BlobRef {
            height: 1,
            commitment: [0u8; 32],
            namespace: [0u8; 29],
        };

        let result = source.get_blob(&blob_ref).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![70, 80, 90]);
        assert_eq!(source.get_current_source(), DASourceType::Emergency);
        assert_eq!(primary.get_blob_call_count(), 1);
        assert_eq!(secondary.get_blob_call_count(), 1);
        assert_eq!(emergency.get_blob_call_count(), 1);
    }

    #[tokio::test]
    async fn test_get_blob_all_sources_fail() {
        let primary = Arc::new(MockDALayer::new_failing("primary"));
        let secondary = Arc::new(MockDALayer::new_failing("secondary"));
        let emergency = Arc::new(MockDALayer::new_failing("emergency"));

        let primary_da: Arc<dyn DALayer> = primary.clone();
        let secondary_da: Arc<dyn DALayer> = secondary.clone();
        let emergency_da: Arc<dyn DALayer> = emergency.clone();

        let source = MultiDASource::with_fallbacks(
            primary_da,
            Some(secondary_da),
            Some(emergency_da),
            MultiDAConfig::default(),
        );

        let blob_ref = BlobRef {
            height: 1,
            commitment: [0u8; 32],
            namespace: [0u8; 29],
        };

        let result = source.get_blob(&blob_ref).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), DAError::Unavailable);
        // current_source should remain unchanged
        assert_eq!(source.get_current_source(), DASourceType::Primary);
    }

    #[tokio::test]
    async fn test_get_blob_fallback_from_secondary_to_primary() {
        // Start with current_source = Secondary (failing)
        // Should fallback to Primary (working)
        let primary = Arc::new(MockDALayer::new_with_data("primary", vec![100, 200]));
        let secondary = Arc::new(MockDALayer::new_failing("secondary"));

        let primary_da: Arc<dyn DALayer> = primary.clone();
        let secondary_da: Arc<dyn DALayer> = secondary.clone();

        let source = MultiDASource::with_fallbacks(
            primary_da,
            Some(secondary_da),
            None,
            MultiDAConfig::default(),
        );

        // Set current to Secondary
        source.set_current_source(DASourceType::Secondary);
        assert_eq!(source.get_current_source(), DASourceType::Secondary);

        let blob_ref = BlobRef {
            height: 1,
            commitment: [0u8; 32],
            namespace: [0u8; 29],
        };

        let result = source.get_blob(&blob_ref).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![100, 200]);
        // Should have fallen back to Primary
        assert_eq!(source.get_current_source(), DASourceType::Primary);
    }

    #[tokio::test]
    async fn test_get_blob_no_duplicate_calls() {
        // Ensure we don't call the same source twice
        let primary = Arc::new(MockDALayer::new_with_data("primary", vec![1, 2, 3]));
        let primary_da: Arc<dyn DALayer> = primary.clone();

        let source = MultiDASource::new(primary_da);

        let blob_ref = BlobRef {
            height: 1,
            commitment: [0u8; 32],
            namespace: [0u8; 29],
        };

        let _ = source.get_blob(&blob_ref).await;

        // Primary should only be called once
        assert_eq!(primary.get_blob_call_count(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // subscribe_blobs Fallback Tests (14A.1A.42)
    // ────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_subscribe_blobs_primary_success() {
        let primary = Arc::new(MockDALayer::new("primary"));
        let primary_da: Arc<dyn DALayer> = primary.clone();

        let source = MultiDASource::new(primary_da);

        let result = source.subscribe_blobs(None).await;

        assert!(result.is_ok());
        assert_eq!(source.get_current_source(), DASourceType::Primary);
        assert_eq!(primary.get_subscribe_call_count(), 1);
    }

    #[tokio::test]
    async fn test_subscribe_blobs_fallback_to_secondary() {
        let primary = Arc::new(MockDALayer::new_failing("primary"));
        let secondary = Arc::new(MockDALayer::new("secondary"));

        let primary_da: Arc<dyn DALayer> = primary.clone();
        let secondary_da: Arc<dyn DALayer> = secondary.clone();

        let source = MultiDASource::with_fallbacks(
            primary_da,
            Some(secondary_da),
            None,
            MultiDAConfig::default(),
        );

        let result = source.subscribe_blobs(Some(100)).await;

        assert!(result.is_ok());
        assert_eq!(source.get_current_source(), DASourceType::Secondary);
        assert_eq!(primary.get_subscribe_call_count(), 1);
        assert_eq!(secondary.get_subscribe_call_count(), 1);
    }

    #[tokio::test]
    async fn test_subscribe_blobs_fallback_to_emergency() {
        let primary = Arc::new(MockDALayer::new_failing("primary"));
        let secondary = Arc::new(MockDALayer::new_failing("secondary"));
        let emergency = Arc::new(MockDALayer::new("emergency"));

        let primary_da: Arc<dyn DALayer> = primary.clone();
        let secondary_da: Arc<dyn DALayer> = secondary.clone();
        let emergency_da: Arc<dyn DALayer> = emergency.clone();

        let source = MultiDASource::with_fallbacks(
            primary_da,
            Some(secondary_da),
            Some(emergency_da),
            MultiDAConfig::default(),
        );

        let result = source.subscribe_blobs(None).await;

        assert!(result.is_ok());
        assert_eq!(source.get_current_source(), DASourceType::Emergency);
    }

    #[tokio::test]
    async fn test_subscribe_blobs_all_fail() {
        let primary = Arc::new(MockDALayer::new_failing("primary"));
        let secondary = Arc::new(MockDALayer::new_failing("secondary"));
        let emergency = Arc::new(MockDALayer::new_failing("emergency"));

        let primary_da: Arc<dyn DALayer> = primary.clone();
        let secondary_da: Arc<dyn DALayer> = secondary.clone();
        let emergency_da: Arc<dyn DALayer> = emergency.clone();

        let source = MultiDASource::with_fallbacks(
            primary_da,
            Some(secondary_da),
            Some(emergency_da),
            MultiDAConfig::default(),
        );

        let result = source.subscribe_blobs(None).await;

        assert!(result.is_err());
        // Use pattern matching because BlobStream doesn't implement Debug
        // which is required by unwrap_err()
        if let Err(e) = result {
            assert_eq!(e, DAError::Unavailable);
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Thread Safety Tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_multi_da_source_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MultiDASource>();
        assert_send_sync::<DASourceType>();
        assert_send_sync::<MultiDAConfig>();
    }

    #[test]
    fn test_multi_da_source_concurrent_source_switching() {
        use std::thread;

        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let source = Arc::new(MultiDASource::new(primary));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let source = Arc::clone(&source);
                thread::spawn(move || {
                    if i % 2 == 0 {
                        let _ = source.get_current_source();
                    } else {
                        let source_type = match i % 3 {
                            0 => DASourceType::Primary,
                            1 => DASourceType::Secondary,
                            _ => DASourceType::Emergency,
                        };
                        source.set_current_source(source_type);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread should not panic");
        }
    }

    #[tokio::test]
    async fn test_get_blob_concurrent_calls() {
        let primary = Arc::new(MockDALayer::new_with_data("primary", vec![1, 2, 3]));
        let primary_da: Arc<dyn DALayer> = primary.clone();

        let source = Arc::new(MultiDASource::new(primary_da));

        let blob_ref = BlobRef {
            height: 1,
            commitment: [0u8; 32],
            namespace: [0u8; 29],
        };

        // Spawn multiple concurrent get_blob calls
        let mut handles = Vec::new();
        for _ in 0..5 {
            let source = Arc::clone(&source);
            let blob_ref = blob_ref.clone();
            handles.push(tokio::spawn(async move {
                source.get_blob(&blob_ref).await
            }));
        }

        // All should succeed
        for handle in handles {
            let result = handle.await.expect("Task should not panic");
            assert!(result.is_ok());
        }

        // Primary should have been called 5 times
        assert_eq!(primary.get_blob_call_count(), 5);
    }
}
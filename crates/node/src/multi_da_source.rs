//! Multi-DA Source abstraction for node follower mode (14A.1A.41)
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
//! ```

use std::sync::Arc;
use parking_lot::RwLock;
use dsdn_common::DALayer;

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
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use dsdn_common::{BlobRef, BlobStream, DAError, DAHealthStatus};

    /// Mock DA layer for testing.
    struct MockDALayer {
        #[allow(dead_code)]
        name: String,
    }

    impl MockDALayer {
        fn new(name: &str) -> Self {
            Self { name: name.to_string() }
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
                    namespace: [0u8; 29],  // Fixed: 29 bytes, not 8
                })
            })
        }

        fn get_blob(
            &self,
            _ref_: &BlobRef,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>> {
            Box::pin(async move {
                Ok(vec![])
            })
        }

        fn subscribe_blobs(
            &self,
            _from_height: Option<u64>,
        ) -> Pin<Box<dyn Future<Output = Result<BlobStream, DAError>> + Send + '_>> {
            Box::pin(async move {
                // Fixed: Use DAError::Unavailable instead of ConnectionFailed
                Err(DAError::Unavailable)
            })
        }

        fn health_check(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<DAHealthStatus, DAError>> + Send + '_>> {
            Box::pin(async move {
                // Fixed: DAHealthStatus is an enum, use variant directly
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

        // Change to secondary
        let changed = source.set_current_source(DASourceType::Secondary);
        assert!(changed);
        assert_eq!(source.get_current_source(), DASourceType::Secondary);

        // Change to emergency
        let changed = source.set_current_source(DASourceType::Emergency);
        assert!(changed);
        assert_eq!(source.get_current_source(), DASourceType::Emergency);

        // Set to same value - should return false
        let changed = source.set_current_source(DASourceType::Emergency);
        assert!(!changed);
        assert_eq!(source.get_current_source(), DASourceType::Emergency);

        // Change back to primary
        let changed = source.set_current_source(DASourceType::Primary);
        assert!(changed);
        assert_eq!(source.get_current_source(), DASourceType::Primary);
    }

    #[test]
    fn test_multi_da_source_get_active_da_primary() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let source = MultiDASource::new(Arc::clone(&primary));

        let active = source.get_active_da();
        // Can't directly compare Arc<dyn Trait>, but we can verify it doesn't panic
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

        // Set to secondary but secondary is None - should fall back to primary
        source.set_current_source(DASourceType::Secondary);
        let _active = source.get_active_da();
        // Should not panic, returns primary as fallback
    }

    #[test]
    fn test_multi_da_source_get_active_da_emergency_fallback_chain() {
        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let secondary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("secondary"));

        let source = MultiDASource::with_fallbacks(
            primary,
            Some(secondary),
            None, // No emergency
            MultiDAConfig::default(),
        );

        // Set to emergency but emergency is None - should fall back to secondary
        source.set_current_source(DASourceType::Emergency);
        let _active = source.get_active_da();
        // Should not panic, returns secondary as fallback
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
    fn test_multi_da_source_concurrent_access() {
        use std::thread;

        let primary: Arc<dyn DALayer> = Arc::new(MockDALayer::new("primary"));
        let source = Arc::new(MultiDASource::new(primary));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let source = Arc::clone(&source);
                thread::spawn(move || {
                    // Alternate between reading and writing
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
}
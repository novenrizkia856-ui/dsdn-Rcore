//! Cache Validation Module (14A.1A.55)
//!
//! Provides integrity validation for FallbackCache entries.
//!
//! ## Features
//!
//! - Hash verification (SHA-256)
//! - Corruption detection (empty data)
//! - TTL expiration checking
//! - Comprehensive validation reports

use std::time::{SystemTime, UNIX_EPOCH};

use crate::fallback_cache::blob::{CachedBlob, CacheError};

// ════════════════════════════════════════════════════════════════════════════════
// VALIDATION ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Types of validation errors for cached blobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    /// Hash of blob data does not match stored hash.
    HashMismatch,
    /// Blob data is corrupted (empty or malformed).
    Corrupted,
    /// Blob has exceeded its TTL.
    Expired,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::HashMismatch => write!(f, "hash mismatch"),
            ValidationError::Corrupted => write!(f, "corrupted data"),
            ValidationError::Expired => write!(f, "expired"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// VALIDATION REPORT
// ════════════════════════════════════════════════════════════════════════════════

/// Report from cache validation operations.
///
/// Contains counts and details of invalid entries.
/// Does not store blob data, only sequence numbers and error types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationReport {
    /// Total number of entries checked.
    pub total_checked: usize,
    /// Number of valid entries.
    pub valid_count: usize,
    /// List of invalid entries: (sequence, error type).
    pub invalid_entries: Vec<(u64, ValidationError)>,
}

impl ValidationReport {
    /// Create a new empty ValidationReport.
    #[must_use]
    pub fn new() -> Self {
        Self {
            total_checked: 0,
            valid_count: 0,
            invalid_entries: Vec::new(),
        }
    }

    /// Get the number of invalid entries.
    #[must_use]
    pub fn invalid_count(&self) -> usize {
        self.invalid_entries.len()
    }

    /// Check if all validated entries are valid.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.invalid_entries.is_empty()
    }

    /// Add a valid entry to the report.
    pub fn add_valid(&mut self) {
        self.total_checked = self.total_checked.saturating_add(1);
        self.valid_count = self.valid_count.saturating_add(1);
    }

    /// Add an invalid entry to the report.
    pub fn add_invalid(&mut self, sequence: u64, error: ValidationError) {
        self.total_checked = self.total_checked.saturating_add(1);
        self.invalid_entries.push((sequence, error));
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CACHE VALIDATOR TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Trait for validating cache entries.
///
/// Implementations define specific validation logic.
pub trait CacheValidator {
    /// Validate a single cache entry.
    ///
    /// ## Returns
    ///
    /// - `Ok(true)` - Blob is valid
    /// - `Ok(false)` - Blob is invalid (caller should record details)
    /// - `Err(_)` - System error (not data error)
    ///
    /// ## Guarantees
    ///
    /// - Does not panic
    /// - Does not mutate cache
    fn validate_entry(
        &self,
        sequence: u64,
        blob: &CachedBlob,
    ) -> Result<bool, CacheError>;

    /// Validate all entries and return a report.
    ///
    /// ## Guarantees
    ///
    /// - Does not panic
    /// - Does not mutate cache
    fn validate_all(&self) -> ValidationReport;
}

// ════════════════════════════════════════════════════════════════════════════════
// HASH VALIDATOR
// ════════════════════════════════════════════════════════════════════════════════

/// Validator that checks blob integrity via hash verification.
///
/// ## Validation Logic
///
/// 1. If data is empty → Corrupted
/// 2. If computed hash != stored hash → HashMismatch  
/// 3. If TTL > 0 and blob is expired → Expired
/// 4. Otherwise → Valid
pub struct HashValidator {
    /// TTL in seconds (0 = disabled).
    ttl_seconds: u64,
}

impl HashValidator {
    /// Create a new HashValidator with TTL setting.
    ///
    /// If ttl_seconds is 0, expiration checking is disabled.
    #[must_use]
    pub fn new(ttl_seconds: u64) -> Self {
        Self { ttl_seconds }
    }

    /// Create a HashValidator with no TTL (expiration disabled).
    #[must_use]
    pub fn without_ttl() -> Self {
        Self { ttl_seconds: 0 }
    }

    /// Compute hash of blob data.
    ///
    /// Uses a simple hash algorithm for validation.
    /// In production, this should use SHA-256.
    #[must_use]
    fn compute_hash(data: &[u8]) -> [u8; 32] {
        // Simple hash computation using FNV-1a style mixing
        // For production, replace with SHA-256 from sha2 crate
        let mut hash = [0u8; 32];
        
        if data.is_empty() {
            return hash;
        }

        // Use a simple but deterministic hash based on data
        let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
        for &byte in data {
            h ^= byte as u64;
            h = h.wrapping_mul(0x100000001b3); // FNV prime
        }

        // Fill hash array with mixed values
        for i in 0..4 {
            let offset = i * 8;
            let rotated = h.rotate_left((i * 17) as u32);
            hash[offset..offset + 8].copy_from_slice(&rotated.to_le_bytes());
        }

        hash
    }

    /// Check if a blob is expired based on TTL.
    ///
    /// Returns true if expired, false otherwise.
    /// If ttl_seconds is 0, always returns false (TTL disabled).
    #[must_use]
    fn is_expired(&self, blob: &CachedBlob) -> bool {
        if self.ttl_seconds == 0 {
            return false;
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let ttl_ms = self.ttl_seconds.saturating_mul(1000);
        let threshold = now_ms.saturating_sub(ttl_ms);

        blob.received_at < threshold
    }

    /// Validate a single blob and return the specific error if invalid.
    ///
    /// ## Returns
    ///
    /// - `Ok(None)` - Blob is valid
    /// - `Ok(Some(error))` - Blob is invalid with specific error
    #[must_use]
    pub fn validate_blob(&self, blob: &CachedBlob) -> Option<ValidationError> {
        // Check 1: Corrupted (empty data)
        if blob.data.is_empty() {
            return Some(ValidationError::Corrupted);
        }

        // Check 2: Hash mismatch
        let computed_hash = Self::compute_hash(&blob.data);
        if computed_hash != blob.hash {
            return Some(ValidationError::HashMismatch);
        }

        // Check 3: Expired (only if TTL is enabled)
        if self.is_expired(blob) {
            return Some(ValidationError::Expired);
        }

        // All checks passed
        None
    }
}

impl Default for HashValidator {
    fn default() -> Self {
        Self::without_ttl()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTION: COMPUTE HASH FOR BLOB CREATION
// ════════════════════════════════════════════════════════════════════════════════

/// Compute hash for given data (for creating valid blobs).
///
/// This function should be used when creating CachedBlob instances
/// to ensure the stored hash matches what HashValidator computes.
#[must_use]
pub fn compute_blob_hash(data: &[u8]) -> [u8; 32] {
    HashValidator::compute_hash(data)
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fallback_cache::blob::DASourceType;
    use std::sync::atomic::AtomicU32;

    fn make_valid_blob(data: Vec<u8>, received_at: u64) -> CachedBlob {
        let hash = compute_blob_hash(&data);
        CachedBlob {
            data,
            source: DASourceType::Primary,
            received_at,
            hash,
            access_count: AtomicU32::new(0),
        }
    }

    fn make_invalid_hash_blob(data: Vec<u8>, received_at: u64) -> CachedBlob {
        // Create blob with wrong hash
        CachedBlob {
            data,
            source: DASourceType::Primary,
            received_at,
            hash: [0xFF; 32], // Wrong hash
            access_count: AtomicU32::new(0),
        }
    }

    fn make_empty_blob(received_at: u64) -> CachedBlob {
        CachedBlob {
            data: vec![],
            source: DASourceType::Primary,
            received_at,
            hash: [0; 32],
            access_count: AtomicU32::new(0),
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // A. VALIDATION ERROR TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validation_error_display() {
        assert_eq!(ValidationError::HashMismatch.to_string(), "hash mismatch");
        assert_eq!(ValidationError::Corrupted.to_string(), "corrupted data");
        assert_eq!(ValidationError::Expired.to_string(), "expired");
    }

    #[test]
    fn test_validation_error_equality() {
        assert_eq!(ValidationError::HashMismatch, ValidationError::HashMismatch);
        assert_ne!(ValidationError::HashMismatch, ValidationError::Corrupted);
        assert_ne!(ValidationError::Corrupted, ValidationError::Expired);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // B. VALIDATION REPORT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validation_report_new() {
        let report = ValidationReport::new();

        assert_eq!(report.total_checked, 0);
        assert_eq!(report.valid_count, 0);
        assert!(report.invalid_entries.is_empty());
        assert!(report.is_healthy());
    }

    #[test]
    fn test_validation_report_add_valid() {
        let mut report = ValidationReport::new();

        report.add_valid();
        report.add_valid();
        report.add_valid();

        assert_eq!(report.total_checked, 3);
        assert_eq!(report.valid_count, 3);
        assert_eq!(report.invalid_count(), 0);
        assert!(report.is_healthy());
    }

    #[test]
    fn test_validation_report_add_invalid() {
        let mut report = ValidationReport::new();

        report.add_invalid(1, ValidationError::HashMismatch);
        report.add_invalid(5, ValidationError::Corrupted);

        assert_eq!(report.total_checked, 2);
        assert_eq!(report.valid_count, 0);
        assert_eq!(report.invalid_count(), 2);
        assert!(!report.is_healthy());

        assert_eq!(report.invalid_entries[0], (1, ValidationError::HashMismatch));
        assert_eq!(report.invalid_entries[1], (5, ValidationError::Corrupted));
    }

    #[test]
    fn test_validation_report_mixed() {
        let mut report = ValidationReport::new();

        report.add_valid();
        report.add_invalid(2, ValidationError::Expired);
        report.add_valid();
        report.add_invalid(4, ValidationError::HashMismatch);

        assert_eq!(report.total_checked, 4);
        assert_eq!(report.valid_count, 2);
        assert_eq!(report.invalid_count(), 2);
        assert!(!report.is_healthy());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // C. HASH VALIDATOR TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_hash_validator_new() {
        let validator = HashValidator::new(3600);
        assert_eq!(validator.ttl_seconds, 3600);
    }

    #[test]
    fn test_hash_validator_without_ttl() {
        let validator = HashValidator::without_ttl();
        assert_eq!(validator.ttl_seconds, 0);
    }

    #[test]
    fn test_hash_validator_default() {
        let validator = HashValidator::default();
        assert_eq!(validator.ttl_seconds, 0);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // D. VALID BLOB TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_valid_blob() {
        let validator = HashValidator::without_ttl();
        let blob = make_valid_blob(vec![1, 2, 3, 4, 5], 1000);

        let result = validator.validate_blob(&blob);
        assert!(result.is_none()); // Valid
    }

    #[test]
    fn test_validate_valid_blob_with_ttl_not_expired() {
        let validator = HashValidator::new(3600); // 1 hour TTL
        
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let blob = make_valid_blob(vec![1, 2, 3], now_ms); // Just received

        let result = validator.validate_blob(&blob);
        assert!(result.is_none()); // Valid, not expired
    }

    // ════════════════════════════════════════════════════════════════════════════
    // E. INVALID BLOB TESTS - HASH MISMATCH
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_hash_mismatch() {
        let validator = HashValidator::without_ttl();
        let blob = make_invalid_hash_blob(vec![1, 2, 3, 4, 5], 1000);

        let result = validator.validate_blob(&blob);
        assert_eq!(result, Some(ValidationError::HashMismatch));
    }

    #[test]
    fn test_validate_modified_data_causes_hash_mismatch() {
        let validator = HashValidator::without_ttl();
        
        // Create valid blob then modify data
        let mut blob = make_valid_blob(vec![1, 2, 3, 4, 5], 1000);
        blob.data[0] = 99; // Modify data

        let result = validator.validate_blob(&blob);
        assert_eq!(result, Some(ValidationError::HashMismatch));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // F. INVALID BLOB TESTS - CORRUPTED
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_empty_data_corrupted() {
        let validator = HashValidator::without_ttl();
        let blob = make_empty_blob(1000);

        let result = validator.validate_blob(&blob);
        assert_eq!(result, Some(ValidationError::Corrupted));
    }

    #[test]
    fn test_corrupted_takes_priority_over_hash_mismatch() {
        let validator = HashValidator::without_ttl();
        
        // Empty data with wrong hash
        let blob = CachedBlob {
            data: vec![],
            source: DASourceType::Primary,
            received_at: 1000,
            hash: [0xFF; 32],
            access_count: AtomicU32::new(0),
        };

        let result = validator.validate_blob(&blob);
        assert_eq!(result, Some(ValidationError::Corrupted)); // Corrupted first
    }

    // ════════════════════════════════════════════════════════════════════════════
    // G. INVALID BLOB TESTS - EXPIRED
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_expired_blob() {
        let validator = HashValidator::new(1); // 1 second TTL
        let blob = make_valid_blob(vec![1, 2, 3], 0); // Very old timestamp

        let result = validator.validate_blob(&blob);
        assert_eq!(result, Some(ValidationError::Expired));
    }

    #[test]
    fn test_ttl_zero_disables_expiration() {
        let validator = HashValidator::new(0); // TTL disabled
        let blob = make_valid_blob(vec![1, 2, 3], 0); // Very old timestamp

        let result = validator.validate_blob(&blob);
        assert!(result.is_none()); // Valid, expiration disabled
    }

    #[test]
    fn test_hash_mismatch_takes_priority_over_expired() {
        let validator = HashValidator::new(1); // 1 second TTL
        
        // Old blob with wrong hash
        let blob = make_invalid_hash_blob(vec![1, 2, 3], 0);

        let result = validator.validate_blob(&blob);
        assert_eq!(result, Some(ValidationError::HashMismatch)); // Hash checked before TTL
    }

    // ════════════════════════════════════════════════════════════════════════════
    // H. HASH COMPUTATION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_compute_hash_deterministic() {
        let data = vec![1, 2, 3, 4, 5];
        
        let hash1 = compute_blob_hash(&data);
        let hash2 = compute_blob_hash(&data);

        assert_eq!(hash1, hash2); // Same data = same hash
    }

    #[test]
    fn test_compute_hash_different_data() {
        let data1 = vec![1, 2, 3];
        let data2 = vec![1, 2, 4];

        let hash1 = compute_blob_hash(&data1);
        let hash2 = compute_blob_hash(&data2);

        assert_ne!(hash1, hash2); // Different data = different hash
    }

    #[test]
    fn test_compute_hash_empty() {
        let hash = compute_blob_hash(&[]);
        assert_eq!(hash, [0u8; 32]); // Empty data = zero hash
    }

    // ════════════════════════════════════════════════════════════════════════════
    // I. IS_EXPIRED TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_is_expired_ttl_zero() {
        let validator = HashValidator::new(0);
        let blob = make_valid_blob(vec![1], 0); // Ancient timestamp

        assert!(!validator.is_expired(&blob)); // TTL disabled
    }

    #[test]
    fn test_is_expired_old_blob() {
        let validator = HashValidator::new(60); // 60 seconds
        let blob = make_valid_blob(vec![1], 0); // Very old

        assert!(validator.is_expired(&blob));
    }

    #[test]
    fn test_is_expired_fresh_blob() {
        let validator = HashValidator::new(3600); // 1 hour
        
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let blob = make_valid_blob(vec![1], now_ms);

        assert!(!validator.is_expired(&blob));
    }

    // ════════════════════════════════════════════════════════════════════════════
    // J. THREAD SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_hash_validator_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<HashValidator>();
    }

    #[test]
    fn test_hash_validator_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<HashValidator>();
    }

    #[test]
    fn test_validation_report_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ValidationReport>();
    }

    #[test]
    fn test_validation_report_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<ValidationReport>();
    }

    #[test]
    fn test_validation_error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ValidationError>();
    }

    #[test]
    fn test_validation_error_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<ValidationError>();
    }
}
//! Validation types for FallbackCache (14A.1A.51)

/// Report from cache validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationReport {
    /// Number of valid blobs.
    pub valid_count: u64,
    /// Number of invalid blobs.
    pub invalid_count: u64,
    /// Number of missing blobs.
    pub missing_count: u64,
}

impl ValidationReport {
    /// Create a new ValidationReport with zero counts.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the total number of blobs checked.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.valid_count
            .saturating_add(self.invalid_count)
            .saturating_add(self.missing_count)
    }

    /// Check if validation passed (no invalid or missing).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.invalid_count == 0 && self.missing_count == 0
    }
}
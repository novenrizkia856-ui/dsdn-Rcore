//! # Audit Log Error (Tahap 15.9)
//!
//! Error type for all audit log operations in DSDN.
//!
//! ## Variants
//!
//! | Variant | Description |
//! |---------|-------------|
//! | `WriteFailed` | WORM storage write failure |
//! | `EncodingFailed` | Bincode serialization/deserialization failure |
//! | `HashChainBroken` | Hash chain integrity violation detected |
//! | `SequenceGap` | Non-monotonic sequence number detected |
//! | `DaPublishFailed` | DA layer publish failure |
//! | `StorageFull` | WORM storage capacity exceeded |
//! | `LockPoisoned` | Mutex/RwLock poisoned |
//! | `RecoveryFailed` | Crash recovery failure |
//!
//! ## Thread Safety
//!
//! `AuditLogError` is `Send + Sync` — all fields are owned types.

use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// AUDIT LOG ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for audit log operations.
///
/// Non-overlapping variants covering every failure mode in the audit pipeline:
/// writing, encoding, hash chain verification, DA publishing, and recovery.
///
/// `Send + Sync + Debug + Clone + PartialEq + Eq + Display + Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditLogError {
    /// WORM storage write operation failed.
    WriteFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// Bincode encoding or decoding failed.
    EncodingFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// Hash chain integrity check failed.
    HashChainBroken {
        /// Expected hash (hex string).
        expected: String,
        /// Actual hash found (hex string).
        got: String,
    },

    /// Sequence number is not monotonically increasing.
    SequenceGap {
        /// Expected sequence number.
        expected: u64,
        /// Actual sequence number found.
        got: u64,
    },

    /// DA layer publish operation failed.
    DaPublishFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// WORM storage capacity has been exceeded.
    StorageFull {
        /// Maximum allowed storage in bytes.
        max_bytes: u64,
    },

    /// Internal lock (Mutex/RwLock) was poisoned.
    LockPoisoned {
        /// Human-readable reason for the poisoning.
        reason: String,
    },

    /// Crash recovery operation failed.
    RecoveryFailed {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// DISPLAY
// ════════════════════════════════════════════════════════════════════════════════

impl fmt::Display for AuditLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditLogError::WriteFailed { reason } => {
                write!(f, "audit log write failed: {}", reason)
            }
            AuditLogError::EncodingFailed { reason } => {
                write!(f, "audit log encoding failed: {}", reason)
            }
            AuditLogError::HashChainBroken { expected, got } => {
                write!(
                    f,
                    "audit hash chain broken: expected {}, got {}",
                    expected, got
                )
            }
            AuditLogError::SequenceGap { expected, got } => {
                write!(
                    f,
                    "audit sequence gap: expected {}, got {}",
                    expected, got
                )
            }
            AuditLogError::DaPublishFailed { reason } => {
                write!(f, "audit DA publish failed: {}", reason)
            }
            AuditLogError::StorageFull { max_bytes } => {
                write!(
                    f,
                    "audit log storage full: max capacity {} bytes",
                    max_bytes
                )
            }
            AuditLogError::LockPoisoned { reason } => {
                write!(f, "audit log lock poisoned: {}", reason)
            }
            AuditLogError::RecoveryFailed { reason } => {
                write!(f, "audit log recovery failed: {}", reason)
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TRAIT
// ════════════════════════════════════════════════════════════════════════════════

impl std::error::Error for AuditLogError {}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: audit_log_error_display_write_failed
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_error_display_write_failed() {
        let err = AuditLogError::WriteFailed {
            reason: "disk full".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("audit log write failed"));
        assert!(msg.contains("disk full"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: audit_log_error_display_hash_chain_broken
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_error_display_hash_chain_broken() {
        let err = AuditLogError::HashChainBroken {
            expected: "aabb".to_string(),
            got: "ccdd".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("audit hash chain broken"));
        assert!(msg.contains("expected aabb"));
        assert!(msg.contains("got ccdd"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: audit_log_error_display_sequence_gap
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_error_display_sequence_gap() {
        let err = AuditLogError::SequenceGap {
            expected: 42,
            got: 44,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("audit sequence gap"));
        assert!(msg.contains("expected 42"));
        assert!(msg.contains("got 44"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: audit_log_error_display_storage_full
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_error_display_storage_full() {
        let err = AuditLogError::StorageFull {
            max_bytes: 104857600,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("audit log storage full"));
        assert!(msg.contains("104857600"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: audit_log_error_display_lock_poisoned
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_error_display_lock_poisoned() {
        let err = AuditLogError::LockPoisoned {
            reason: "writer thread panicked".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("audit log lock poisoned"));
        assert!(msg.contains("writer thread panicked"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: audit_log_error_equality_comparison
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_error_equality_comparison() {
        let e1 = AuditLogError::WriteFailed {
            reason: "a".to_string(),
        };
        let e2 = AuditLogError::WriteFailed {
            reason: "a".to_string(),
        };
        let e3 = AuditLogError::WriteFailed {
            reason: "b".to_string(),
        };
        let e4 = AuditLogError::EncodingFailed {
            reason: "a".to_string(),
        };

        // Same variant + same fields → equal
        assert_eq!(e1, e2);

        // Same variant + different fields → not equal
        assert_ne!(e1, e3);

        // Different variant → not equal
        assert_ne!(e1, e4);

        // SequenceGap equality
        let sg1 = AuditLogError::SequenceGap {
            expected: 1,
            got: 3,
        };
        let sg2 = AuditLogError::SequenceGap {
            expected: 1,
            got: 3,
        };
        let sg3 = AuditLogError::SequenceGap {
            expected: 1,
            got: 5,
        };
        assert_eq!(sg1, sg2);
        assert_ne!(sg1, sg3);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: audit_log_error_clone
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_error_clone() {
        let errors: Vec<AuditLogError> = vec![
            AuditLogError::WriteFailed {
                reason: "test".to_string(),
            },
            AuditLogError::EncodingFailed {
                reason: "bad bytes".to_string(),
            },
            AuditLogError::HashChainBroken {
                expected: "aabb".to_string(),
                got: "ccdd".to_string(),
            },
            AuditLogError::SequenceGap {
                expected: 1,
                got: 3,
            },
            AuditLogError::DaPublishFailed {
                reason: "timeout".to_string(),
            },
            AuditLogError::StorageFull { max_bytes: 1024 },
            AuditLogError::LockPoisoned {
                reason: "poisoned".to_string(),
            },
            AuditLogError::RecoveryFailed {
                reason: "corrupt".to_string(),
            },
        ];

        for (i, err) in errors.iter().enumerate() {
            let cloned = err.clone();
            assert_eq!(err, &cloned, "variant {} clone must be equal", i);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: audit_log_error_error_trait
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_error_error_trait() {
        // Verify Error trait is implemented by using it as dyn Error
        fn takes_error(_e: &dyn std::error::Error) {}

        let err = AuditLogError::WriteFailed {
            reason: "test".to_string(),
        };
        takes_error(&err);

        // Also verify Display is used by Error's default source/description
        let display_msg = format!("{}", err);
        assert!(!display_msg.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: audit_log_error_send_sync
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_error_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AuditLogError>();
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: audit_log_error_display_all_variants
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_log_error_display_all_variants() {
        let errors: Vec<(AuditLogError, &str)> = vec![
            (
                AuditLogError::WriteFailed {
                    reason: "r".to_string(),
                },
                "audit log write failed: r",
            ),
            (
                AuditLogError::EncodingFailed {
                    reason: "r".to_string(),
                },
                "audit log encoding failed: r",
            ),
            (
                AuditLogError::HashChainBroken {
                    expected: "e".to_string(),
                    got: "g".to_string(),
                },
                "audit hash chain broken: expected e, got g",
            ),
            (
                AuditLogError::SequenceGap {
                    expected: 5,
                    got: 7,
                },
                "audit sequence gap: expected 5, got 7",
            ),
            (
                AuditLogError::DaPublishFailed {
                    reason: "r".to_string(),
                },
                "audit DA publish failed: r",
            ),
            (
                AuditLogError::StorageFull { max_bytes: 1024 },
                "audit log storage full: max capacity 1024 bytes",
            ),
            (
                AuditLogError::LockPoisoned {
                    reason: "r".to_string(),
                },
                "audit log lock poisoned: r",
            ),
            (
                AuditLogError::RecoveryFailed {
                    reason: "r".to_string(),
                },
                "audit log recovery failed: r",
            ),
        ];

        for (i, (err, expected)) in errors.iter().enumerate() {
            let msg = format!("{}", err);
            assert_eq!(
                &msg, expected,
                "variant {} Display must match: got '{}', expected '{}'",
                i, msg, expected
            );
        }
    }
}
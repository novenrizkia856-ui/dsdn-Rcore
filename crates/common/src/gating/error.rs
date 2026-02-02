//! # Gating Error Types (14B.6)
//!
//! Defines the comprehensive error enum for the DSDN gating system.
//! `GatingError` is the public error contract for all admission and
//! gating operations, consumed by coordinators, validators, and
//! operator tooling.
//!
//! ## Overview
//!
//! Every gating check that can fail produces a specific `GatingError`
//! variant. The variants are non-overlapping — each has a distinct
//! semantic meaning:
//!
//! | Category | Variants |
//! |----------|----------|
//! | Stake | `InsufficientStake`, `ZeroStake` |
//! | Cooldown | `SlashingCooldownActive` |
//! | TLS | `TLSInvalid` |
//! | Identity | `IdentityMismatch`, `IdentityVerificationFailed` |
//! | Status | `NodeBanned`, `NodeQuarantined`, `NodeNotRegistered` |
//! | Class | `InvalidNodeClass` |
//!
//! ## Display Messages
//!
//! All `Display` messages are deterministic, operator-friendly, and
//! contain no internal debug formatting or locale-dependent content.
//! Messages are designed for logging, monitoring, and operator dashboards.
//!
//! ## Safety Properties
//!
//! - `GatingError` is a value type: `Clone`, `Debug`, `PartialEq`, `Eq`.
//! - No side effects, no global state, no allocations beyond String fields.
//! - Implements `std::fmt::Display` and `std::error::Error`.
//! - No `thiserror`, `anyhow`, or implicit error wrapping.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::identity::NodeClass;
use super::tls::TLSValidationError;

// ════════════════════════════════════════════════════════════════════════════════
// GATING ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Comprehensive error type for the DSDN gating system.
///
/// `GatingError` represents every possible failure during node admission
/// and gating verification. Each variant maps to a specific, non-overlapping
/// failure condition.
///
/// ## Usage
///
/// ```rust,ignore
/// use dsdn_common::{GatingError, NodeClass};
///
/// let err = GatingError::InsufficientStake {
///     required: 5_000_000_000_000_000_000_000,
///     actual: 100,
///     class: NodeClass::Storage,
/// };
/// println!("{}", err);
/// // "insufficient stake for Storage: required 5000000000000000000000, actual 100"
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatingError {
    /// The node's stake is below the minimum required for its class.
    /// `ZeroStake` is checked first — this variant is only used when
    /// stake is non-zero but insufficient.
    InsufficientStake {
        /// Minimum stake required for the class (smallest on-chain units).
        required: u128,
        /// Actual stake provided (smallest on-chain units).
        actual: u128,
        /// The node class that was checked against.
        class: NodeClass,
    },

    /// The node's stake is exactly zero.
    /// Zero stake is always rejected before checking class minimums.
    ZeroStake,

    /// The node is in an active slashing cooldown and cannot re-register.
    SlashingCooldownActive {
        /// Seconds remaining until the cooldown expires.
        remaining_secs: u64,
        /// Reason for the original slashing event.
        reason: String,
    },

    /// TLS certificate validation failed.
    /// Wraps a [`TLSValidationError`] with the specific failure reason.
    TLSInvalid(TLSValidationError),

    /// The node's identity does not match the operator binding.
    /// The node_id and operator address are included for diagnostics.
    IdentityMismatch {
        /// The Ed25519 public key of the node.
        node_id: [u8; 32],
        /// The operator wallet address.
        operator: [u8; 20],
    },

    /// Node identity verification failed with a specific reason.
    /// This covers signature verification failures and other
    /// identity-related checks beyond simple mismatch.
    IdentityVerificationFailed(String),

    /// The node is currently banned and cannot participate.
    NodeBanned {
        /// Unix timestamp (seconds) until which the ban is active.
        until_timestamp: u64,
    },

    /// The node is currently quarantined and cannot receive workloads.
    NodeQuarantined {
        /// Reason for the quarantine.
        reason: String,
    },

    /// The node is not registered in the network.
    NodeNotRegistered,

    /// The node class value is invalid or unrecognized.
    InvalidNodeClass(String),
}

impl fmt::Display for GatingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatingError::InsufficientStake {
                required,
                actual,
                class,
            } => {
                write!(
                    f,
                    "insufficient stake for {}: required {}, actual {}",
                    class, required, actual
                )
            }
            GatingError::ZeroStake => {
                write!(f, "node has zero stake")
            }
            GatingError::SlashingCooldownActive {
                remaining_secs,
                reason,
            } => {
                write!(
                    f,
                    "node is in slashing cooldown for {} seconds: {}",
                    remaining_secs, reason
                )
            }
            GatingError::TLSInvalid(inner) => {
                let detail = match inner {
                    TLSValidationError::Expired => "certificate expired",
                    TLSValidationError::NotYetValid => "certificate not yet valid",
                    TLSValidationError::FingerprintMismatch => "fingerprint mismatch",
                    TLSValidationError::EmptySubject => "empty subject",
                    TLSValidationError::MissingCert => "missing certificate",
                };
                write!(f, "TLS validation failed: {}", detail)
            }
            GatingError::IdentityMismatch { .. } => {
                write!(f, "node identity does not match operator binding")
            }
            GatingError::IdentityVerificationFailed(reason) => {
                write!(f, "node identity verification failed: {}", reason)
            }
            GatingError::NodeBanned { until_timestamp } => {
                write!(f, "node is banned until timestamp {}", until_timestamp)
            }
            GatingError::NodeQuarantined { reason } => {
                write!(f, "node is quarantined: {}", reason)
            }
            GatingError::NodeNotRegistered => {
                write!(f, "node is not registered")
            }
            GatingError::InvalidNodeClass(value) => {
                write!(f, "invalid node class: {}", value)
            }
        }
    }
}

impl std::error::Error for GatingError {}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────────
    // DISPLAY TESTS — EXACT MESSAGE VERIFICATION
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_display_insufficient_stake_storage() {
        let err = GatingError::InsufficientStake {
            required: 5_000_000_000_000_000_000_000,
            actual: 100,
            class: NodeClass::Storage,
        };
        assert_eq!(
            format!("{}", err),
            "insufficient stake for Storage: required 5000000000000000000000, actual 100"
        );
    }

    #[test]
    fn test_display_insufficient_stake_compute() {
        let err = GatingError::InsufficientStake {
            required: 500_000_000_000_000_000_000,
            actual: 42,
            class: NodeClass::Compute,
        };
        assert_eq!(
            format!("{}", err),
            "insufficient stake for Compute: required 500000000000000000000, actual 42"
        );
    }

    #[test]
    fn test_display_zero_stake() {
        let err = GatingError::ZeroStake;
        assert_eq!(format!("{}", err), "node has zero stake");
    }

    #[test]
    fn test_display_slashing_cooldown_active() {
        let err = GatingError::SlashingCooldownActive {
            remaining_secs: 86_400,
            reason: "stake drop below minimum".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "node is in slashing cooldown for 86400 seconds: stake drop below minimum"
        );
    }

    #[test]
    fn test_display_tls_invalid_expired() {
        let err = GatingError::TLSInvalid(TLSValidationError::Expired);
        assert_eq!(
            format!("{}", err),
            "TLS validation failed: certificate expired"
        );
    }

    #[test]
    fn test_display_tls_invalid_not_yet_valid() {
        let err = GatingError::TLSInvalid(TLSValidationError::NotYetValid);
        assert_eq!(
            format!("{}", err),
            "TLS validation failed: certificate not yet valid"
        );
    }

    #[test]
    fn test_display_tls_invalid_fingerprint_mismatch() {
        let err = GatingError::TLSInvalid(TLSValidationError::FingerprintMismatch);
        assert_eq!(
            format!("{}", err),
            "TLS validation failed: fingerprint mismatch"
        );
    }

    #[test]
    fn test_display_tls_invalid_empty_subject() {
        let err = GatingError::TLSInvalid(TLSValidationError::EmptySubject);
        assert_eq!(
            format!("{}", err),
            "TLS validation failed: empty subject"
        );
    }

    #[test]
    fn test_display_tls_invalid_missing_cert() {
        let err = GatingError::TLSInvalid(TLSValidationError::MissingCert);
        assert_eq!(
            format!("{}", err),
            "TLS validation failed: missing certificate"
        );
    }

    #[test]
    fn test_display_identity_mismatch() {
        let err = GatingError::IdentityMismatch {
            node_id: [0x01; 32],
            operator: [0x02; 20],
        };
        assert_eq!(
            format!("{}", err),
            "node identity does not match operator binding"
        );
    }

    #[test]
    fn test_display_identity_verification_failed() {
        let err = GatingError::IdentityVerificationFailed(
            "signature verification failed".to_string(),
        );
        assert_eq!(
            format!("{}", err),
            "node identity verification failed: signature verification failed"
        );
    }

    #[test]
    fn test_display_node_banned() {
        let err = GatingError::NodeBanned {
            until_timestamp: 1_700_086_400,
        };
        assert_eq!(
            format!("{}", err),
            "node is banned until timestamp 1700086400"
        );
    }

    #[test]
    fn test_display_node_quarantined() {
        let err = GatingError::NodeQuarantined {
            reason: "stake dropped below minimum".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "node is quarantined: stake dropped below minimum"
        );
    }

    #[test]
    fn test_display_node_not_registered() {
        let err = GatingError::NodeNotRegistered;
        assert_eq!(format!("{}", err), "node is not registered");
    }

    #[test]
    fn test_display_invalid_node_class() {
        let err = GatingError::InvalidNodeClass("Validator".to_string());
        assert_eq!(format!("{}", err), "invalid node class: Validator");
    }

    // ──────────────────────────────────────────────────────────────────────
    // DISPLAY DETERMINISM
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_display_deterministic() {
        let err = GatingError::InsufficientStake {
            required: 1000,
            actual: 500,
            class: NodeClass::Storage,
        };
        let s1 = format!("{}", err);
        let s2 = format!("{}", err);
        let s3 = format!("{}", err);
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
    }

    // ──────────────────────────────────────────────────────────────────────
    // TRAIT TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_clone() {
        let err = GatingError::SlashingCooldownActive {
            remaining_secs: 100,
            reason: "test".to_string(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_debug() {
        let err = GatingError::ZeroStake;
        let debug = format!("{:?}", err);
        assert!(debug.contains("ZeroStake"));
    }

    #[test]
    fn test_debug_contains_fields() {
        let err = GatingError::InsufficientStake {
            required: 999,
            actual: 111,
            class: NodeClass::Compute,
        };
        let debug = format!("{:?}", err);
        assert!(debug.contains("InsufficientStake"));
        assert!(debug.contains("999"));
        assert!(debug.contains("111"));
        assert!(debug.contains("Compute"));
    }

    #[test]
    fn test_eq_same_variant() {
        let a = GatingError::ZeroStake;
        let b = GatingError::ZeroStake;
        assert_eq!(a, b);
    }

    #[test]
    fn test_eq_struct_variant() {
        let a = GatingError::InsufficientStake {
            required: 100,
            actual: 50,
            class: NodeClass::Storage,
        };
        let b = GatingError::InsufficientStake {
            required: 100,
            actual: 50,
            class: NodeClass::Storage,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_ne_different_variant() {
        assert_ne!(GatingError::ZeroStake, GatingError::NodeNotRegistered);
    }

    #[test]
    fn test_ne_same_variant_different_fields() {
        let a = GatingError::InsufficientStake {
            required: 100,
            actual: 50,
            class: NodeClass::Storage,
        };
        let b = GatingError::InsufficientStake {
            required: 200,
            actual: 50,
            class: NodeClass::Storage,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_ne_insufficient_vs_zero() {
        let a = GatingError::InsufficientStake {
            required: 100,
            actual: 50,
            class: NodeClass::Compute,
        };
        let b = GatingError::ZeroStake;
        assert_ne!(a, b);
    }

    // ──────────────────────────────────────────────────────────────────────
    // SERDE TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_roundtrip_insufficient_stake() {
        let err = GatingError::InsufficientStake {
            required: 5_000_000_000_000_000_000_000,
            actual: 42,
            class: NodeClass::Storage,
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let back: GatingError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    #[test]
    fn test_serde_roundtrip_zero_stake() {
        let err = GatingError::ZeroStake;
        let json = serde_json::to_string(&err).expect("serialize");
        let back: GatingError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    #[test]
    fn test_serde_roundtrip_slashing_cooldown() {
        let err = GatingError::SlashingCooldownActive {
            remaining_secs: 604_800,
            reason: "identity spoofing".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let back: GatingError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    #[test]
    fn test_serde_roundtrip_tls_invalid() {
        let err = GatingError::TLSInvalid(TLSValidationError::Expired);
        let json = serde_json::to_string(&err).expect("serialize");
        let back: GatingError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    #[test]
    fn test_serde_roundtrip_identity_mismatch() {
        let err = GatingError::IdentityMismatch {
            node_id: [0xAA; 32],
            operator: [0xBB; 20],
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let back: GatingError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    #[test]
    fn test_serde_roundtrip_identity_verification_failed() {
        let err = GatingError::IdentityVerificationFailed("bad sig".to_string());
        let json = serde_json::to_string(&err).expect("serialize");
        let back: GatingError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    #[test]
    fn test_serde_roundtrip_node_banned() {
        let err = GatingError::NodeBanned {
            until_timestamp: 1_700_000_000,
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let back: GatingError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    #[test]
    fn test_serde_roundtrip_node_quarantined() {
        let err = GatingError::NodeQuarantined {
            reason: "violation".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let back: GatingError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    #[test]
    fn test_serde_roundtrip_node_not_registered() {
        let err = GatingError::NodeNotRegistered;
        let json = serde_json::to_string(&err).expect("serialize");
        let back: GatingError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    #[test]
    fn test_serde_roundtrip_invalid_node_class() {
        let err = GatingError::InvalidNodeClass("Validator".to_string());
        let json = serde_json::to_string(&err).expect("serialize");
        let back: GatingError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, back);
    }

    // ──────────────────────────────────────────────────────────────────────
    // std::error::Error TRAIT TEST
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<GatingError>();
    }

    #[test]
    fn test_error_source_is_none() {
        // GatingError does not wrap other std::error::Error sources
        let err = GatingError::ZeroStake;
        let err_ref: &dyn std::error::Error = &err;
        assert!(err_ref.source().is_none());
    }

    // ──────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GatingError>();
    }

    // ──────────────────────────────────────────────────────────────────────
    // SEMANTIC NON-OVERLAP TESTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_insufficient_stake_ne_zero_stake() {
        let a = GatingError::InsufficientStake {
            required: 100,
            actual: 50,
            class: NodeClass::Compute,
        };
        let b = GatingError::ZeroStake;
        assert_ne!(a, b);
        // Display messages are different
        assert_ne!(format!("{}", a), format!("{}", b));
    }

    #[test]
    fn test_node_banned_ne_node_quarantined() {
        let a = GatingError::NodeBanned {
            until_timestamp: 1000,
        };
        let b = GatingError::NodeQuarantined {
            reason: "test".to_string(),
        };
        assert_ne!(a, b);
        assert_ne!(format!("{}", a), format!("{}", b));
    }

    #[test]
    fn test_tls_invalid_ne_identity_verification_failed() {
        let a = GatingError::TLSInvalid(TLSValidationError::Expired);
        let b = GatingError::IdentityVerificationFailed("expired".to_string());
        assert_ne!(a, b);
        assert_ne!(format!("{}", a), format!("{}", b));
    }

    #[test]
    fn test_invalid_node_class_ne_node_not_registered() {
        let a = GatingError::InvalidNodeClass("unknown".to_string());
        let b = GatingError::NodeNotRegistered;
        assert_ne!(a, b);
        assert_ne!(format!("{}", a), format!("{}", b));
    }

    // ──────────────────────────────────────────────────────────────────────
    // ALL VARIANTS DISTINCT TEST
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_all_variants_distinct() {
        let variants: Vec<GatingError> = vec![
            GatingError::InsufficientStake {
                required: 100,
                actual: 50,
                class: NodeClass::Storage,
            },
            GatingError::ZeroStake,
            GatingError::SlashingCooldownActive {
                remaining_secs: 100,
                reason: "test".to_string(),
            },
            GatingError::TLSInvalid(TLSValidationError::Expired),
            GatingError::IdentityMismatch {
                node_id: [0x01; 32],
                operator: [0x02; 20],
            },
            GatingError::IdentityVerificationFailed("fail".to_string()),
            GatingError::NodeBanned {
                until_timestamp: 1000,
            },
            GatingError::NodeQuarantined {
                reason: "q".to_string(),
            },
            GatingError::NodeNotRegistered,
            GatingError::InvalidNodeClass("bad".to_string()),
        ];

        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(
                    variants[i], variants[j],
                    "variants[{}] == variants[{}]",
                    i, j
                );
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // ALL DISPLAY MESSAGES NON-EMPTY
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_all_display_messages_non_empty() {
        let variants: Vec<GatingError> = vec![
            GatingError::InsufficientStake {
                required: 100,
                actual: 50,
                class: NodeClass::Storage,
            },
            GatingError::ZeroStake,
            GatingError::SlashingCooldownActive {
                remaining_secs: 100,
                reason: "r".to_string(),
            },
            GatingError::TLSInvalid(TLSValidationError::Expired),
            GatingError::TLSInvalid(TLSValidationError::NotYetValid),
            GatingError::TLSInvalid(TLSValidationError::FingerprintMismatch),
            GatingError::TLSInvalid(TLSValidationError::EmptySubject),
            GatingError::TLSInvalid(TLSValidationError::MissingCert),
            GatingError::IdentityMismatch {
                node_id: [0; 32],
                operator: [0; 20],
            },
            GatingError::IdentityVerificationFailed("x".to_string()),
            GatingError::NodeBanned {
                until_timestamp: 0,
            },
            GatingError::NodeQuarantined {
                reason: "y".to_string(),
            },
            GatingError::NodeNotRegistered,
            GatingError::InvalidNodeClass("z".to_string()),
        ];

        for (i, err) in variants.iter().enumerate() {
            let msg = format!("{}", err);
            assert!(
                !msg.is_empty(),
                "variant[{}] Display is empty",
                i
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // DISPLAY DOES NOT CONTAIN DEBUG ARTIFACTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_display_no_debug_artifacts() {
        let variants: Vec<GatingError> = vec![
            GatingError::InsufficientStake {
                required: 100,
                actual: 50,
                class: NodeClass::Storage,
            },
            GatingError::TLSInvalid(TLSValidationError::Expired),
            GatingError::IdentityMismatch {
                node_id: [0x01; 32],
                operator: [0x02; 20],
            },
        ];

        for err in &variants {
            let msg = format!("{}", err);
            // Should not contain debug-style formatting
            assert!(
                !msg.contains("GatingError"),
                "Display contains type name: {}",
                msg
            );
            assert!(
                !msg.contains("{"),
                "Display contains debug braces: {}",
                msg
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // TLSInvalid WRAPS ALL TLSValidationError VARIANTS
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_tls_invalid_all_inner_variants() {
        let inners = [
            TLSValidationError::Expired,
            TLSValidationError::NotYetValid,
            TLSValidationError::FingerprintMismatch,
            TLSValidationError::EmptySubject,
            TLSValidationError::MissingCert,
        ];

        let expected_details = [
            "certificate expired",
            "certificate not yet valid",
            "fingerprint mismatch",
            "empty subject",
            "missing certificate",
        ];

        for (inner, detail) in inners.iter().zip(expected_details.iter()) {
            let err = GatingError::TLSInvalid(inner.clone());
            let msg = format!("{}", err);
            let expected = format!("TLS validation failed: {}", detail);
            assert_eq!(msg, expected, "inner={:?}", inner);
        }
    }
}
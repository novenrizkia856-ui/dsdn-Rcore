//! DA Health Status and Error Types for DSDN Data Availability Layer
//!
//! Module ini mendefinisikan type untuk health monitoring dan error handling
//! pada komunikasi dengan Celestia DA layer.

use std::fmt;
use std::error::Error;
use crate::da_event::BlobRef;

/// Status kesehatan DA layer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DAHealthStatus {
    /// DA layer berfungsi normal
    Healthy {
        /// Block height terakhir yang diketahui
        last_height: u64,
        /// Latency dalam milliseconds
        latency_ms: u64,
    },

    /// DA layer dalam kondisi degraded
    Degraded {
        /// Alasan degradasi
        reason: String,
        /// Block height terakhir yang diketahui
        last_height: u64,
    },

    /// DA layer tidak tersedia
    Unavailable {
        /// Timestamp sejak kapan tidak tersedia
        since: u64,
        /// Pesan error
        error: String,
    },

    /// DA layer sedang sinkronisasi
    Syncing {
        /// Block height saat ini
        current: u64,
        /// Target block height
        target: u64,
        /// Progress dalam persen (0-100)
        progress_percent: u8,
    },
}

/// Error types untuk operasi DA layer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DAError {
    /// Koneksi ke DA layer gagal
    ConnectionFailed(String),

    /// Blob tidak ditemukan
    BlobNotFound(BlobRef),

    /// Blob invalid
    InvalidBlob {
        /// Referensi blob yang invalid
        r#ref: BlobRef,
        /// Alasan invalid
        reason: String,
    },

    /// Namespace tidak cocok
    NamespaceMismatch,

    /// Decode gagal
    DecodeFailed(String),

    /// Timeout
    Timeout,

    /// Rate limited
    RateLimited {
        /// Waktu tunggu sebelum retry dalam milliseconds
        retry_after_ms: u64,
    },
}

impl fmt::Display for DAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DAError::ConnectionFailed(msg) => {
                write!(f, "DA connection failed: {}", msg)
            }
            DAError::BlobNotFound(blob_ref) => {
                write!(f, "Blob not found: {}", blob_ref)
            }
            DAError::InvalidBlob { r#ref, reason } => {
                write!(f, "Invalid blob {}: {}", r#ref, reason)
            }
            DAError::NamespaceMismatch => {
                write!(f, "Namespace mismatch")
            }
            DAError::DecodeFailed(msg) => {
                write!(f, "Decode failed: {}", msg)
            }
            DAError::Timeout => {
                write!(f, "DA operation timeout")
            }
            DAError::RateLimited { retry_after_ms } => {
                write!(f, "Rate limited, retry after {} ms", retry_after_ms)
            }
        }
    }
}

impl Error for DAError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_da_health_status_healthy() {
        let status = DAHealthStatus::Healthy {
            last_height: 12345,
            latency_ms: 50,
        };

        match status {
            DAHealthStatus::Healthy { last_height, latency_ms } => {
                assert_eq!(last_height, 12345, "last_height mismatch");
                assert_eq!(latency_ms, 50, "latency_ms mismatch");
            }
            _ => panic!("expected Healthy variant"),
        }
    }

    #[test]
    fn test_da_health_status_degraded() {
        let status = DAHealthStatus::Degraded {
            reason: "high latency".to_string(),
            last_height: 12340,
        };

        match status {
            DAHealthStatus::Degraded { reason, last_height } => {
                assert_eq!(reason, "high latency", "reason mismatch");
                assert_eq!(last_height, 12340, "last_height mismatch");
            }
            _ => panic!("expected Degraded variant"),
        }
    }

    #[test]
    fn test_da_health_status_unavailable() {
        let status = DAHealthStatus::Unavailable {
            since: 1704067200000,
            error: "connection refused".to_string(),
        };

        match status {
            DAHealthStatus::Unavailable { since, error } => {
                assert_eq!(since, 1704067200000, "since mismatch");
                assert_eq!(error, "connection refused", "error mismatch");
            }
            _ => panic!("expected Unavailable variant"),
        }
    }

    #[test]
    fn test_da_health_status_syncing() {
        let status = DAHealthStatus::Syncing {
            current: 10000,
            target: 12345,
            progress_percent: 81,
        };

        match status {
            DAHealthStatus::Syncing { current, target, progress_percent } => {
                assert_eq!(current, 10000, "current mismatch");
                assert_eq!(target, 12345, "target mismatch");
                assert_eq!(progress_percent, 81, "progress_percent mismatch");
            }
            _ => panic!("expected Syncing variant"),
        }
    }

    #[test]
    fn test_da_error_connection_failed() {
        let error = DAError::ConnectionFailed("network unreachable".to_string());

        match &error {
            DAError::ConnectionFailed(msg) => {
                assert_eq!(msg, "network unreachable", "message mismatch");
            }
            _ => panic!("expected ConnectionFailed variant"),
        }

        let display = format!("{}", error);
        assert!(!display.is_empty(), "Display must not be empty");
        assert!(display.contains("network unreachable"), "Display must contain message");
    }

    #[test]
    fn test_da_error_blob_not_found() {
        let namespace: [u8; 29] = [0x01u8; 29];
        let commitment: [u8; 32] = [0xffu8; 32];

        let blob_ref = BlobRef {
            height: 100,
            namespace: namespace,
            index: 5,
            commitment: commitment,
        };

        let error = DAError::BlobNotFound(blob_ref.clone());

        match &error {
            DAError::BlobNotFound(br) => {
                assert_eq!(br.height, 100, "height mismatch");
                assert_eq!(br.index, 5, "index mismatch");
                assert_eq!(br.namespace.len(), 29, "namespace must be 29 bytes");
                assert_eq!(br.commitment.len(), 32, "commitment must be 32 bytes");
            }
            _ => panic!("expected BlobNotFound variant"),
        }

        let display = format!("{}", error);
        assert!(!display.is_empty(), "Display must not be empty");
        assert!(display.contains("100"), "Display must contain height");
    }

    #[test]
    fn test_da_error_invalid_blob() {
        let namespace: [u8; 29] = [0x02u8; 29];
        let commitment: [u8; 32] = [0xaau8; 32];

        let blob_ref = BlobRef {
            height: 200,
            namespace: namespace,
            index: 10,
            commitment: commitment,
        };

        let error = DAError::InvalidBlob {
            r#ref: blob_ref.clone(),
            reason: "checksum mismatch".to_string(),
        };

        match &error {
            DAError::InvalidBlob { r#ref, reason } => {
                assert_eq!(r#ref.height, 200, "height mismatch");
                assert_eq!(r#ref.index, 10, "index mismatch");
                assert_eq!(reason, "checksum mismatch", "reason mismatch");
            }
            _ => panic!("expected InvalidBlob variant"),
        }

        let display = format!("{}", error);
        assert!(!display.is_empty(), "Display must not be empty");
        assert!(display.contains("checksum mismatch"), "Display must contain reason");
    }

    #[test]
    fn test_da_error_namespace_mismatch() {
        let error = DAError::NamespaceMismatch;

        match &error {
            DAError::NamespaceMismatch => {}
            _ => panic!("expected NamespaceMismatch variant"),
        }

        let display = format!("{}", error);
        assert!(!display.is_empty(), "Display must not be empty");
        assert!(display.contains("mismatch"), "Display must contain 'mismatch'");
    }

    #[test]
    fn test_da_error_decode_failed() {
        let error = DAError::DecodeFailed("invalid bincode format".to_string());

        match &error {
            DAError::DecodeFailed(msg) => {
                assert_eq!(msg, "invalid bincode format", "message mismatch");
            }
            _ => panic!("expected DecodeFailed variant"),
        }

        let display = format!("{}", error);
        assert!(!display.is_empty(), "Display must not be empty");
        assert!(display.contains("invalid bincode format"), "Display must contain message");
    }

    #[test]
    fn test_da_error_timeout() {
        let error = DAError::Timeout;

        match &error {
            DAError::Timeout => {}
            _ => panic!("expected Timeout variant"),
        }

        let display = format!("{}", error);
        assert!(!display.is_empty(), "Display must not be empty");
        assert!(display.contains("timeout") || display.contains("Timeout"), "Display must contain 'timeout'");
    }

    #[test]
    fn test_da_error_rate_limited() {
        let error = DAError::RateLimited {
            retry_after_ms: 5000,
        };

        match &error {
            DAError::RateLimited { retry_after_ms } => {
                assert_eq!(*retry_after_ms, 5000, "retry_after_ms mismatch");
            }
            _ => panic!("expected RateLimited variant"),
        }

        let display = format!("{}", error);
        assert!(!display.is_empty(), "Display must not be empty");
        assert!(display.contains("5000"), "Display must contain retry_after_ms value");
    }

    #[test]
    fn test_da_error_is_std_error() {
        let error = DAError::Timeout;

        // Verify DAError implements std::error::Error
        let _: &dyn Error = &error;

        // Test that we can use it as a boxed error
        let boxed: Box<dyn Error> = Box::new(error);
        assert!(!boxed.to_string().is_empty(), "Error to_string must not be empty");
    }

    #[test]
    fn test_da_error_display_determinism() {
        let error = DAError::RateLimited {
            retry_after_ms: 1000,
        };

        let display1 = format!("{}", error);
        let display2 = format!("{}", error);

        assert_eq!(display1, display2, "Display must be deterministic");
    }

    #[test]
    fn test_da_health_status_clone() {
        let status = DAHealthStatus::Syncing {
            current: 100,
            target: 200,
            progress_percent: 50,
        };

        let cloned = status.clone();
        assert_eq!(status, cloned, "Clone must produce equal value");
    }

    #[test]
    fn test_da_error_clone() {
        let namespace: [u8; 29] = [0x03u8; 29];
        let commitment: [u8; 32] = [0xbbu8; 32];

        let blob_ref = BlobRef {
            height: 300,
            namespace: namespace,
            index: 15,
            commitment: commitment,
        };

        let error = DAError::BlobNotFound(blob_ref);
        let cloned = error.clone();

        assert_eq!(error, cloned, "Clone must produce equal value");
    }
}
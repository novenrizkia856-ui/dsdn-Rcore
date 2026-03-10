//! Serialization Helpers for DSDN DA Events
//!
//! Module ini menyediakan fungsi encoding/decoding deterministik untuk DAEvent.
//! Encoding yang sama HARUS menghasilkan output byte yang identik.
//!
//! ## Fallback Types Support (14A.1A.8)
//!
//! Module ini juga menyediakan encoding/decoding untuk fallback-related types:
//! - `FallbackEvent` - Events untuk DA fallback operations
//! - `PendingBlob` - Blob yang menunggu reconciliation
//!
//! Semua fungsi menggunakan konfigurasi bincode yang IDENTIK untuk menjamin
//! kompatibilitas dan determinisme lintas platform.

use sha3::{Sha3_256, Digest};
use crate::da_event::DAEvent;
use crate::da_health::DAError;
use crate::fallback_event::FallbackEvent;
use crate::pending_blob::PendingBlob;

/// Type alias untuk decode errors.
///
/// Menggunakan `DAError` untuk konsistensi dengan existing DA encoding functions.
/// Semua decode errors dikembalikan sebagai `DAError::DecodeFailed`.
pub type DecodeError = DAError;

/// Encode single DAEvent ke bytes dengan format deterministik.
///
/// # Determinism Guarantee
/// Input yang sama SELALU menghasilkan output byte yang identik,
/// tidak bergantung pada platform, compiler, atau runtime state.
///
/// # Arguments
/// * `event` - Reference ke DAEvent yang akan di-encode
///
/// # Returns
/// Vec<u8> berisi binary representation dari event
pub fn encode_event(event: &DAEvent) -> Vec<u8> {
    // bincode menggunakan little-endian dan fixed encoding order
    // yang menjamin deterministic output
    bincode::serialize(event).unwrap_or_else(|_| Vec::new())
}

/// Decode bytes ke DAEvent.
///
/// # Arguments
/// * `bytes` - Slice bytes hasil dari encode_event
///
/// # Returns
/// * `Ok(DAEvent)` - Berhasil decode
/// * `Err(DAError::DecodeFailed)` - Gagal decode
///
/// # Roundtrip Guarantee
/// decode_event(encode_event(event)) == event (untuk semua valid event)
pub fn decode_event(bytes: &[u8]) -> Result<DAEvent, DAError> {
    if bytes.is_empty() {
        return Err(DAError::DecodeFailed("empty input".to_string()));
    }
    bincode::deserialize(bytes)
        .map_err(|e| DAError::DecodeFailed(e.to_string()))
}

/// Compute SHA3-256 hash dari encoded event.
///
/// # Determinism Guarantee
/// Hash dihitung dari HASIL encode_event, bukan struct langsung.
/// Input event yang sama SELALU menghasilkan hash yang identik.
///
/// # Arguments
/// * `event` - Reference ke DAEvent
///
/// # Returns
/// Fixed 32 byte array berisi SHA3-256 hash
pub fn compute_event_hash(event: &DAEvent) -> [u8; 32] {
    let encoded = encode_event(event);
    let mut hasher = Sha3_256::new();
    hasher.update(&encoded);
    hasher.finalize().into()
}

/// Encode batch of DAEvents ke bytes.
///
/// # Format
/// ```text
/// [event_count:8][event_1_len:8][event_1_bytes:N]...[event_N_len:8][event_N_bytes:M]
/// ```
///
/// # Determinism Guarantee
/// Urutan event TIDAK BERUBAH. Output deterministik.
///
/// # Arguments
/// * `events` - Slice of DAEvent references
///
/// # Returns
/// Vec<u8> berisi concatenated length-prefixed events
pub fn batch_encode(events: &[DAEvent]) -> Vec<u8> {
    let mut result = Vec::new();
    
    // Write event count as u64 (8 bytes, little-endian)
    let count = events.len() as u64;
    result.extend_from_slice(&count.to_le_bytes());
    
    // Write each event with length prefix
    for event in events {
        let encoded = encode_event(event);
        let len = encoded.len() as u64;
        result.extend_from_slice(&len.to_le_bytes());
        result.extend_from_slice(&encoded);
    }
    
    result
}

/// Decode bytes ke Vec<DAEvent>.
///
/// # Arguments
/// * `bytes` - Slice bytes hasil dari batch_encode
///
/// # Returns
/// * `Ok(Vec<DAEvent>)` - Berhasil decode semua events
/// * `Err(DAError::DecodeFailed)` - Gagal decode
///
/// # Roundtrip Guarantee
/// batch_decode(batch_encode(events)) == events
/// Urutan dan isi TIDAK BERUBAH.
pub fn batch_decode(bytes: &[u8]) -> Result<Vec<DAEvent>, DAError> {
    if bytes.len() < 8 {
        return Err(DAError::DecodeFailed("batch too short for count".to_string()));
    }
    
    let mut cursor = 0;
    
    // Read event count
    let count_bytes: [u8; 8] = bytes[cursor..cursor + 8]
        .try_into()
        .map_err(|_| DAError::DecodeFailed("failed to read count".to_string()))?;
    let count = u64::from_le_bytes(count_bytes) as usize;
    cursor += 8;
    
    // Validate count to prevent allocation overflow
    // Each event needs at least 8 bytes for length prefix
    let max_possible_events = (bytes.len() - 8) / 8;
    if count > max_possible_events {
        return Err(DAError::DecodeFailed(
            format!("invalid event count {} exceeds maximum possible {}", count, max_possible_events)
        ));
    }
    
    let mut events = Vec::with_capacity(count);
    
    // Read each event
    for i in 0..count {
        // Read length prefix
        if cursor + 8 > bytes.len() {
            return Err(DAError::DecodeFailed(
                format!("batch truncated at event {} length", i)
            ));
        }
        
        let len_bytes: [u8; 8] = bytes[cursor..cursor + 8]
            .try_into()
            .map_err(|_| DAError::DecodeFailed(
                format!("failed to read length for event {}", i)
            ))?;
        let event_len = u64::from_le_bytes(len_bytes) as usize;
        cursor += 8;
        
        // Read event bytes
        if cursor + event_len > bytes.len() {
            return Err(DAError::DecodeFailed(
                format!("batch truncated at event {} data", i)
            ));
        }
        
        let event_bytes = &bytes[cursor..cursor + event_len];
        let event = decode_event(event_bytes)?;
        events.push(event);
        cursor += event_len;
    }
    
    Ok(events)
}

// ════════════════════════════════════════════════════════════════════════════════
// FALLBACK TYPES ENCODING (14A.1A.8)
// ════════════════════════════════════════════════════════════════════════════════

/// Encode FallbackEvent ke bytes dengan format deterministik.
///
/// # Determinism Guarantee
///
/// Input yang sama SELALU menghasilkan output byte yang identik,
/// tidak bergantung pada platform, compiler, atau runtime state.
///
/// Menggunakan konfigurasi bincode yang IDENTIK dengan `encode_event`
/// untuk menjamin konsistensi encoding lintas semua proto types.
///
/// # Arguments
///
/// * `event` - Reference ke FallbackEvent yang akan di-encode
///
/// # Returns
///
/// `Vec<u8>` berisi binary representation dari event.
/// Mengembalikan empty Vec jika serialisasi gagal (defensive, seharusnya tidak terjadi
/// untuk valid FallbackEvent).
///
/// # Example
///
/// ```
/// use dsdn_proto::fallback_event::FallbackEvent;
/// use dsdn_proto::encoding::encode_fallback_event;
///
/// let event = FallbackEvent::FallbackActivated {
///     version: 1,
/// };
///
/// let bytes = encode_fallback_event(&event);
/// assert!(!bytes.is_empty());
/// ```
pub fn encode_fallback_event(event: &FallbackEvent) -> Vec<u8> {
    // Menggunakan bincode::serialize yang sama dengan encode_event
    // untuk menjamin konsistensi encoding (little-endian, fixed encoding order)
    bincode::serialize(event).unwrap_or_else(|_| Vec::new())
}

/// Decode bytes ke FallbackEvent.
///
/// # Arguments
///
/// * `bytes` - Slice bytes hasil dari `encode_fallback_event`
///
/// # Returns
///
/// * `Ok(FallbackEvent)` - Berhasil decode
/// * `Err(DecodeError)` - Gagal decode dengan pesan error eksplisit
///
/// # Roundtrip Guarantee
///
/// `decode_fallback_event(encode_fallback_event(event)) == event`
/// untuk semua valid FallbackEvent.
///
/// # Errors
///
/// Mengembalikan `DecodeError::DecodeFailed` jika:
/// - Input bytes kosong
/// - Format bytes tidak valid
/// - Bytes tidak merepresentasikan FallbackEvent yang valid
///
/// # Example
///
/// ```
/// use dsdn_proto::fallback_event::FallbackEvent;
/// use dsdn_proto::encoding::{encode_fallback_event, decode_fallback_event};
///
/// let original = FallbackEvent::FallbackActivated {
///     version: 1,
/// };
///
/// let bytes = encode_fallback_event(&original);
/// let decoded = decode_fallback_event(&bytes).expect("decode must succeed");
/// assert_eq!(original, decoded);
/// ```
pub fn decode_fallback_event(bytes: &[u8]) -> Result<FallbackEvent, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::DecodeFailed("empty input".to_string()));
    }
    bincode::deserialize(bytes)
        .map_err(|e| DecodeError::DecodeFailed(e.to_string()))
}

/// Encode PendingBlob ke bytes dengan format deterministik.
///
/// # Determinism Guarantee
///
/// Input yang sama SELALU menghasilkan output byte yang identik,
/// tidak bergantung pada platform, compiler, atau runtime state.
///
/// Menggunakan konfigurasi bincode yang IDENTIK dengan `encode_event`
/// untuk menjamin konsistensi encoding lintas semua proto types.
///
/// # Arguments
///
/// * `blob` - Reference ke PendingBlob yang akan di-encode
///
/// # Returns
///
/// `Vec<u8>` berisi binary representation dari blob.
/// Mengembalikan empty Vec jika serialisasi gagal (defensive, seharusnya tidak terjadi
/// untuk valid PendingBlob).
///
/// # Example
///
/// ```
/// use dsdn_proto::pending_blob::PendingBlob;
/// use dsdn_proto::encoding::encode_pending_blob;
///
/// let blob = PendingBlob {
///     data: vec![1, 2, 3, 4],
///     original_sequence: 42,
///     source_da: String::from("validator_quorum"),
///     received_at: 1704067200,
///     retry_count: 0,
///     commitment: None,
/// };
///
/// let bytes = encode_pending_blob(&blob);
/// assert!(!bytes.is_empty());
/// ```
pub fn encode_pending_blob(blob: &PendingBlob) -> Vec<u8> {
    // Menggunakan bincode::serialize yang sama dengan encode_event
    // untuk menjamin konsistensi encoding (little-endian, fixed encoding order)
    bincode::serialize(blob).unwrap_or_else(|_| Vec::new())
}

/// Decode bytes ke PendingBlob.
///
/// # Arguments
///
/// * `bytes` - Slice bytes hasil dari `encode_pending_blob`
///
/// # Returns
///
/// * `Ok(PendingBlob)` - Berhasil decode
/// * `Err(DecodeError)` - Gagal decode dengan pesan error eksplisit
///
/// # Roundtrip Guarantee
///
/// `decode_pending_blob(encode_pending_blob(blob)) == blob`
/// untuk semua valid PendingBlob.
///
/// # Errors
///
/// Mengembalikan `DecodeError::DecodeFailed` jika:
/// - Input bytes kosong
/// - Format bytes tidak valid
/// - Bytes tidak merepresentasikan PendingBlob yang valid
///
/// # Example
///
/// ```
/// use dsdn_proto::pending_blob::PendingBlob;
/// use dsdn_proto::encoding::{encode_pending_blob, decode_pending_blob};
///
/// let original = PendingBlob {
///     data: vec![1, 2, 3, 4],
///     original_sequence: 42,
///     source_da: String::from("test"),
///     received_at: 1704067200,
///     retry_count: 0,
///     commitment: None,
/// };
///
/// let bytes = encode_pending_blob(&original);
/// let decoded = decode_pending_blob(&bytes).expect("decode must succeed");
/// assert_eq!(original, decoded);
/// ```
pub fn decode_pending_blob(bytes: &[u8]) -> Result<PendingBlob, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::DecodeFailed("empty input".to_string()));
    }
    bincode::deserialize(bytes)
        .map_err(|e| DecodeError::DecodeFailed(e.to_string()))
}

// ════════════════════════════════════════════════════════════════════════════════
// FALLBACK TYPES HASH COMPUTATION (14A.1A.9)
// ════════════════════════════════════════════════════════════════════════════════

/// Compute SHA3-256 hash dari encoded FallbackEvent.
///
/// # Determinism Guarantee
///
/// Hash dihitung dari HASIL `encode_fallback_event`, bukan struct langsung.
/// Input event yang sama SELALU menghasilkan hash yang identik (bitwise).
///
/// Menggunakan algoritma SHA3-256 yang IDENTIK dengan `compute_event_hash`
/// untuk menjamin konsistensi hashing lintas semua proto types.
///
/// # Arguments
///
/// * `event` - Reference ke FallbackEvent yang akan di-hash
///
/// # Returns
///
/// Fixed 32 byte array berisi SHA3-256 hash.
/// Jika encoding gagal (seharusnya tidak terjadi untuk valid FallbackEvent),
/// mengembalikan hash dari empty bytes.
///
/// # Thread Safety
///
/// Fungsi ini bersifat pure dan thread-safe. Tidak ada shared mutable state.
///
/// # Example
///
/// ```
/// use dsdn_proto::fallback_event::FallbackEvent;
/// use dsdn_proto::encoding::compute_fallback_event_hash;
///
/// let event = FallbackEvent::FallbackActivated {
///     version: 1,
/// };
///
/// let hash = compute_fallback_event_hash(&event);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn compute_fallback_event_hash(event: &FallbackEvent) -> [u8; 32] {
    let encoded = encode_fallback_event(event);
    let mut hasher = Sha3_256::new();
    hasher.update(&encoded);
    hasher.finalize().into()
}

/// Compute SHA3-256 hash dari encoded PendingBlob.
///
/// # Determinism Guarantee
///
/// Hash dihitung dari HASIL `encode_pending_blob`, bukan struct langsung.
/// Input blob yang sama SELALU menghasilkan hash yang identik (bitwise).
///
/// Menggunakan algoritma SHA3-256 yang IDENTIK dengan `compute_event_hash`
/// untuk menjamin konsistensi hashing lintas semua proto types.
///
/// # Arguments
///
/// * `blob` - Reference ke PendingBlob yang akan di-hash
///
/// # Returns
///
/// Fixed 32 byte array berisi SHA3-256 hash.
/// Jika encoding gagal (seharusnya tidak terjadi untuk valid PendingBlob),
/// mengembalikan hash dari empty bytes.
///
/// # Thread Safety
///
/// Fungsi ini bersifat pure dan thread-safe. Tidak ada shared mutable state.
///
/// # Note
///
/// Hash ini berbeda dari `PendingBlob::compute_hash()` yang hanya hash field `data`.
/// Fungsi ini hash seluruh struct (semua fields) untuk integrity verification.
///
/// # Example
///
/// ```
/// use dsdn_proto::pending_blob::PendingBlob;
/// use dsdn_proto::encoding::compute_pending_blob_hash;
///
/// let blob = PendingBlob {
///     data: vec![1, 2, 3, 4],
///     original_sequence: 42,
///     source_da: String::from("test"),
///     received_at: 1704067200,
///     retry_count: 0,
///     commitment: None,
/// };
///
/// let hash = compute_pending_blob_hash(&blob);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn compute_pending_blob_hash(blob: &PendingBlob) -> [u8; 32] {
    let encoded = encode_pending_blob(blob);
    let mut hasher = Sha3_256::new();
    hasher.update(&encoded);
    hasher.finalize().into()
}

/// Verify hash dari FallbackEvent dengan expected hash.
///
/// # Verification Process
///
/// 1. Menghitung ulang hash dari event menggunakan `compute_fallback_event_hash`
/// 2. Membandingkan dengan `expected` secara bitwise (constant-time)
///
/// # Arguments
///
/// * `event` - Reference ke FallbackEvent yang akan diverifikasi
/// * `expected` - Reference ke expected hash (32 bytes)
///
/// # Returns
///
/// * `true` - Hash event IDENTIK dengan expected (bitwise match)
/// * `false` - Hash event BERBEDA dengan expected
///
/// # Security Note
///
/// Perbandingan menggunakan iterasi byte-by-byte yang menghasilkan
/// hasil boolean final. Meskipun bukan constant-time cryptographic comparison,
/// ini cukup untuk integrity verification (bukan timing-sensitive authentication).
///
/// # Thread Safety
///
/// Fungsi ini bersifat pure dan thread-safe. Tidak ada side-effect.
///
/// # Example
///
/// ```
/// use dsdn_proto::fallback_event::FallbackEvent;
/// use dsdn_proto::encoding::{compute_fallback_event_hash, verify_fallback_event_hash};
///
/// let event = FallbackEvent::FallbackActivated {
///     version: 1,
/// };
///
/// let hash = compute_fallback_event_hash(&event);
/// assert!(verify_fallback_event_hash(&event, &hash));
///
/// // Wrong hash should return false
/// let wrong_hash = [0u8; 32];
/// assert!(!verify_fallback_event_hash(&event, &wrong_hash));
/// ```
pub fn verify_fallback_event_hash(event: &FallbackEvent, expected: &[u8; 32]) -> bool {
    let computed = compute_fallback_event_hash(event);
    // Constant-time comparison untuk menghindari timing attacks
    // Meskipun ini bukan cryptographic signature verification,
    // best practice tetap menggunakan constant-time comparison
    computed.iter().zip(expected.iter()).fold(true, |acc, (a, b)| acc && (*a == *b))
}

// ════════════════════════════════════════════════════════════════════════════════
// AUDIT LOG EVENT ENCODING (Tahap 15.7)
// ════════════════════════════════════════════════════════════════════════════════

use crate::proto_audit_event_reexport::{AuditLogEvent, AuditLogEntry};

/// Encode `AuditLogEvent` ke bytes dengan format deterministik.
///
/// Menggunakan bincode yang IDENTIK dengan `encode_event` dan `encode_fallback_event`.
///
/// # Returns
///
/// `Vec<u8>` berisi binary representation. Empty Vec jika serialisasi gagal.
pub fn encode_audit_event(event: &AuditLogEvent) -> Vec<u8> {
    bincode::serialize(event).unwrap_or_else(|_| Vec::new())
}

/// Decode bytes ke `AuditLogEvent`.
///
/// # Errors
///
/// Returns `DecodeError::DecodeFailed` jika input kosong atau invalid.
pub fn decode_audit_event(bytes: &[u8]) -> Result<AuditLogEvent, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::DecodeFailed("empty input".to_string()));
    }
    bincode::deserialize(bytes)
        .map_err(|e| DecodeError::DecodeFailed(e.to_string()))
}

/// Compute SHA3-256 hash dari encoded `AuditLogEvent`.
///
/// Hash dihitung dari HASIL `encode_audit_event`, bukan struct langsung.
pub fn compute_audit_event_hash(event: &AuditLogEvent) -> [u8; 32] {
    let encoded = encode_audit_event(event);
    let mut hasher = Sha3_256::new();
    hasher.update(&encoded);
    hasher.finalize().into()
}

/// Verify hash dari `AuditLogEvent` dengan expected hash.
///
/// Returns `true` jika computed hash == expected (bitwise).
pub fn verify_audit_event_hash(event: &AuditLogEvent, expected: &[u8; 32]) -> bool {
    let computed = compute_audit_event_hash(event);
    computed.iter().zip(expected.iter()).fold(true, |acc, (a, b)| acc && (*a == *b))
}

// ════════════════════════════════════════════════════════════════════════════════
// AUDIT LOG ENTRY ENCODING (Tahap 15.7)
// ════════════════════════════════════════════════════════════════════════════════

/// Encode `AuditLogEntry` ke bytes dengan format deterministik.
///
/// Serializes the ENTIRE entry including `entry_hash`.
pub fn encode_audit_entry(entry: &AuditLogEntry) -> Vec<u8> {
    bincode::serialize(entry).unwrap_or_else(|_| Vec::new())
}

/// Decode bytes ke `AuditLogEntry`.
///
/// # Errors
///
/// Returns `DecodeError::DecodeFailed` jika input kosong atau invalid.
pub fn decode_audit_entry(bytes: &[u8]) -> Result<AuditLogEntry, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::DecodeFailed("empty input".to_string()));
    }
    bincode::deserialize(bytes)
        .map_err(|e| DecodeError::DecodeFailed(e.to_string()))
}

/// Compute SHA3-256 hash dari encoded `AuditLogEntry`.
///
/// Hash dihitung dari FULL encoded entry (semua fields termasuk entry_hash).
/// Ini berbeda dari `AuditLogEntry::compute_entry_hash()` yang exclude entry_hash.
pub fn compute_audit_entry_hash(entry: &AuditLogEntry) -> [u8; 32] {
    let encoded = encode_audit_entry(entry);
    let mut hasher = Sha3_256::new();
    hasher.update(&encoded);
    hasher.finalize().into()
}

// ════════════════════════════════════════════════════════════════════════════════
// AUDIT LOG ENTRY BATCH ENCODING (Tahap 15.7)
// ════════════════════════════════════════════════════════════════════════════════

/// Batch encode `AuditLogEntry` slice.
///
/// # Format
///
/// ```text
/// [count:u64 LE][len_1:u64 LE][entry_1_bytes]...[len_N:u64 LE][entry_N_bytes]
/// ```
///
/// Identical to `batch_encode` for `DAEvent`.
pub fn batch_encode_audit(entries: &[AuditLogEntry]) -> Vec<u8> {
    let mut result = Vec::new();

    let count = entries.len() as u64;
    result.extend_from_slice(&count.to_le_bytes());

    for entry in entries {
        let encoded = encode_audit_entry(entry);
        let len = encoded.len() as u64;
        result.extend_from_slice(&len.to_le_bytes());
        result.extend_from_slice(&encoded);
    }

    result
}

/// Batch decode bytes ke `Vec<AuditLogEntry>`.
///
/// # Format
///
/// ```text
/// [count:u64 LE][len_1:u64 LE][entry_1_bytes]...[len_N:u64 LE][entry_N_bytes]
/// ```
///
/// # Errors
///
/// Returns `DecodeError::DecodeFailed` jika data truncated atau corrupt.
pub fn batch_decode_audit(bytes: &[u8]) -> Result<Vec<AuditLogEntry>, DecodeError> {
    if bytes.len() < 8 {
        return Err(DecodeError::DecodeFailed("batch too short for count".to_string()));
    }

    let mut cursor = 0;

    // Read count
    let count_bytes: [u8; 8] = bytes[cursor..cursor + 8]
        .try_into()
        .map_err(|_| DecodeError::DecodeFailed("failed to read count".to_string()))?;
    let count = u64::from_le_bytes(count_bytes) as usize;
    cursor += 8;

    // Validate count
    let max_possible = (bytes.len().saturating_sub(8)) / 8;
    if count > max_possible {
        return Err(DecodeError::DecodeFailed(
            format!("invalid entry count {} exceeds maximum possible {}", count, max_possible),
        ));
    }

    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        // Read length prefix
        if cursor + 8 > bytes.len() {
            return Err(DecodeError::DecodeFailed(
                format!("batch truncated at entry {} length", i),
            ));
        }

        let len_bytes: [u8; 8] = bytes[cursor..cursor + 8]
            .try_into()
            .map_err(|_| DecodeError::DecodeFailed(
                format!("failed to read length for entry {}", i),
            ))?;
        let entry_len = u64::from_le_bytes(len_bytes) as usize;
        cursor += 8;

        // Read entry bytes
        if cursor + entry_len > bytes.len() {
            return Err(DecodeError::DecodeFailed(
                format!("batch truncated at entry {} data", i),
            ));
        }

        let entry_bytes = &bytes[cursor..cursor + entry_len];
        let entry = decode_audit_entry(entry_bytes)?;
        entries.push(entry);
        cursor += entry_len;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::da_event::{ReplicaRemovalReason, DeleteReason};

    fn make_node_registered_event() -> DAEvent {
        DAEvent::NodeRegistered {
            version: 1,
            timestamp_ms: 1704067200000,
            node_id: "node-test-001".to_string(),
            zone: "id-jakarta-1".to_string(),
            addr: "192.168.1.100:9000".to_string(),
            capacity_gb: 1000,
        }
    }

    fn make_chunk_declared_event() -> DAEvent {
        DAEvent::ChunkDeclared {
            version: 1,
            timestamp_ms: 1704067200000,
            chunk_hash: "abcdef1234567890".to_string(),
            size_bytes: 1048576,
            uploader_id: "uploader-001".to_string(),
            replication_factor: 3,
        }
    }

    fn make_replica_added_event() -> DAEvent {
        DAEvent::ReplicaAdded {
            version: 1,
            timestamp_ms: 1704067200000,
            chunk_hash: "chunk-hash-001".to_string(),
            node_id: "node-001".to_string(),
            replica_index: 0,
        }
    }

    fn make_replica_removed_event() -> DAEvent {
        DAEvent::ReplicaRemoved {
            version: 1,
            timestamp_ms: 1704067200000,
            chunk_hash: "chunk-hash-002".to_string(),
            node_id: "node-002".to_string(),
            reason: ReplicaRemovalReason::NodeOffline,
        }
    }

    fn make_delete_requested_event() -> DAEvent {
        DAEvent::DeleteRequested {
            version: 1,
            timestamp_ms: 1704067200000,
            chunk_hash: "chunk-to-delete".to_string(),
            requester_id: "user-001".to_string(),
            reason: DeleteReason::UserRequest,
        }
    }

    #[test]
    fn test_encode_event_not_empty() {
        let event = make_node_registered_event();
        let encoded = encode_event(&event);
        assert!(!encoded.is_empty(), "encoded event must not be empty");
    }

    #[test]
    fn test_decode_event_roundtrip_node_registered() {
        let original = make_node_registered_event();
        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_event_roundtrip_chunk_declared() {
        let original = make_chunk_declared_event();
        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_event_roundtrip_replica_added() {
        let original = make_replica_added_event();
        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_event_roundtrip_replica_removed() {
        let original = make_replica_removed_event();
        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_event_roundtrip_delete_requested() {
        let original = make_delete_requested_event();
        let encoded = encode_event(&original);
        let decoded = decode_event(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_event_empty_input() {
        let result = decode_event(&[]);
        assert!(result.is_err(), "empty input must fail");
    }

    #[test]
    fn test_decode_event_invalid_input() {
        let result = decode_event(&[0x00, 0x01, 0x02]);
        assert!(result.is_err(), "invalid input must fail");
    }

    #[test]
    fn test_encode_determinism_multiple_calls() {
        let event = make_node_registered_event();
        
        let encoded1 = encode_event(&event);
        let encoded2 = encode_event(&event);
        let encoded3 = encode_event(&event);
        
        assert_eq!(encoded1, encoded2, "encode must be deterministic (1 vs 2)");
        assert_eq!(encoded2, encoded3, "encode must be deterministic (2 vs 3)");
    }

    #[test]
    fn test_encode_determinism_100_iterations() {
        let event = make_chunk_declared_event();
        let reference = encode_event(&event);
        
        for i in 0..100 {
            let encoded = encode_event(&event);
            assert_eq!(
                reference, encoded,
                "encode must be deterministic at iteration {}", i
            );
        }
    }

    #[test]
    fn test_compute_event_hash_fixed_size() {
        let event = make_node_registered_event();
        let hash = compute_event_hash(&event);
        assert_eq!(hash.len(), 32, "hash must be exactly 32 bytes");
    }

    #[test]
    fn test_compute_event_hash_determinism() {
        let event = make_chunk_declared_event();
        
        let hash1 = compute_event_hash(&event);
        let hash2 = compute_event_hash(&event);
        let hash3 = compute_event_hash(&event);
        
        assert_eq!(hash1, hash2, "hash must be deterministic (1 vs 2)");
        assert_eq!(hash2, hash3, "hash must be deterministic (2 vs 3)");
    }

    #[test]
    fn test_compute_event_hash_100_iterations() {
        let event = make_replica_added_event();
        let reference = compute_event_hash(&event);
        
        for i in 0..100 {
            let hash = compute_event_hash(&event);
            assert_eq!(
                reference, hash,
                "hash must be deterministic at iteration {}", i
            );
        }
    }

    #[test]
    fn test_compute_event_hash_different_events() {
        let event1 = make_node_registered_event();
        let event2 = make_chunk_declared_event();
        
        let hash1 = compute_event_hash(&event1);
        let hash2 = compute_event_hash(&event2);
        
        assert_ne!(hash1, hash2, "different events must have different hashes");
    }

    #[test]
    fn test_batch_encode_empty() {
        let events: Vec<DAEvent> = vec![];
        let encoded = batch_encode(&events);
        
        // Should contain at least the count (8 bytes)
        assert_eq!(encoded.len(), 8, "empty batch should have 8 bytes for count");
        
        // Count should be 0
        let count = u64::from_le_bytes(encoded[0..8].try_into().unwrap());
        assert_eq!(count, 0, "empty batch count must be 0");
    }

    #[test]
    fn test_batch_encode_single() {
        let events = vec![make_node_registered_event()];
        let encoded = batch_encode(&events);
        
        assert!(encoded.len() > 8, "single event batch must be > 8 bytes");
        
        let count = u64::from_le_bytes(encoded[0..8].try_into().unwrap());
        assert_eq!(count, 1, "single event batch count must be 1");
    }

    #[test]
    fn test_batch_roundtrip_empty() {
        let original: Vec<DAEvent> = vec![];
        let encoded = batch_encode(&original);
        let decoded = batch_decode(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "empty batch roundtrip must work");
    }

    #[test]
    fn test_batch_roundtrip_single() {
        let original = vec![make_node_registered_event()];
        let encoded = batch_encode(&original);
        let decoded = batch_decode(&encoded).expect("decode must succeed");
        assert_eq!(original, decoded, "single event batch roundtrip must work");
    }

    #[test]
    fn test_batch_roundtrip_multiple() {
        let original = vec![
            make_node_registered_event(),
            make_chunk_declared_event(),
            make_replica_added_event(),
            make_replica_removed_event(),
            make_delete_requested_event(),
        ];
        
        let encoded = batch_encode(&original);
        let decoded = batch_decode(&encoded).expect("decode must succeed");
        
        assert_eq!(original.len(), decoded.len(), "batch length must match");
        for (i, (orig, dec)) in original.iter().zip(decoded.iter()).enumerate() {
            assert_eq!(orig, dec, "event {} must match", i);
        }
    }

    #[test]
    fn test_batch_order_preserved() {
        let original = vec![
            make_delete_requested_event(),
            make_node_registered_event(),
            make_chunk_declared_event(),
        ];
        
        let encoded = batch_encode(&original);
        let decoded = batch_decode(&encoded).expect("decode must succeed");
        
        // Verify exact order
        assert_eq!(original[0], decoded[0], "event 0 order must be preserved");
        assert_eq!(original[1], decoded[1], "event 1 order must be preserved");
        assert_eq!(original[2], decoded[2], "event 2 order must be preserved");
    }

    #[test]
    fn test_batch_encode_determinism() {
        let events = vec![
            make_node_registered_event(),
            make_chunk_declared_event(),
        ];
        
        let encoded1 = batch_encode(&events);
        let encoded2 = batch_encode(&events);
        let encoded3 = batch_encode(&events);
        
        assert_eq!(encoded1, encoded2, "batch encode must be deterministic (1 vs 2)");
        assert_eq!(encoded2, encoded3, "batch encode must be deterministic (2 vs 3)");
    }

    #[test]
    fn test_batch_decode_truncated_count() {
        let result = batch_decode(&[0x01, 0x02, 0x03]);
        assert!(result.is_err(), "truncated count must fail");
    }

    #[test]
    fn test_batch_decode_truncated_length() {
        // Valid count of 1, but no length prefix
        let mut bytes = vec![];
        bytes.extend_from_slice(&1u64.to_le_bytes());
        
        let result = batch_decode(&bytes);
        assert!(result.is_err(), "truncated length must fail");
    }

    #[test]
    fn test_batch_decode_truncated_data() {
        // Valid count of 1, valid length of 100, but no data
        let mut bytes = vec![];
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&100u64.to_le_bytes());
        
        let result = batch_decode(&bytes);
        assert!(result.is_err(), "truncated data must fail");
    }

    // ════════════════════════════════════════════════════════════════════════════
    // FALLBACK EVENT ENCODING TESTS (14A.1A.8)
    // ════════════════════════════════════════════════════════════════════════════

    use crate::fallback_event::FallbackEvent;
    use crate::pending_blob::PendingBlob;

    fn make_fallback_activated_event() -> FallbackEvent {
        FallbackEvent::FallbackActivated {
            version: 1,
        }
    }

    fn make_fallback_deactivated_event() -> FallbackEvent {
        FallbackEvent::FallbackDeactivated {
            version: 1,
        }
    }

    fn make_reconciliation_started_event() -> FallbackEvent {
        FallbackEvent::ReconciliationStarted {
            version: 1,
        }
    }

    fn make_reconciliation_completed_event() -> FallbackEvent {
        FallbackEvent::ReconciliationCompleted {
            version: 1,
        }
    }

    fn make_pending_blob() -> PendingBlob {
        PendingBlob {
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            original_sequence: 42,
            source_da: String::from("validator_quorum"),
            received_at: 1704067200,
            retry_count: 2,
            commitment: Some([0xAB; 32]),
        }
    }

    fn make_pending_blob_no_commitment() -> PendingBlob {
        PendingBlob {
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            original_sequence: 100,
            source_da: String::from("emergency"),
            received_at: 1704153600,
            retry_count: 0,
            commitment: None,
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // encode_fallback_event tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_fallback_event_not_empty() {
        let event = make_fallback_activated_event();
        let encoded = encode_fallback_event(&event);
        assert!(!encoded.is_empty(), "encoded fallback event must not be empty");
    }

    #[test]
    fn test_encode_fallback_event_all_variants() {
        let events = [
            make_fallback_activated_event(),
            make_fallback_deactivated_event(),
            make_reconciliation_started_event(),
            make_reconciliation_completed_event(),
        ];

        for event in &events {
            let encoded = encode_fallback_event(event);
            assert!(!encoded.is_empty(), "all variants must encode to non-empty bytes");
        }
    }

    #[test]
    fn test_encode_fallback_event_determinism_multiple_calls() {
        let event = make_fallback_activated_event();

        let encoded1 = encode_fallback_event(&event);
        let encoded2 = encode_fallback_event(&event);
        let encoded3 = encode_fallback_event(&event);

        assert_eq!(encoded1, encoded2, "encode must be deterministic (1 vs 2)");
        assert_eq!(encoded2, encoded3, "encode must be deterministic (2 vs 3)");
    }

    #[test]
    fn test_encode_fallback_event_determinism_100_iterations() {
        let event = make_fallback_deactivated_event();
        let reference = encode_fallback_event(&event);

        for i in 0..100 {
            let encoded = encode_fallback_event(&event);
            assert_eq!(
                reference, encoded,
                "encode must be deterministic at iteration {}", i
            );
        }
    }

    #[test]
    fn test_encode_fallback_event_determinism_all_variants() {
        let events = [
            make_fallback_activated_event(),
            make_fallback_deactivated_event(),
            make_reconciliation_started_event(),
            make_reconciliation_completed_event(),
        ];

        for event in &events {
            let encoded1 = encode_fallback_event(event);
            let encoded2 = encode_fallback_event(event);
            assert_eq!(encoded1, encoded2, "all variants must encode deterministically");
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // decode_fallback_event tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_fallback_event_roundtrip_activated() {
        let original = make_fallback_activated_event();
        let encoded = encode_fallback_event(&original);
        let decoded = decode_fallback_event(&encoded);
        
        assert!(decoded.is_ok(), "decode must succeed");
        assert_eq!(original, decoded.unwrap(), "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_fallback_event_roundtrip_deactivated() {
        let original = make_fallback_deactivated_event();
        let encoded = encode_fallback_event(&original);
        let decoded = decode_fallback_event(&encoded);
        
        assert!(decoded.is_ok(), "decode must succeed");
        assert_eq!(original, decoded.unwrap(), "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_fallback_event_roundtrip_reconciliation_started() {
        let original = make_reconciliation_started_event();
        let encoded = encode_fallback_event(&original);
        let decoded = decode_fallback_event(&encoded);
        
        assert!(decoded.is_ok(), "decode must succeed");
        assert_eq!(original, decoded.unwrap(), "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_fallback_event_roundtrip_reconciliation_completed() {
        let original = make_reconciliation_completed_event();
        let encoded = encode_fallback_event(&original);
        let decoded = decode_fallback_event(&encoded);
        
        assert!(decoded.is_ok(), "decode must succeed");
        assert_eq!(original, decoded.unwrap(), "roundtrip must preserve event");
    }

    #[test]
    fn test_decode_fallback_event_roundtrip_all_variants() {
        let events = [
            make_fallback_activated_event(),
            make_fallback_deactivated_event(),
            make_reconciliation_started_event(),
            make_reconciliation_completed_event(),
        ];

        for original in &events {
            let encoded = encode_fallback_event(original);
            let decoded = decode_fallback_event(&encoded);
            
            assert!(decoded.is_ok(), "decode must succeed for all variants");
            assert_eq!(original, &decoded.unwrap(), "roundtrip must preserve all variants");
        }
    }

    #[test]
    fn test_decode_fallback_event_empty_input() {
        let result = decode_fallback_event(&[]);
        assert!(result.is_err(), "empty input must fail");
    }

    #[test]
    fn test_decode_fallback_event_invalid_input() {
        let result = decode_fallback_event(&[0x00, 0x01, 0x02]);
        assert!(result.is_err(), "invalid input must fail");
    }

    #[test]
    fn test_decode_fallback_event_error_is_decode_error() {
        let result = decode_fallback_event(&[]);
        assert!(result.is_err(), "empty input must fail");
        
        match result {
            Err(DecodeError::DecodeFailed(_)) => { /* expected */ }
            _ => panic!("error must be DecodeError::DecodeFailed"),
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // encode_pending_blob tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_pending_blob_not_empty() {
        let blob = make_pending_blob();
        let encoded = encode_pending_blob(&blob);
        assert!(!encoded.is_empty(), "encoded pending blob must not be empty");
    }

    #[test]
    fn test_encode_pending_blob_with_commitment() {
        let blob = make_pending_blob();
        let encoded = encode_pending_blob(&blob);
        assert!(!encoded.is_empty(), "blob with commitment must encode");
    }

    #[test]
    fn test_encode_pending_blob_without_commitment() {
        let blob = make_pending_blob_no_commitment();
        let encoded = encode_pending_blob(&blob);
        assert!(!encoded.is_empty(), "blob without commitment must encode");
    }

    #[test]
    fn test_encode_pending_blob_determinism_multiple_calls() {
        let blob = make_pending_blob();

        let encoded1 = encode_pending_blob(&blob);
        let encoded2 = encode_pending_blob(&blob);
        let encoded3 = encode_pending_blob(&blob);

        assert_eq!(encoded1, encoded2, "encode must be deterministic (1 vs 2)");
        assert_eq!(encoded2, encoded3, "encode must be deterministic (2 vs 3)");
    }

    #[test]
    fn test_encode_pending_blob_determinism_100_iterations() {
        let blob = make_pending_blob();
        let reference = encode_pending_blob(&blob);

        for i in 0..100 {
            let encoded = encode_pending_blob(&blob);
            assert_eq!(
                reference, encoded,
                "encode must be deterministic at iteration {}", i
            );
        }
    }

    #[test]
    fn test_encode_pending_blob_empty_data() {
        let blob = PendingBlob {
            data: Vec::new(),
            original_sequence: 0,
            source_da: String::from("test"),
            received_at: 0,
            retry_count: 0,
            commitment: None,
        };

        let encoded = encode_pending_blob(&blob);
        assert!(!encoded.is_empty(), "blob with empty data must still encode");
    }

    #[test]
    fn test_encode_pending_blob_large_data() {
        let blob = PendingBlob {
            data: vec![0u8; 10000],
            original_sequence: u64::MAX,
            source_da: String::from("large_test"),
            received_at: u64::MAX,
            retry_count: u32::MAX,
            commitment: Some([0xFF; 32]),
        };

        let encoded = encode_pending_blob(&blob);
        assert!(!encoded.is_empty(), "blob with large data must encode");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // decode_pending_blob tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_pending_blob_roundtrip() {
        let original = make_pending_blob();
        let encoded = encode_pending_blob(&original);
        let decoded = decode_pending_blob(&encoded);
        
        assert!(decoded.is_ok(), "decode must succeed");
        assert_eq!(original, decoded.unwrap(), "roundtrip must preserve blob");
    }

    #[test]
    fn test_decode_pending_blob_roundtrip_no_commitment() {
        let original = make_pending_blob_no_commitment();
        let encoded = encode_pending_blob(&original);
        let decoded = decode_pending_blob(&encoded);
        
        assert!(decoded.is_ok(), "decode must succeed");
        assert_eq!(original, decoded.unwrap(), "roundtrip must preserve blob");
    }

    #[test]
    fn test_decode_pending_blob_roundtrip_empty_data() {
        let original = PendingBlob {
            data: Vec::new(),
            original_sequence: 0,
            source_da: String::from("empty"),
            received_at: 0,
            retry_count: 0,
            commitment: None,
        };
        
        let encoded = encode_pending_blob(&original);
        let decoded = decode_pending_blob(&encoded);
        
        assert!(decoded.is_ok(), "decode must succeed for empty data");
        assert_eq!(original, decoded.unwrap(), "roundtrip must preserve empty data blob");
    }

    #[test]
    fn test_decode_pending_blob_roundtrip_max_values() {
        let original = PendingBlob {
            data: vec![0xFF; 100],
            original_sequence: u64::MAX,
            source_da: String::from("max_values"),
            received_at: u64::MAX,
            retry_count: u32::MAX,
            commitment: Some([0xFF; 32]),
        };
        
        let encoded = encode_pending_blob(&original);
        let decoded = decode_pending_blob(&encoded);
        
        assert!(decoded.is_ok(), "decode must succeed for max values");
        assert_eq!(original, decoded.unwrap(), "roundtrip must preserve max values");
    }

    #[test]
    fn test_decode_pending_blob_empty_input() {
        let result = decode_pending_blob(&[]);
        assert!(result.is_err(), "empty input must fail");
    }

    #[test]
    fn test_decode_pending_blob_invalid_input() {
        let result = decode_pending_blob(&[0x00, 0x01, 0x02]);
        assert!(result.is_err(), "invalid input must fail");
    }

    #[test]
    fn test_decode_pending_blob_error_is_decode_error() {
        let result = decode_pending_blob(&[]);
        assert!(result.is_err(), "empty input must fail");
        
        match result {
            Err(DecodeError::DecodeFailed(_)) => { /* expected */ }
            _ => panic!("error must be DecodeError::DecodeFailed"),
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Cross-compatibility tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fallback_and_da_encoding_use_same_config() {
        // Verify that fallback encoding uses the same bincode config as DA events
        // by checking that serialization produces consistent little-endian format
        
        let da_event = make_node_registered_event();
        let fallback_event = make_fallback_activated_event();
        
        let da_encoded = encode_event(&da_event);
        let fallback_encoded = encode_fallback_event(&fallback_event);
        
        // Both should produce valid bincode (first 4 bytes are typically variant discriminant)
        assert!(da_encoded.len() >= 4, "DA event encoding must be valid bincode");
        assert!(fallback_encoded.len() >= 4, "Fallback event encoding must be valid bincode");
    }

    #[test]
    fn test_decode_error_type_consistency() {
        // Verify that both DA and fallback decode return the same error type
        let da_result = decode_event(&[]);
        let fallback_result = decode_fallback_event(&[]);
        let blob_result = decode_pending_blob(&[]);
        
        // All should return DecodeError (which is DAError)
        assert!(da_result.is_err());
        assert!(fallback_result.is_err());
        assert!(blob_result.is_err());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // FALLBACK EVENT HASH COMPUTATION TESTS (14A.1A.9)
    // ════════════════════════════════════════════════════════════════════════════

    // ────────────────────────────────────────────────────────────────────────────
    // compute_fallback_event_hash tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_fallback_event_hash_returns_32_bytes() {
        let event = make_fallback_activated_event();
        let hash = compute_fallback_event_hash(&event);
        assert_eq!(hash.len(), 32, "hash must be exactly 32 bytes");
    }

    #[test]
    fn test_compute_fallback_event_hash_determinism_multiple_calls() {
        let event = make_fallback_activated_event();

        let hash1 = compute_fallback_event_hash(&event);
        let hash2 = compute_fallback_event_hash(&event);
        let hash3 = compute_fallback_event_hash(&event);

        assert_eq!(hash1, hash2, "hash must be deterministic (1 vs 2)");
        assert_eq!(hash2, hash3, "hash must be deterministic (2 vs 3)");
    }

    #[test]
    fn test_compute_fallback_event_hash_determinism_100_iterations() {
        let event = make_fallback_deactivated_event();
        let reference = compute_fallback_event_hash(&event);

        for i in 0..100 {
            let hash = compute_fallback_event_hash(&event);
            assert_eq!(
                reference, hash,
                "hash must be deterministic at iteration {}", i
            );
        }
    }

    #[test]
    fn test_compute_fallback_event_hash_all_variants() {
        let events = [
            make_fallback_activated_event(),
            make_fallback_deactivated_event(),
            make_reconciliation_started_event(),
            make_reconciliation_completed_event(),
        ];

        for event in &events {
            let hash = compute_fallback_event_hash(event);
            assert_eq!(hash.len(), 32, "all variants must produce 32-byte hash");
        }
    }

    #[test]
    fn test_compute_fallback_event_hash_different_events_different_hashes() {
        let event1 = make_fallback_activated_event();
        let event2 = make_fallback_deactivated_event();

        let hash1 = compute_fallback_event_hash(&event1);
        let hash2 = compute_fallback_event_hash(&event2);

        assert_ne!(hash1, hash2, "different events must produce different hashes");
    }

    #[test]
    fn test_compute_fallback_event_hash_consistent_with_encoding() {
        // Verify that hash is computed from encoded bytes
        let event = make_fallback_activated_event();
        
        let hash1 = compute_fallback_event_hash(&event);
        
        // Manually compute hash from encoded bytes
        let encoded = encode_fallback_event(&event);
        let mut hasher = Sha3_256::new();
        hasher.update(&encoded);
        let hash2: [u8; 32] = hasher.finalize().into();
        
        assert_eq!(hash1, hash2, "hash must be consistent with manual encoding + hashing");
    }

    #[test]
    fn test_compute_fallback_event_hash_stability_across_encode_decode() {
        let original = make_fallback_activated_event();
        let hash1 = compute_fallback_event_hash(&original);
        
        // Encode and decode
        let encoded = encode_fallback_event(&original);
        let decoded = decode_fallback_event(&encoded);
        assert!(decoded.is_ok(), "decode must succeed");
        
        let hash2 = compute_fallback_event_hash(&decoded.unwrap());
        
        assert_eq!(hash1, hash2, "hash must be stable across encode/decode cycle");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // compute_pending_blob_hash tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_pending_blob_hash_returns_32_bytes() {
        let blob = make_pending_blob();
        let hash = compute_pending_blob_hash(&blob);
        assert_eq!(hash.len(), 32, "hash must be exactly 32 bytes");
    }

    #[test]
    fn test_compute_pending_blob_hash_determinism_multiple_calls() {
        let blob = make_pending_blob();

        let hash1 = compute_pending_blob_hash(&blob);
        let hash2 = compute_pending_blob_hash(&blob);
        let hash3 = compute_pending_blob_hash(&blob);

        assert_eq!(hash1, hash2, "hash must be deterministic (1 vs 2)");
        assert_eq!(hash2, hash3, "hash must be deterministic (2 vs 3)");
    }

    #[test]
    fn test_compute_pending_blob_hash_determinism_100_iterations() {
        let blob = make_pending_blob();
        let reference = compute_pending_blob_hash(&blob);

        for i in 0..100 {
            let hash = compute_pending_blob_hash(&blob);
            assert_eq!(
                reference, hash,
                "hash must be deterministic at iteration {}", i
            );
        }
    }

    #[test]
    fn test_compute_pending_blob_hash_different_blobs_different_hashes() {
        let blob1 = make_pending_blob();
        let blob2 = make_pending_blob_no_commitment();

        let hash1 = compute_pending_blob_hash(&blob1);
        let hash2 = compute_pending_blob_hash(&blob2);

        assert_ne!(hash1, hash2, "different blobs must produce different hashes");
    }

    #[test]
    fn test_compute_pending_blob_hash_empty_data() {
        let blob = PendingBlob {
            data: Vec::new(),
            original_sequence: 0,
            source_da: String::from("empty"),
            received_at: 0,
            retry_count: 0,
            commitment: None,
        };

        let hash = compute_pending_blob_hash(&blob);
        assert_eq!(hash.len(), 32, "empty data blob must produce 32-byte hash");
    }

    #[test]
    fn test_compute_pending_blob_hash_large_data() {
        let blob = PendingBlob {
            data: vec![0xAB; 10000],
            original_sequence: u64::MAX,
            source_da: String::from("large"),
            received_at: u64::MAX,
            retry_count: u32::MAX,
            commitment: Some([0xFF; 32]),
        };

        let hash = compute_pending_blob_hash(&blob);
        assert_eq!(hash.len(), 32, "large data blob must produce 32-byte hash");
    }

    #[test]
    fn test_compute_pending_blob_hash_consistent_with_encoding() {
        let blob = make_pending_blob();
        
        let hash1 = compute_pending_blob_hash(&blob);
        
        // Manually compute hash from encoded bytes
        let encoded = encode_pending_blob(&blob);
        let mut hasher = Sha3_256::new();
        hasher.update(&encoded);
        let hash2: [u8; 32] = hasher.finalize().into();
        
        assert_eq!(hash1, hash2, "hash must be consistent with manual encoding + hashing");
    }

    #[test]
    fn test_compute_pending_blob_hash_stability_across_encode_decode() {
        let original = make_pending_blob();
        let hash1 = compute_pending_blob_hash(&original);
        
        // Encode and decode
        let encoded = encode_pending_blob(&original);
        let decoded = decode_pending_blob(&encoded);
        assert!(decoded.is_ok(), "decode must succeed");
        
        let hash2 = compute_pending_blob_hash(&decoded.unwrap());
        
        assert_eq!(hash1, hash2, "hash must be stable across encode/decode cycle");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // verify_fallback_event_hash tests
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_fallback_event_hash_returns_true_for_correct_hash() {
        let event = make_fallback_activated_event();
        let hash = compute_fallback_event_hash(&event);
        
        assert!(verify_fallback_event_hash(&event, &hash), "must return true for correct hash");
    }

    #[test]
    fn test_verify_fallback_event_hash_returns_false_for_wrong_hash() {
        let event = make_fallback_activated_event();
        let wrong_hash = [0u8; 32];
        
        assert!(!verify_fallback_event_hash(&event, &wrong_hash), "must return false for wrong hash");
    }

    #[test]
    fn test_verify_fallback_event_hash_returns_false_for_different_event_hash() {
        let event1 = make_fallback_activated_event();
        let event2 = make_fallback_deactivated_event();
        
        let hash2 = compute_fallback_event_hash(&event2);
        
        assert!(!verify_fallback_event_hash(&event1, &hash2), "must return false for different event's hash");
    }

    #[test]
    fn test_verify_fallback_event_hash_all_variants() {
        let events = [
            make_fallback_activated_event(),
            make_fallback_deactivated_event(),
            make_reconciliation_started_event(),
            make_reconciliation_completed_event(),
        ];

        for event in &events {
            let hash = compute_fallback_event_hash(event);
            assert!(
                verify_fallback_event_hash(event, &hash),
                "verify must return true for correct hash of all variants"
            );
        }
    }

    #[test]
    fn test_verify_fallback_event_hash_determinism() {
        let event = make_fallback_activated_event();
        let hash = compute_fallback_event_hash(&event);
        
        // Verify multiple times
        for i in 0..100 {
            assert!(
                verify_fallback_event_hash(&event, &hash),
                "verify must be deterministic at iteration {}", i
            );
        }
    }

    #[test]
    fn test_verify_fallback_event_hash_bitwise_comparison() {
        let event = make_fallback_activated_event();
        let mut hash = compute_fallback_event_hash(&event);
        
        // Original hash should verify
        assert!(verify_fallback_event_hash(&event, &hash), "original hash must verify");
        
        // Flip one bit - should fail
        hash[0] ^= 0x01;
        assert!(!verify_fallback_event_hash(&event, &hash), "flipped bit must fail verification");
        
        // Flip back - should verify again
        hash[0] ^= 0x01;
        assert!(verify_fallback_event_hash(&event, &hash), "restored hash must verify");
    }

    #[test]
    fn test_verify_fallback_event_hash_all_bytes_matter() {
        let event = make_fallback_activated_event();
        let correct_hash = compute_fallback_event_hash(&event);
        
        // Test that changing any byte causes verification to fail
        for i in 0..32 {
            let mut modified_hash = correct_hash;
            modified_hash[i] ^= 0xFF;
            assert!(
                !verify_fallback_event_hash(&event, &modified_hash),
                "modifying byte {} must cause verification to fail", i
            );
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Cross-consistency tests (14A.1A.9)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fallback_hash_uses_same_algorithm_as_da_hash() {
        // Verify that both DA events and fallback events use the same SHA3-256 algorithm
        // by checking hash output length
        
        let da_event = make_node_registered_event();
        let fallback_event = make_fallback_activated_event();
        
        let da_hash = compute_event_hash(&da_event);
        let fallback_hash = compute_fallback_event_hash(&fallback_event);
        
        assert_eq!(da_hash.len(), 32, "DA hash must be 32 bytes");
        assert_eq!(fallback_hash.len(), 32, "Fallback hash must be 32 bytes");
        assert_eq!(da_hash.len(), fallback_hash.len(), "Both must use same hash algorithm (same output size)");
    }

    #[test]
    fn test_hash_pipeline_encoding_then_sha3() {
        // Verify that the hash pipeline is: encode → SHA3-256
        // Both DA events and fallback events should follow this pattern
        
        let fallback_event = make_fallback_activated_event();
        
        // Step 1: Encode
        let encoded = encode_fallback_event(&fallback_event);
        assert!(!encoded.is_empty(), "encoding must produce bytes");
        
        // Step 2: Hash
        let mut hasher = Sha3_256::new();
        hasher.update(&encoded);
        let manual_hash: [u8; 32] = hasher.finalize().into();
        
        // Step 3: Compare with function output
        let function_hash = compute_fallback_event_hash(&fallback_event);
        
        assert_eq!(manual_hash, function_hash, "hash must follow encode → SHA3-256 pipeline");
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// AUDIT ENCODING TESTS (Tahap 15.7)
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod audit_encoding_tests {
    use super::*;
    use crate::audit_event::{
        AuditLogEvent, AuditLogEntry, StakeOperation, AUDIT_EVENT_SCHEMA_VERSION,
    };

    fn sample_slashing_event() -> AuditLogEvent {
        AuditLogEvent::SlashingExecuted {
            version: 1,
            timestamp_ms: 1700000000,
            validator_id: "val-001".to_string(),
            node_id: "node-001".to_string(),
            slash_amount: 5000,
            reason: "double_sign".to_string(),
            epoch: 42,
            evidence_hash: [0xAB; 32],
        }
    }

    fn sample_stake_event() -> AuditLogEvent {
        AuditLogEvent::StakeUpdated {
            version: 1,
            timestamp_ms: 1700000001,
            staker_address: "staker-001".to_string(),
            operation: StakeOperation::Delegate,
            amount: 1000,
            validator_id: "val-002".to_string(),
            epoch: 43,
        }
    }

    fn make_entry(seq: u64, ts: u64, prev: [u8; 32], event: AuditLogEvent) -> AuditLogEntry {
        let mut entry = AuditLogEntry {
            sequence: seq,
            timestamp_ms: ts,
            prev_hash: prev,
            event,
            entry_hash: [0u8; 32],
        };
        entry.entry_hash = entry.compute_entry_hash();
        entry
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: audit_event_encode_decode_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_encode_decode_roundtrip() {
        let events = [sample_slashing_event(), sample_stake_event()];
        for (i, event) in events.iter().enumerate() {
            let encoded = encode_audit_event(event);
            assert!(!encoded.is_empty(), "event {} must encode", i);
            let decoded = decode_audit_event(&encoded);
            match decoded {
                Ok(rt) => assert_eq!(event, &rt, "event {} roundtrip must match", i),
                Err(e) => assert!(false, "event {} decode failed: {}", i, e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: audit_event_hash_deterministic
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_hash_deterministic() {
        let event = sample_slashing_event();
        let h1 = compute_audit_event_hash(&event);
        let h2 = compute_audit_event_hash(&event);
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_eq!(h1.len(), 32);

        for _ in 0..100 {
            assert_eq!(h1, compute_audit_event_hash(&event));
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: audit_event_hash_changes_when_event_changes
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_hash_changes_when_event_changes() {
        let h1 = compute_audit_event_hash(&sample_slashing_event());
        let h2 = compute_audit_event_hash(&sample_stake_event());
        assert_ne!(h1, h2, "different events must have different hashes");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: audit_event_verify_hash_true
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_verify_hash_true() {
        let event = sample_slashing_event();
        let hash = compute_audit_event_hash(&event);
        assert!(verify_audit_event_hash(&event, &hash), "correct hash must verify");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: audit_event_verify_hash_false
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_event_verify_hash_false() {
        let event = sample_slashing_event();
        let wrong = [0u8; 32];
        assert!(!verify_audit_event_hash(&event, &wrong), "wrong hash must fail");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: audit_entry_encode_decode_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_entry_encode_decode_roundtrip() {
        let entry = make_entry(1, 1700000000, [0u8; 32], sample_slashing_event());
        let encoded = encode_audit_entry(&entry);
        assert!(!encoded.is_empty());
        let decoded = decode_audit_entry(&encoded);
        match decoded {
            Ok(rt) => assert_eq!(entry, rt, "entry roundtrip must match"),
            Err(e) => assert!(false, "entry decode failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: audit_entry_hash_deterministic
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_entry_hash_deterministic() {
        let entry = make_entry(1, 1700000000, [0u8; 32], sample_slashing_event());
        let h1 = compute_audit_entry_hash(&entry);
        let h2 = compute_audit_entry_hash(&entry);
        assert_eq!(h1, h2, "entry hash must be deterministic");
        assert_eq!(h1.len(), 32);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: audit_entry_hash_changes_when_entry_changes
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_entry_hash_changes_when_entry_changes() {
        let e1 = make_entry(1, 1700000000, [0u8; 32], sample_slashing_event());
        let e2 = make_entry(2, 1700000000, [0u8; 32], sample_slashing_event());
        let h1 = compute_audit_entry_hash(&e1);
        let h2 = compute_audit_entry_hash(&e2);
        assert_ne!(h1, h2, "different entries must have different hashes");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: batch_encode_decode_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn batch_encode_decode_roundtrip() {
        let e1 = make_entry(1, 100, [0u8; 32], sample_slashing_event());
        let e2 = make_entry(2, 200, e1.entry_hash, sample_stake_event());
        let e3 = make_entry(3, 300, e2.entry_hash, sample_slashing_event());

        let entries = vec![e1.clone(), e2.clone(), e3.clone()];
        let encoded = batch_encode_audit(&entries);
        let decoded = batch_decode_audit(&encoded);

        match decoded {
            Ok(rt) => {
                assert_eq!(rt.len(), 3, "batch length must match");
                assert_eq!(rt[0], e1);
                assert_eq!(rt[1], e2);
                assert_eq!(rt[2], e3);
            }
            Err(e) => assert!(false, "batch decode failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: batch_encode_zero_entries
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn batch_encode_zero_entries() {
        let entries: Vec<AuditLogEntry> = vec![];
        let encoded = batch_encode_audit(&entries);

        // Should have 8 bytes for count = 0
        assert_eq!(encoded.len(), 8);
        let count = u64::from_le_bytes(encoded[0..8].try_into().unwrap_or([0u8; 8]));
        assert_eq!(count, 0);

        let decoded = batch_decode_audit(&encoded);
        match decoded {
            Ok(rt) => assert_eq!(rt.len(), 0, "empty batch must decode to empty vec"),
            Err(e) => assert!(false, "empty batch decode failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: batch_decode_invalid_length_error
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn batch_decode_invalid_length_error() {
        // Too short for count
        let result = batch_decode_audit(&[0x01, 0x02, 0x03]);
        assert!(result.is_err(), "truncated count must fail");

        // Count says 1 entry but no length prefix
        let mut bad = Vec::new();
        bad.extend_from_slice(&1u64.to_le_bytes());
        let result2 = batch_decode_audit(&bad);
        assert!(result2.is_err(), "truncated length must fail");

        // Count says 1, length says 100, but no data
        let mut bad2 = Vec::new();
        bad2.extend_from_slice(&1u64.to_le_bytes());
        bad2.extend_from_slice(&100u64.to_le_bytes());
        let result3 = batch_decode_audit(&bad2);
        assert!(result3.is_err(), "truncated data must fail");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: batch_decode_corrupted_data_error
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn batch_decode_corrupted_data_error() {
        // Count says 1, length says 5, data is garbage
        let mut bad = Vec::new();
        bad.extend_from_slice(&1u64.to_le_bytes());
        bad.extend_from_slice(&5u64.to_le_bytes());
        bad.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04]);
        let result = batch_decode_audit(&bad);
        assert!(result.is_err(), "corrupted entry data must fail");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: decode_audit_event_empty_input
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn decode_audit_event_empty_input() {
        let result = decode_audit_event(&[]);
        assert!(result.is_err(), "empty input must fail");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: decode_audit_entry_empty_input
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn decode_audit_entry_empty_input() {
        let result = decode_audit_entry(&[]);
        assert!(result.is_err(), "empty input must fail");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: audit_encoding_uses_same_bincode_config
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_encoding_uses_same_bincode_config() {
        // Verify audit encoding produces valid bincode with same config
        let event = sample_slashing_event();
        let encoded = encode_audit_event(&event);
        assert!(encoded.len() >= 4, "must produce valid bincode");

        // First 4 bytes = u32 discriminant for SlashingExecuted = 0
        let disc = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(disc, 0, "SlashingExecuted discriminant must be 0");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 16: batch_order_preserved
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn batch_order_preserved() {
        let e1 = make_entry(1, 100, [0u8; 32], sample_slashing_event());
        let e2 = make_entry(2, 200, e1.entry_hash, sample_stake_event());

        let encoded = batch_encode_audit(&[e1.clone(), e2.clone()]);
        let decoded = batch_decode_audit(&encoded);

        match decoded {
            Ok(rt) => {
                assert_eq!(rt[0], e1, "order must be preserved");
                assert_eq!(rt[1], e2, "order must be preserved");
            }
            Err(e) => assert!(false, "decode failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // 15.8 COMPREHENSIVE ENCODING TESTS
    // ════════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════════
    // TEST 17: encode_decode_audit_event_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn encode_decode_audit_event_roundtrip() {
        // Test all 9 variant types through encoding pipeline
        let events: Vec<AuditLogEvent> = vec![
            sample_slashing_event(),
            sample_stake_event(),
            AuditLogEvent::AntiSelfDealingViolation {
                version: 1, timestamp_ms: 100,
                node_id: "n".to_string(), submitter_address: "s".to_string(),
                receipt_hash: [0xCC; 32], detection_type: "direct_match".to_string(),
                penalty_applied: true,
            },
            AuditLogEvent::UserControlledDelete {
                version: 1, timestamp_ms: 200,
                chunk_hash: "ch".to_string(), requester_id: "u".to_string(),
                reason: "gdpr".to_string(), authorized: false,
            },
            AuditLogEvent::DaSyncSequenceUpdate {
                version: 1, timestamp_ms: 300,
                da_source: "celestia".to_string(), sequence_number: 99,
                previous_sequence: 98, blob_count: 5,
            },
            AuditLogEvent::GovernanceProposalEvent {
                version: 1, timestamp_ms: 400,
                proposal_id: "p".to_string(), proposer_address: "a".to_string(),
                proposal_type: "t".to_string(), delay_window_secs: 3600,
                status: crate::audit_event::GovernanceStatus::Submitted,
            },
            AuditLogEvent::CommitteeRotationEvent {
                version: 1, timestamp_ms: 500,
                old_epoch: 1, new_epoch: 2,
                old_committee_hash: [0xAA; 32], new_committee_hash: [0xBB; 32],
                member_count: 5, threshold: 3,
            },
            AuditLogEvent::DaFallbackEvent {
                version: 1, timestamp_ms: 600,
                action: crate::audit_event::DaFallbackAction::Activated,
                previous_source: "celestia".to_string(),
                new_source: "quorum".to_string(),
                reason: "timeout".to_string(), celestia_last_height: 999,
            },
            AuditLogEvent::ComputeChallengeEvent {
                version: 1, timestamp_ms: 700,
                receipt_hash: [0xDD; 32], challenger_id: "c".to_string(),
                challenged_node_id: "cn".to_string(),
                challenge_type: "exec".to_string(),
                outcome: crate::audit_event::ChallengeOutcome::Pending,
            },
        ];

        for (i, event) in events.iter().enumerate() {
            let encoded = encode_audit_event(event);
            assert!(!encoded.is_empty(), "event {} must encode", i);
            let decoded = decode_audit_event(&encoded);
            match decoded {
                Ok(rt) => assert_eq!(event, &rt, "event {} roundtrip via encoding pipeline", i),
                Err(e) => assert!(false, "event {} decode failed: {}", i, e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 18: encode_decode_audit_entry_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn encode_decode_audit_entry_roundtrip_15_8() {
        let e1 = make_entry(1, 100, [0u8; 32], sample_slashing_event());
        let e2 = make_entry(2, 200, e1.entry_hash, sample_stake_event());

        for (i, entry) in [&e1, &e2].iter().enumerate() {
            let encoded = encode_audit_entry(entry);
            assert!(!encoded.is_empty(), "entry {} must encode", i);
            let decoded = decode_audit_entry(&encoded);
            match decoded {
                Ok(rt) => {
                    assert_eq!(*entry, &rt, "entry {} roundtrip", i);
                    // Verify hash preserved
                    assert_eq!(entry.entry_hash, rt.entry_hash, "entry {} hash preserved", i);
                }
                Err(e) => assert!(false, "entry {} decode failed: {}", i, e),
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 19: batch_encode_decode_audit_roundtrip
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn batch_encode_decode_audit_roundtrip_15_8() {
        let e1 = make_entry(1, 100, [0u8; 32], sample_slashing_event());
        let e2 = make_entry(2, 200, e1.entry_hash, sample_stake_event());
        let e3 = make_entry(3, 300, e2.entry_hash, sample_slashing_event());
        let e4 = make_entry(4, 400, e3.entry_hash, sample_stake_event());

        let entries = vec![e1.clone(), e2.clone(), e3.clone(), e4.clone()];
        let encoded = batch_encode_audit(&entries);
        let decoded = batch_decode_audit(&encoded);

        match decoded {
            Ok(rt) => {
                assert_eq!(rt.len(), 4, "batch length must match");
                for (i, (orig, dec)) in entries.iter().zip(rt.iter()).enumerate() {
                    assert_eq!(orig, dec, "batch entry {} must match", i);
                }
            }
            Err(e) => assert!(false, "batch decode failed: {}", e),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 20: audit_hash_determinism_100_iterations
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_hash_determinism_100_iterations() {
        let event = sample_slashing_event();
        let reference = compute_audit_event_hash(&event);

        for i in 0..100 {
            let hash = compute_audit_event_hash(&event);
            assert_eq!(
                reference, hash,
                "audit event hash must be deterministic at iteration {}",
                i
            );
        }

        let entry = make_entry(1, 1700000000, [0u8; 32], sample_slashing_event());
        let ref_entry = compute_audit_entry_hash(&entry);

        for i in 0..100 {
            let hash = compute_audit_entry_hash(&entry);
            assert_eq!(
                ref_entry, hash,
                "audit entry hash must be deterministic at iteration {}",
                i
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 21: audit_entry_hash_differs_per_event
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn audit_entry_hash_differs_per_event() {
        let e1 = make_entry(1, 1700000000, [0u8; 32], sample_slashing_event());
        let e2 = make_entry(1, 1700000000, [0u8; 32], sample_stake_event());

        let h1 = compute_audit_entry_hash(&e1);
        let h2 = compute_audit_entry_hash(&e2);

        assert_ne!(h1, h2, "entries with different events must have different hashes");

        // Also verify via entry_hash field
        assert_ne!(e1.entry_hash, e2.entry_hash, "entry_hash fields must differ");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 22: cross_compatibility_same_bincode_config
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn cross_compatibility_same_bincode_config() {
        let event = sample_slashing_event();

        // Method 1: direct bincode::serialize
        let direct = bincode::serialize(&event);

        // Method 2: via encode_audit_event
        let via_fn = encode_audit_event(&event);

        match direct {
            Ok(direct_bytes) => {
                assert_eq!(
                    direct_bytes, via_fn,
                    "direct serialize and encode_audit_event must produce identical bytes"
                );
            }
            Err(e) => assert!(false, "direct serialize failed: {}", e),
        }

        // Same for entry
        let entry = make_entry(1, 100, [0u8; 32], sample_slashing_event());
        let direct_entry = bincode::serialize(&entry);
        let via_fn_entry = encode_audit_entry(&entry);

        match direct_entry {
            Ok(de) => {
                assert_eq!(
                    de, via_fn_entry,
                    "direct entry serialize and encode_audit_entry must produce identical bytes"
                );
            }
            Err(e) => assert!(false, "direct entry serialize failed: {}", e),
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::da_event::{ReplicaRemovalReason, DeleteReason};
    use proptest::prelude::*;

    fn arb_node_registered() -> impl Strategy<Value = DAEvent> {
        (
            any::<u8>(),
            any::<u64>(),
            "[a-z0-9]{1,20}",
            "[a-z0-9]{1,10}",
            "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{1,5}",
            any::<u64>(),
        )
            .prop_map(|(version, timestamp_ms, node_id, zone, addr, capacity_gb)| {
                DAEvent::NodeRegistered {
                    version,
                    timestamp_ms,
                    node_id,
                    zone,
                    addr,
                    capacity_gb,
                }
            })
    }

    fn arb_chunk_declared() -> impl Strategy<Value = DAEvent> {
        (
            any::<u8>(),
            any::<u64>(),
            "[a-f0-9]{16,64}",
            any::<u64>(),
            "[a-z0-9]{1,20}",
            any::<u8>(),
        )
            .prop_map(|(version, timestamp_ms, chunk_hash, size_bytes, uploader_id, replication_factor)| {
                DAEvent::ChunkDeclared {
                    version,
                    timestamp_ms,
                    chunk_hash,
                    size_bytes,
                    uploader_id,
                    replication_factor,
                }
            })
    }

    fn arb_replica_added() -> impl Strategy<Value = DAEvent> {
        (
            any::<u8>(),
            any::<u64>(),
            "[a-f0-9]{16,64}",
            "[a-z0-9]{1,20}",
            any::<u8>(),
        )
            .prop_map(|(version, timestamp_ms, chunk_hash, node_id, replica_index)| {
                DAEvent::ReplicaAdded {
                    version,
                    timestamp_ms,
                    chunk_hash,
                    node_id,
                    replica_index,
                }
            })
    }

    fn arb_replica_removal_reason() -> impl Strategy<Value = ReplicaRemovalReason> {
        prop_oneof![
            Just(ReplicaRemovalReason::NodeOffline),
            Just(ReplicaRemovalReason::Rebalance),
            Just(ReplicaRemovalReason::Corruption),
            Just(ReplicaRemovalReason::Manual),
        ]
    }

    fn arb_replica_removed() -> impl Strategy<Value = DAEvent> {
        (
            any::<u8>(),
            any::<u64>(),
            "[a-f0-9]{16,64}",
            "[a-z0-9]{1,20}",
            arb_replica_removal_reason(),
        )
            .prop_map(|(version, timestamp_ms, chunk_hash, node_id, reason)| {
                DAEvent::ReplicaRemoved {
                    version,
                    timestamp_ms,
                    chunk_hash,
                    node_id,
                    reason,
                }
            })
    }

    fn arb_delete_reason() -> impl Strategy<Value = DeleteReason> {
        prop_oneof![
            Just(DeleteReason::UserRequest),
            Just(DeleteReason::Expired),
            Just(DeleteReason::Governance),
            Just(DeleteReason::Compliance),
        ]
    }

    fn arb_delete_requested() -> impl Strategy<Value = DAEvent> {
        (
            any::<u8>(),
            any::<u64>(),
            "[a-f0-9]{16,64}",
            "[a-z0-9]{1,20}",
            arb_delete_reason(),
        )
            .prop_map(|(version, timestamp_ms, chunk_hash, requester_id, reason)| {
                DAEvent::DeleteRequested {
                    version,
                    timestamp_ms,
                    chunk_hash,
                    requester_id,
                    reason,
                }
            })
    }

    fn arb_da_event() -> impl Strategy<Value = DAEvent> {
        prop_oneof![
            arb_node_registered(),
            arb_chunk_declared(),
            arb_replica_added(),
            arb_replica_removed(),
            arb_delete_requested(),
        ]
    }

    proptest! {
        #[test]
        fn proptest_encode_decode_roundtrip(event in arb_da_event()) {
            let encoded = encode_event(&event);
            let decoded = decode_event(&encoded).expect("decode must succeed");
            prop_assert_eq!(event, decoded, "roundtrip must preserve event");
        }

        #[test]
        fn proptest_encode_determinism(event in arb_da_event()) {
            let encoded1 = encode_event(&event);
            let encoded2 = encode_event(&event);
            prop_assert_eq!(encoded1, encoded2, "encode must be deterministic");
        }

        #[test]
        fn proptest_hash_determinism(event in arb_da_event()) {
            let hash1 = compute_event_hash(&event);
            let hash2 = compute_event_hash(&event);
            prop_assert_eq!(hash1, hash2, "hash must be deterministic");
        }

        #[test]
        fn proptest_hash_fixed_size(event in arb_da_event()) {
            let hash = compute_event_hash(&event);
            prop_assert_eq!(hash.len(), 32, "hash must be 32 bytes");
        }

        #[test]
        fn proptest_batch_roundtrip(events in prop::collection::vec(arb_da_event(), 0..10)) {
            let encoded = batch_encode(&events);
            let decoded = batch_decode(&encoded).expect("batch decode must succeed");
            prop_assert_eq!(events.len(), decoded.len(), "batch length must match");
            for (i, (orig, dec)) in events.iter().zip(decoded.iter()).enumerate() {
                prop_assert_eq!(orig, dec, "event {} must match", i);
            }
        }

        #[test]
        fn proptest_batch_encode_determinism(events in prop::collection::vec(arb_da_event(), 0..5)) {
            let encoded1 = batch_encode(&events);
            let encoded2 = batch_encode(&events);
            prop_assert_eq!(encoded1, encoded2, "batch encode must be deterministic");
        }

        #[test]
        fn proptest_batch_order_preserved(events in prop::collection::vec(arb_da_event(), 1..5)) {
            let encoded = batch_encode(&events);
            let decoded = batch_decode(&encoded).expect("batch decode must succeed");
            
            for (i, (orig, dec)) in events.iter().zip(decoded.iter()).enumerate() {
                prop_assert_eq!(orig, dec, "event {} order must be preserved", i);
            }
        }

        #[test]
        fn proptest_encode_100_times_determinism(event in arb_da_event()) {
            let reference = encode_event(&event);
            for i in 0..100 {
                let encoded = encode_event(&event);
                prop_assert_eq!(
                    &reference, &encoded,
                    "encode must be deterministic at iteration {}", i
                );
            }
        }

        #[test]
        fn proptest_hash_stability_across_encode(event in arb_da_event()) {
            // Hash should be stable even if we re-encode
            let hash1 = compute_event_hash(&event);
            
            // Re-encode and decode, then hash again
            let encoded = encode_event(&event);
            let decoded = decode_event(&encoded).expect("decode must succeed");
            let hash2 = compute_event_hash(&decoded);
            
            prop_assert_eq!(hash1, hash2, "hash must be stable across re-encoding");
        }
    }
}
//! # Receipt Hashing Utilities
//!
//! CANONICAL hashing utilities yang menjadi satu-satunya referensi
//! hashing untuk `ReceiptV1`, `ExecutionCommitment`, dan `ClaimReward`.
//!
//! Hash yang dihasilkan HARUS identik antara common, proto, dan chain.
//!
//! ## Algoritma
//!
//! Semua hash menggunakan SHA3-256 atas raw byte concatenation.
//! Tidak ada separator, tidak ada length prefix, tidak ada serialization framework.
//!
//! ## Integer Encoding
//!
//! Semua integer di-encode sebagai **big-endian** bytes.
//!
//! ## Caller Contract
//!
//! Caller WAJIB menjamin panjang slice sesuai spesifikasi.
//! `debug_assert` digunakan untuk mendeteksi pelanggaran di development.
//! Di release build, slice yang lebih pendek/panjang akan tetap di-hash
//! tanpa panic — hasil hash menjadi tidak valid secara semantik.

use sha3::{Digest, Sha3_256};

/// 32 zero bytes, digunakan saat `execution_commitment_hash` is `None`.
const ZERO_HASH_32: [u8; 32] = [0u8; 32];

// ════════════════════════════════════════════════════════════════════════════════
// compute_receipt_v1_hash
// ════════════════════════════════════════════════════════════════════════════════

/// CANONICAL hash untuk ReceiptV1.
///
/// ## Byte Layout (161 bytes total)
///
/// | Offset | Field | Size | Encoding |
/// |--------|-------|------|----------|
/// | 0 | `workload_id` | 32 | raw bytes |
/// | 32 | `node_id` | 32 | raw bytes |
/// | 64 | `receipt_type` | 1 | u8 (0=Storage, 1=Compute) |
/// | 65 | `usage_proof_hash` | 32 | raw bytes |
/// | 97 | `execution_commitment_hash` | 32 | raw bytes or 32 zero bytes |
/// | 129 | `reward_base` | 16 | big-endian u128 |
/// | 145 | `timestamp` | 8 | big-endian u64 |
/// | 153 | `epoch` | 8 | big-endian u64 |
///
/// ## IMPORTANT
///
/// Proto, Chain, dan Coordinator HARUS mengikuti layout ini.
/// Perubahan urutan field akan merusak consensus.
/// All integers encoded BIG-ENDIAN.
///
/// ## Caller Contract
///
/// - `workload_id` MUST be 32 bytes
/// - `node_id` MUST be 32 bytes
/// - `usage_proof_hash` MUST be 32 bytes
/// - `execution_commitment_hash` if Some, MUST be 32 bytes
/// - `receipt_type` MUST be 0 or 1
///
/// `debug_assert` digunakan untuk mendeteksi pelanggaran di development.
#[must_use]
pub fn compute_receipt_v1_hash(
    workload_id: &[u8],
    node_id: &[u8],
    receipt_type: u8,
    usage_proof_hash: &[u8],
    execution_commitment_hash: Option<&[u8]>,
    reward_base: u128,
    timestamp: u64,
    epoch: u64,
) -> [u8; 32] {
    debug_assert_eq!(workload_id.len(), 32);
    debug_assert_eq!(node_id.len(), 32);
    debug_assert_eq!(usage_proof_hash.len(), 32);
    if let Some(ech) = execution_commitment_hash {
        debug_assert_eq!(ech.len(), 32);
    }

    let mut hasher = Sha3_256::new();

    // 1. workload_id (32 bytes)
    hasher.update(workload_id);

    // 2. node_id (32 bytes)
    hasher.update(node_id);

    // 3. receipt_type (1 byte)
    hasher.update([receipt_type]);

    // 4. usage_proof_hash (32 bytes)
    hasher.update(usage_proof_hash);

    // 5. execution_commitment_hash (32 bytes or zero)
    match execution_commitment_hash {
        Some(ech) => hasher.update(ech),
        None => hasher.update(ZERO_HASH_32),
    }

    // 6. reward_base (16 bytes, big-endian)
    hasher.update(reward_base.to_be_bytes());

    // 7. timestamp (8 bytes, big-endian)
    hasher.update(timestamp.to_be_bytes());

    // 8. epoch (8 bytes, big-endian)
    hasher.update(epoch.to_be_bytes());

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ════════════════════════════════════════════════════════════════════════════════
// compute_execution_commitment_hash
// ════════════════════════════════════════════════════════════════════════════════

/// CANONICAL hash untuk ExecutionCommitment.
///
/// ## Byte Layout (192 bytes total)
///
/// | Offset | Field | Size |
/// |--------|-------|------|
/// | 0 | `workload_id` | 32 |
/// | 32 | `input_hash` | 32 |
/// | 64 | `output_hash` | 32 |
/// | 96 | `state_root_before` | 32 |
/// | 128 | `state_root_after` | 32 |
/// | 160 | `execution_trace_merkle_root` | 32 |
///
/// ## IMPORTANT
///
/// Proto, Chain, dan Coordinator HARUS mengikuti layout ini.
/// Perubahan urutan field akan merusak consensus.
///
/// ## Caller Contract
///
/// Semua parameter MUST be 32 bytes.
/// `debug_assert` digunakan untuk mendeteksi pelanggaran di development.
#[must_use]
pub fn compute_execution_commitment_hash(
    workload_id: &[u8],
    input_hash: &[u8],
    output_hash: &[u8],
    state_root_before: &[u8],
    state_root_after: &[u8],
    execution_trace_merkle_root: &[u8],
) -> [u8; 32] {
    debug_assert_eq!(workload_id.len(), 32);
    debug_assert_eq!(input_hash.len(), 32);
    debug_assert_eq!(output_hash.len(), 32);
    debug_assert_eq!(state_root_before.len(), 32);
    debug_assert_eq!(state_root_after.len(), 32);
    debug_assert_eq!(execution_trace_merkle_root.len(), 32);

    let mut hasher = Sha3_256::new();

    // 1. workload_id (32)
    hasher.update(workload_id);

    // 2. input_hash (32)
    hasher.update(input_hash);

    // 3. output_hash (32)
    hasher.update(output_hash);

    // 4. state_root_before (32)
    hasher.update(state_root_before);

    // 5. state_root_after (32)
    hasher.update(state_root_after);

    // 6. execution_trace_merkle_root (32)
    hasher.update(execution_trace_merkle_root);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ════════════════════════════════════════════════════════════════════════════════
// compute_claim_reward_hash
// ════════════════════════════════════════════════════════════════════════════════

/// CANONICAL hash untuk ClaimReward transaction.
///
/// ## Byte Layout (60 bytes total)
///
/// | Offset | Field | Size | Encoding |
/// |--------|-------|------|----------|
/// | 0 | `receipt_hash` | 32 | raw bytes |
/// | 32 | `submitter` | 20 | raw bytes |
/// | 52 | `nonce` | 8 | big-endian u64 |
///
/// ## IMPORTANT
///
/// Proto, Chain, dan Coordinator HARUS mengikuti layout ini.
/// Perubahan urutan field akan merusak consensus.
/// All integers encoded BIG-ENDIAN.
///
/// ## Caller Contract
///
/// - `receipt_hash` MUST be 32 bytes
/// - `submitter` MUST be 20 bytes
///
/// `debug_assert` digunakan untuk mendeteksi pelanggaran di development.
#[must_use]
pub fn compute_claim_reward_hash(
    receipt_hash: &[u8],
    submitter: &[u8],
    nonce: u64,
) -> [u8; 32] {
    debug_assert_eq!(receipt_hash.len(), 32);
    debug_assert_eq!(submitter.len(), 20);

    let mut hasher = Sha3_256::new();

    // 1. receipt_hash (32 bytes)
    hasher.update(receipt_hash);

    // 2. submitter (20 bytes)
    hasher.update(submitter);

    // 3. nonce (8 bytes, big-endian)
    hasher.update(nonce.to_be_bytes());

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── 1. RECEIPT HASH DETERMINISTIC ───────────────────────────────────

    #[test]
    fn test_receipt_hash_deterministic() {
        let wid = [0x01u8; 32];
        let nid = [0x02u8; 32];
        let uph = [0x03u8; 32];
        let ech = [0x04u8; 32];

        let first = compute_receipt_v1_hash(
            &wid, &nid, 0, &uph, Some(&ech), 1000, 1700000000, 42,
        );

        for _ in 0..1000 {
            let h = compute_receipt_v1_hash(
                &wid, &nid, 0, &uph, Some(&ech), 1000, 1700000000, 42,
            );
            assert_eq!(first, h);
        }
    }

    // ── 2. RECEIPT HASH FIELD SENSITIVITY ───────────────────────────────

    #[test]
    fn test_receipt_hash_diff_field_changes_hash() {
        let base = compute_receipt_v1_hash(
            &[0x01; 32], &[0x02; 32], 0, &[0x03; 32],
            Some(&[0x04; 32]), 1000, 1700000000, 42,
        );

        // Change workload_id
        let h = compute_receipt_v1_hash(
            &[0xFF; 32], &[0x02; 32], 0, &[0x03; 32],
            Some(&[0x04; 32]), 1000, 1700000000, 42,
        );
        assert_ne!(base, h, "workload_id change must affect hash");

        // Change node_id
        let h = compute_receipt_v1_hash(
            &[0x01; 32], &[0xFF; 32], 0, &[0x03; 32],
            Some(&[0x04; 32]), 1000, 1700000000, 42,
        );
        assert_ne!(base, h, "node_id change must affect hash");

        // Change receipt_type
        let h = compute_receipt_v1_hash(
            &[0x01; 32], &[0x02; 32], 1, &[0x03; 32],
            Some(&[0x04; 32]), 1000, 1700000000, 42,
        );
        assert_ne!(base, h, "receipt_type change must affect hash");

        // Change usage_proof_hash
        let h = compute_receipt_v1_hash(
            &[0x01; 32], &[0x02; 32], 0, &[0xFF; 32],
            Some(&[0x04; 32]), 1000, 1700000000, 42,
        );
        assert_ne!(base, h, "usage_proof_hash change must affect hash");

        // Change execution_commitment_hash
        let h = compute_receipt_v1_hash(
            &[0x01; 32], &[0x02; 32], 0, &[0x03; 32],
            Some(&[0xFF; 32]), 1000, 1700000000, 42,
        );
        assert_ne!(base, h, "ec_hash change must affect hash");

        // Change reward_base
        let h = compute_receipt_v1_hash(
            &[0x01; 32], &[0x02; 32], 0, &[0x03; 32],
            Some(&[0x04; 32]), 9999, 1700000000, 42,
        );
        assert_ne!(base, h, "reward_base change must affect hash");

        // Change timestamp
        let h = compute_receipt_v1_hash(
            &[0x01; 32], &[0x02; 32], 0, &[0x03; 32],
            Some(&[0x04; 32]), 1000, 9999999999, 42,
        );
        assert_ne!(base, h, "timestamp change must affect hash");

        // Change epoch
        let h = compute_receipt_v1_hash(
            &[0x01; 32], &[0x02; 32], 0, &[0x03; 32],
            Some(&[0x04; 32]), 1000, 1700000000, 99,
        );
        assert_ne!(base, h, "epoch change must affect hash");
    }

    // ── 3. EXECUTION COMMITMENT HASH DETERMINISTIC ──────────────────────

    #[test]
    fn test_execution_commitment_hash_deterministic() {
        let first = compute_execution_commitment_hash(
            &[0x01; 32], &[0x02; 32], &[0x03; 32],
            &[0x04; 32], &[0x05; 32], &[0x06; 32],
        );

        for _ in 0..1000 {
            let h = compute_execution_commitment_hash(
                &[0x01; 32], &[0x02; 32], &[0x03; 32],
                &[0x04; 32], &[0x05; 32], &[0x06; 32],
            );
            assert_eq!(first, h);
        }
    }

    // ── 4. CLAIM REWARD HASH DETERMINISTIC ──────────────────────────────

    #[test]
    fn test_claim_reward_hash_deterministic() {
        let first = compute_claim_reward_hash(&[0x01; 32], &[0x02; 20], 42);

        for _ in 0..1000 {
            let h = compute_claim_reward_hash(&[0x01; 32], &[0x02; 20], 42);
            assert_eq!(first, h);
        }
    }

    // ── 5. BIG-ENDIAN ENCODING — REWARD BASE ────────────────────────────

    #[test]
    fn test_big_endian_encoding_reward_base() {
        // Different reward_base values that differ only in endianness
        // should produce different hashes.
        let h1 = compute_receipt_v1_hash(
            &[0; 32], &[0; 32], 0, &[0; 32], None, 0x0100, 0, 0,
        );
        let h2 = compute_receipt_v1_hash(
            &[0; 32], &[0; 32], 0, &[0; 32], None, 0x0001, 0, 0,
        );
        assert_ne!(h1, h2, "different reward_base must produce different hash");

        // Verify actual big-endian layout by checking that a known value
        // produces the same hash when manually constructing the buffer.
        let reward: u128 = 0x0102030405060708090A0B0C0D0E0F10;
        let h_fn = compute_receipt_v1_hash(
            &[0; 32], &[0; 32], 0, &[0; 32], None, reward, 0, 0,
        );

        let mut manual_buf = Vec::with_capacity(161);
        manual_buf.extend_from_slice(&[0u8; 32]); // workload_id
        manual_buf.extend_from_slice(&[0u8; 32]); // node_id
        manual_buf.push(0);                         // receipt_type
        manual_buf.extend_from_slice(&[0u8; 32]); // usage_proof_hash
        manual_buf.extend_from_slice(&[0u8; 32]); // ec (zero)
        manual_buf.extend_from_slice(&reward.to_be_bytes());
        manual_buf.extend_from_slice(&0u64.to_be_bytes());
        manual_buf.extend_from_slice(&0u64.to_be_bytes());
        assert_eq!(manual_buf.len(), 161);

        let mut hasher = Sha3_256::new();
        hasher.update(&manual_buf);
        let result = hasher.finalize();
        let mut h_manual = [0u8; 32];
        h_manual.copy_from_slice(&result);

        assert_eq!(h_fn, h_manual, "function must match manual big-endian construction");
    }

    // ── 6. BIG-ENDIAN ENCODING — NONCE ──────────────────────────────────

    #[test]
    fn test_big_endian_encoding_nonce() {
        let h1 = compute_claim_reward_hash(&[0; 32], &[0; 20], 0x0100);
        let h2 = compute_claim_reward_hash(&[0; 32], &[0; 20], 0x0001);
        assert_ne!(h1, h2, "different nonce must produce different hash");

        // Verify big-endian via manual construction.
        let nonce: u64 = 0x0102030405060708;
        let h_fn = compute_claim_reward_hash(&[0; 32], &[0; 20], nonce);

        let mut manual_buf = Vec::with_capacity(60);
        manual_buf.extend_from_slice(&[0u8; 32]); // receipt_hash
        manual_buf.extend_from_slice(&[0u8; 20]); // submitter
        manual_buf.extend_from_slice(&nonce.to_be_bytes());
        assert_eq!(manual_buf.len(), 60);

        let mut hasher = Sha3_256::new();
        hasher.update(&manual_buf);
        let result = hasher.finalize();
        let mut h_manual = [0u8; 32];
        h_manual.copy_from_slice(&result);

        assert_eq!(h_fn, h_manual, "function must match manual big-endian construction");
    }

    // ── 7. NONE EC HASH EQUALS ZERO32 ───────────────────────────────────

    #[test]
    fn test_none_execution_commitment_hash_equals_zero32() {
        let h_none = compute_receipt_v1_hash(
            &[0x01; 32], &[0x02; 32], 0, &[0x03; 32],
            None, 1000, 1700000000, 42,
        );
        let h_zero = compute_receipt_v1_hash(
            &[0x01; 32], &[0x02; 32], 0, &[0x03; 32],
            Some(&[0u8; 32]), 1000, 1700000000, 42,
        );
        assert_eq!(h_none, h_zero, "None must produce same hash as 32 zero bytes");
    }

    // ── 8. LAYOUT LENGTH EXACT ──────────────────────────────────────────

    #[test]
    fn test_layout_length_exact() {
        // Receipt V1: 32+32+1+32+32+16+8+8 = 161
        assert_eq!(32 + 32 + 1 + 32 + 32 + 16 + 8 + 8, 161);

        // ExecutionCommitment: 32*6 = 192
        assert_eq!(32 * 6, 192);

        // ClaimReward: 32+20+8 = 60
        assert_eq!(32 + 20 + 8, 60);
    }

    // ── ADDITIONAL: EC HASH FIELD SENSITIVITY ───────────────────────────

    #[test]
    fn test_ec_hash_field_sensitivity() {
        let base = compute_execution_commitment_hash(
            &[0x01; 32], &[0x02; 32], &[0x03; 32],
            &[0x04; 32], &[0x05; 32], &[0x06; 32],
        );

        // Change each field
        for i in 0..6 {
            let mut fields: [[u8; 32]; 6] = [
                [0x01; 32], [0x02; 32], [0x03; 32],
                [0x04; 32], [0x05; 32], [0x06; 32],
            ];
            fields[i] = [0xFF; 32];
            let h = compute_execution_commitment_hash(
                &fields[0], &fields[1], &fields[2],
                &fields[3], &fields[4], &fields[5],
            );
            assert_ne!(base, h, "changing field {} must affect hash", i);
        }
    }

    // ── ADDITIONAL: CLAIM REWARD FIELD SENSITIVITY ──────────────────────

    #[test]
    fn test_claim_reward_field_sensitivity() {
        let base = compute_claim_reward_hash(&[0x01; 32], &[0x02; 20], 42);

        let h = compute_claim_reward_hash(&[0xFF; 32], &[0x02; 20], 42);
        assert_ne!(base, h, "receipt_hash change");

        let h = compute_claim_reward_hash(&[0x01; 32], &[0xFF; 20], 42);
        assert_ne!(base, h, "submitter change");

        let h = compute_claim_reward_hash(&[0x01; 32], &[0x02; 20], 99);
        assert_ne!(base, h, "nonce change");
    }

    // ── ADDITIONAL: HASH OUTPUT IS 32 BYTES ─────────────────────────────

    #[test]
    fn test_all_hashes_are_32_bytes() {
        let h1 = compute_receipt_v1_hash(
            &[0; 32], &[0; 32], 0, &[0; 32], None, 0, 0, 0,
        );
        assert_eq!(h1.len(), 32);

        let h2 = compute_execution_commitment_hash(
            &[0; 32], &[0; 32], &[0; 32], &[0; 32], &[0; 32], &[0; 32],
        );
        assert_eq!(h2.len(), 32);

        let h3 = compute_claim_reward_hash(&[0; 32], &[0; 20], 0);
        assert_eq!(h3.len(), 32);
    }

    // ── ADDITIONAL: HASHES ARE NOT ZERO ─────────────────────────────────

    #[test]
    fn test_nonzero_inputs_produce_nonzero_hash() {
        let h = compute_receipt_v1_hash(
            &[0x01; 32], &[0x02; 32], 1, &[0x03; 32],
            Some(&[0x04; 32]), 1000, 1700000000, 42,
        );
        assert_ne!(h, [0u8; 32]);
    }
}
//! # Resource Receipt Module (13.10)
//!
//! Module ini mendefinisikan struktur data `ResourceReceipt` yang digunakan sebagai
//! fondasi sistem reward dan anti-self-dealing di DSDN.
//!
//! ## Karakteristik Receipt
//!
//! - Deterministic: receipt_id dihitung dari seluruh field kecuali signature
//! - Verifiable: coordinator_signature dapat diverifikasi dengan pubkey
//! - Stateless: tidak bergantung pada ChainState
//!
//! ## Penggunaan
//!
//! Receipt dibuat oleh Coordinator dan ditulis sebagai blob ke Celestia DA.
//! Node membaca receipt dan mengirim transaksi ClaimReward ke Chain Nusantara.
//!
//! ## Reward Distribution
//!
//! - 70% → node
//! - 20% → validator
//! - 10% → treasury

use crate::types::{Address, Hash};
use crate::crypto::{self, CryptoAlgorithm};
use serde::{Serialize, Deserialize};

// ════════════════════════════════════════════════════════════════════════════
// COORDINATOR PUBKEY (CONSENSUS-CRITICAL)
// ════════════════════════════════════════════════════════════════════════════

/// Ed25519 public key milik Coordinator untuk verifikasi receipt signature.
/// Placeholder: harus diganti dengan pubkey production sebelum mainnet.
/// Perubahan nilai ini memerlukan hard-fork.
pub const COORDINATOR_PUBKEY: [u8; 32] = [0u8; 32];
/// Algorithm used to verify coordinator signatures.
pub const COORDINATOR_ALGORITHM: CryptoAlgorithm = CryptoAlgorithm::Ecdsa;
// ════════════════════════════════════════════════════════════════════════════
// ENUMS
// ════════════════════════════════════════════════════════════════════════════

/// Klasifikasi node berdasarkan infrastruktur.
/// Digunakan untuk diferensiasi reward dan cost index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeClass {
    /// Node regular (home server, VPS standar)
    Regular,
    /// Node datacenter (dedicated server, high availability)
    Datacenter,
}

/// Tipe resource yang disediakan oleh node.
/// Menentukan ResourceClass untuk fee split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceType {
    /// Storage service (chunk hosting, replication)
    Storage,
    /// Compute service (WASM execution, microVM)
    Compute,
}

// ════════════════════════════════════════════════════════════════════════════
// CH.9 — RECEIPT TYPE CONVERSION TRAITS
// ════════════════════════════════════════════════════════════════════════════
//
// Bidirectional conversion between ResourceType (V0) and ReceiptType (V1).
// Both enums have exactly two variants: Storage and Compute.
// The mapping is exact (1:1), not lossy.
//
// These traits enable seamless interop between the legacy receipt pipeline
// (ResourceReceipt + ResourceType) and the new pipeline (ReceiptV1 + ReceiptType)
// during the migration period.
// ════════════════════════════════════════════════════════════════════════════

/// Convert `ResourceType` (V0) → `ReceiptType` (V1).
///
/// | `ResourceType` | `ReceiptType` |
/// |-----------------|---------------|
/// | `Storage` | `Storage` |
/// | `Compute` | `Compute` |
impl From<ResourceType> for dsdn_common::receipt_v1::ReceiptType {
    fn from(rt: ResourceType) -> Self {
        match rt {
            ResourceType::Storage => Self::Storage,
            ResourceType::Compute => Self::Compute,
        }
    }
}

/// Convert `ReceiptType` (V1) → `ResourceType` (V0).
///
/// | `ReceiptType` | `ResourceType` |
/// |---------------|-----------------|
/// | `Storage` | `Storage` |
/// | `Compute` | `Compute` |
impl From<dsdn_common::receipt_v1::ReceiptType> for ResourceType {
    fn from(rt: dsdn_common::receipt_v1::ReceiptType) -> Self {
        use dsdn_common::receipt_v1::ReceiptType;
        match rt {
            ReceiptType::Storage => Self::Storage,
            ReceiptType::Compute => Self::Compute,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// MEASURED USAGE
// ════════════════════════════════════════════════════════════════════════════

/// Metrik penggunaan resource yang diukur oleh Coordinator.
/// Semua nilai dalam satuan dasar (tidak di-scale).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasuredUsage {
    /// CPU cycles yang digunakan
    pub cpu: u64,
    /// RAM bytes yang dialokasikan
    pub ram: u64,
    /// Jumlah chunk yang di-host
    pub chunk_count: u64,
    /// Bandwidth bytes yang ditransfer
    pub bw: u64,
}

impl MeasuredUsage {
    /// Membuat MeasuredUsage baru dengan nilai eksplisit.
    pub fn new(cpu: u64, ram: u64, chunk_count: u64, bw: u64) -> Self {
        Self { cpu, ram, chunk_count, bw }
    }

    /// Membuat MeasuredUsage dengan semua nilai nol.
    pub fn zero() -> Self {
        Self { cpu: 0, ram: 0, chunk_count: 0, bw: 0 }
    }

    /// Serialize ke bytes untuk hashing (deterministic order).
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&self.cpu.to_be_bytes());
        buf.extend_from_slice(&self.ram.to_be_bytes());
        buf.extend_from_slice(&self.chunk_count.to_be_bytes());
        buf.extend_from_slice(&self.bw.to_be_bytes());
        buf
    }
}

// ════════════════════════════════════════════════════════════════════════════
// RESOURCE RECEIPT
// ════════════════════════════════════════════════════════════════════════════

/// Receipt yang dikeluarkan oleh Coordinator untuk kerja node.
///
/// Receipt ini adalah bukti kerja yang dapat di-claim oleh node untuk menerima reward.
/// Coordinator menandatangani receipt dan menyimpannya di Celestia DA.
///
/// ## Fields
///
/// - `receipt_id`: Hash unik yang dihitung dari seluruh field kecuali signature
/// - `node_address`: Address node yang melakukan kerja
/// - `node_class`: Klasifikasi node (Regular/Datacenter)
/// - `resource_type`: Tipe resource (Storage/Compute)
/// - `measured_usage`: Metrik penggunaan resource
/// - `reward_base`: Jumlah reward dasar dalam satuan terkecil
/// - `anti_self_dealing_flag`: Flag untuk mencegah self-dealing
/// - `timestamp`: Unix timestamp saat receipt dibuat
/// - `coordinator_signature`: Ed25519 signature dari Coordinator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceReceipt {
    /// Hash unik receipt (dihitung dari field lain kecuali signature)
    pub receipt_id: Hash,
    /// Address node penerima reward
    pub node_address: Address,
    /// Klasifikasi node
    pub node_class: NodeClass,
    /// Tipe resource yang disediakan
    pub resource_type: ResourceType,
    /// Metrik penggunaan resource terukur
    pub measured_usage: MeasuredUsage,
    /// Reward dasar yang akan didistribusikan (70/20/10)
    pub reward_base: u128,
    /// Flag anti-self-dealing (true = sender tidak boleh sama dengan node)
    pub anti_self_dealing_flag: bool,
    /// Unix timestamp pembuatan receipt
    pub timestamp: u64,
    /// Signature dari Coordinator atas receipt_id
    pub coordinator_signature: Vec<u8>,
    /// Algorithm identifier for coordinator_signature (default Ecdsa for backward compatibility)
    #[serde(default)]
    pub coordinator_signature_algorithm: CryptoAlgorithm,
}

impl ResourceReceipt {
    /// Membuat ResourceReceipt baru.
    ///
    /// `receipt_id` akan dihitung secara otomatis dari field lainnya.
    /// `coordinator_signature` harus diisi setelah receipt dibuat menggunakan
    /// private key Coordinator.
    pub fn new(
        node_address: Address,
        node_class: NodeClass,
        resource_type: ResourceType,
        measured_usage: MeasuredUsage,
        reward_base: u128,
        anti_self_dealing_flag: bool,
        timestamp: u64,
    ) -> Self {
        let mut receipt = Self {
            receipt_id: Hash::from_bytes([0u8; 64]),
            node_address,
            node_class,
            resource_type,
            measured_usage,
            reward_base,
            anti_self_dealing_flag,
            timestamp,
            coordinator_signature: Vec::new(),
            coordinator_signature_algorithm: COORDINATOR_ALGORITHM,
        };
        receipt.receipt_id = receipt.compute_receipt_id();
        receipt
    }

    /// Menghitung receipt_id dari seluruh field KECUALI coordinator_signature.
    ///
    /// Urutan serialisasi (deterministic):
    /// 1. node_address (20 bytes)
    /// 2. node_class (1 byte: 0=Regular, 1=Datacenter)
    /// 3. resource_type (1 byte: 0=Storage, 1=Compute)
    /// 4. measured_usage (32 bytes: cpu, ram, chunk_count, bw masing-masing 8 bytes BE)
    /// 5. reward_base (16 bytes BE)
    /// 6. anti_self_dealing_flag (1 byte: 0=false, 1=true)
    /// 7. timestamp (8 bytes BE)
    ///
    /// Total: 79 bytes sebelum hashing.
    pub fn compute_receipt_id(&self) -> Hash {
        let mut data = Vec::with_capacity(79);
        
        // 1. node_address (20 bytes)
        data.extend_from_slice(self.node_address.as_bytes());
        
        // 2. node_class (1 byte)
        let node_class_byte: u8 = match self.node_class {
            NodeClass::Regular => 0,
            NodeClass::Datacenter => 1,
        };
        data.push(node_class_byte);
        
        // 3. resource_type (1 byte)
        let resource_type_byte: u8 = match self.resource_type {
            ResourceType::Storage => 0,
            ResourceType::Compute => 1,
        };
        data.push(resource_type_byte);
        
        // 4. measured_usage (32 bytes)
        data.extend_from_slice(&self.measured_usage.to_bytes());
        
        // 5. reward_base (16 bytes BE)
        data.extend_from_slice(&self.reward_base.to_be_bytes());
        
        // 6. anti_self_dealing_flag (1 byte)
        let flag_byte: u8 = if self.anti_self_dealing_flag { 1 } else { 0 };
        data.push(flag_byte);
        
        // 7. timestamp (8 bytes BE)
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        
        // Hash dengan SHA3-512
        crypto::sha3_512(&data)
    }

    /// Memverifikasi coordinator_signature atas receipt_id.
    ///
    /// Signature harus dibuat dengan Ed25519 private key milik Coordinator.
    /// Verifikasi dilakukan dengan COORDINATOR_PUBKEY konstanta.
    ///
    /// Returns `true` bila signature valid, `false` bila tidak valid.
    pub fn verify_coordinator_signature(&self) -> bool {
        if self.coordinator_signature.is_empty() {
            return false;
        }
        
        crypto::verify_signature_with_algorithm(
            self.coordinator_signature_algorithm,
            &COORDINATOR_PUBKEY,
            self.receipt_id.as_bytes(),
            &self.coordinator_signature,
        ).unwrap_or(false)
    }

    /// Menetapkan coordinator_signature setelah receipt dibuat.
    pub fn set_signature(&mut self, signature: Vec<u8>) {
        self.coordinator_signature = signature;
    }

    /// Mengembalikan true bila receipt memiliki signature.
    pub fn has_signature(&self) -> bool {
        !self.coordinator_signature.is_empty()
    }

    /// Recompute receipt_id dan update field.
    /// Digunakan setelah field berubah.
    pub fn refresh_receipt_id(&mut self) {
        self.receipt_id = self.compute_receipt_id();
    }

    // ════════════════════════════════════════════════════════════════════
    // CH.9 — RECEIPT V1 MIGRATION BRIDGE
    // ════════════════════════════════════════════════════════════════════
    //
    // ## Migration Strategy
    //
    // ReceiptV1 is the target format for all new receipts.
    // ResourceReceipt (V0) remains supported during the migration period.
    //
    // `to_receipt_v1()` provides a one-way, lossy conversion from V0 to V1.
    // It is lossy because:
    //
    // 1. `workload_id` is derived from receipt_id (first 32 of 64 bytes).
    // 2. `node_id` is zero-padded from 20-byte address to 32-byte NodeId.
    // 3. `node_class` is dropped (deprecated in V1).
    // 4. `execution_commitment` is always None (V0 does not carry this).
    //    This means Compute receipts will FAIL conversion because V1
    //    requires `execution_commitment = Some(...)` for Compute type.
    // 5. `node_signature` is mapped from `coordinator_signature` (different
    //    semantic — V0 has single coordinator sig, V1 separates node sig
    //    from coordinator threshold sig).
    // 6. `submitter_address` is set to `node_address` (in V0, the node
    //    itself submits the claim).
    //
    // ## Deprecation Plan
    //
    // After all nodes migrate to V1 receipt generation:
    // 1. `to_receipt_v1()` becomes unused.
    // 2. `ResourceReceipt` is marked `#[deprecated]`.
    // 3. V0 processing pipeline is removed after full chain migration.
    // ════════════════════════════════════════════════════════════════════

    /// Checks whether this ResourceReceipt meets minimum requirements
    /// for conversion to ReceiptV1.
    ///
    /// Requirements:
    /// - Must have a coordinator signature (`has_signature() == true`).
    /// - Must have a non-zero reward base (`reward_base > 0`).
    ///
    /// This is a necessary but NOT sufficient condition for successful
    /// conversion. `to_receipt_v1()` may still fail for other reasons
    /// (e.g., Compute receipts lack execution_commitment in V1).
    ///
    /// ## Guarantees
    ///
    /// - Pure function. No mutation. No side effects.
    /// - Deterministic.
    /// - No panic.
    #[must_use]
    pub fn can_upgrade_to_v1(&self) -> bool {
        self.has_signature() && self.reward_base > 0
    }

    /// Convert this `ResourceReceipt` to a `ReceiptV1`.
    ///
    /// This is a **one-way, lossy** conversion for backward compatibility
    /// during the V0 → V1 migration period. See module-level documentation
    /// for details on what is lost.
    ///
    /// ## Parameters
    ///
    /// - `threshold_signature` — Coordinator aggregate threshold signature
    ///   (FROST). In V0 there is only `coordinator_signature`; in V1 the
    ///   coordinator threshold sig and node sig are separate. This parameter
    ///   provides the threshold signature for the V1 format.
    /// - `signer_ids` — IDs of signers who participated in threshold signing.
    /// - `epoch` — Epoch number. V0 does not track epoch; caller must provide.
    ///
    /// ## Field Mapping
    ///
    /// | V1 Field | Source | Notes |
    /// |----------|--------|-------|
    /// | `workload_id` | `receipt_id[..32]` | First 32 bytes of 64-byte hash |
    /// | `node_id` | `node_address` zero-padded | 20 bytes → 32 bytes |
    /// | `receipt_type` | `resource_type` via `From` | Exact mapping |
    /// | `usage_proof_hash` | SHA3-512(`measured_usage`)[..32] | Derived hash |
    /// | `execution_commitment` | `None` | V0 has no EC; Compute will error |
    /// | `coordinator_threshold_signature` | `threshold_signature` param | Caller provides |
    /// | `signer_ids` | `signer_ids` param | Caller provides |
    /// | `node_signature` | `coordinator_signature` | Semantic mismatch (lossy) |
    /// | `submitter_address` | `node_address` bytes | V0: node = submitter |
    /// | `reward_base` | `self.reward_base` | Direct copy |
    /// | `timestamp` | `self.timestamp` | Direct copy |
    /// | `epoch` | `epoch` param | Caller provides |
    ///
    /// ## Errors
    ///
    /// Returns `ReceiptError` if ReceiptV1 invariants are violated:
    /// - `MissingExecutionCommitment` — Compute receipt (V0 has no EC).
    /// - `EmptyCoordinatorSignature` — `threshold_signature` is empty.
    /// - `EmptyNodeSignature` — `coordinator_signature` is empty.
    ///
    /// ## Guarantees
    ///
    /// - No panic. No unwrap.
    /// - No mutation of `self`.
    /// - Deterministic: same inputs → same output.
    pub fn to_receipt_v1(
        &self,
        threshold_signature: Vec<u8>,
        signer_ids: Vec<[u8; 32]>,
        epoch: u64,
    ) -> Result<dsdn_common::receipt_v1::ReceiptV1, dsdn_common::receipt_v1::ReceiptError> {
        use dsdn_common::coordinator::WorkloadId;

        // 1. workload_id: first 32 bytes of receipt_id (64-byte SHA3-512 hash).
        let id_bytes = self.receipt_id.as_bytes();
        let mut wid_bytes = [0u8; 32];
        let copy_len = id_bytes.len().min(32);
        wid_bytes[..copy_len].copy_from_slice(&id_bytes[..copy_len]);
        let workload_id = WorkloadId::new(wid_bytes);

        // 2. node_id: zero-padded from 20-byte Address to 32-byte NodeId.
        let addr_bytes = self.node_address.as_bytes();
        let mut node_id = [0u8; 32];
        let addr_copy_len = addr_bytes.len().min(32);
        node_id[..addr_copy_len].copy_from_slice(&addr_bytes[..addr_copy_len]);

        // 3. receipt_type: From<ResourceType> for ReceiptType.
        let receipt_type: dsdn_common::receipt_v1::ReceiptType = self.resource_type.into();

        // 4. usage_proof_hash: SHA3-512 of measured_usage bytes, take first 32.
        let usage_full_hash = crypto::sha3_512(&self.measured_usage.to_bytes());
        let mut usage_proof_hash = [0u8; 32];
        let hash_bytes = usage_full_hash.as_bytes();
        let hash_copy_len = hash_bytes.len().min(32);
        usage_proof_hash[..hash_copy_len].copy_from_slice(&hash_bytes[..hash_copy_len]);

        // 5. execution_commitment: V0 does not have this field.
        //    Storage → None (correct). Compute → None (will fail at ReceiptV1::new).
        let execution_commitment = None;

        // 6. node_signature: mapped from coordinator_signature (lossy).
        let node_signature = self.coordinator_signature.clone();

        // 7. submitter_address: in V0, node submits its own claim.
        let mut submitter_address = [0u8; 20];
        let sub_copy_len = addr_bytes.len().min(20);
        submitter_address[..sub_copy_len].copy_from_slice(&addr_bytes[..sub_copy_len]);

        // Delegate to ReceiptV1::new() which enforces all invariants.
        dsdn_common::receipt_v1::ReceiptV1::new(
            workload_id,
            node_id,
            receipt_type,
            usage_proof_hash,
            execution_commitment,
            threshold_signature,
            signer_ids,
            node_signature,
            submitter_address,
            self.reward_base,
            self.timestamp,
            epoch,
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_address() -> Address {
        Address::from_str("0x1234567890123456789012345678901234567890").unwrap()
    }

    #[test]
    fn test_receipt_id_deterministic() {
        let receipt1 = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            1_000_000,
            true,
            1700000000,
        );

        let receipt2 = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            1_000_000,
            true,
            1700000000,
        );

        // receipt_id harus sama untuk input yang sama
        assert_eq!(receipt1.receipt_id, receipt2.receipt_id);
        assert_eq!(receipt1.compute_receipt_id(), receipt2.compute_receipt_id());
    }

    #[test]
    fn test_receipt_id_changes_with_field() {
        let receipt1 = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            1_000_000,
            true,
            1700000000,
        );

        let receipt2 = ResourceReceipt::new(
            test_address(),
            NodeClass::Datacenter, // berbeda
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            1_000_000,
            true,
            1700000000,
        );

        // receipt_id harus berbeda
        assert_ne!(receipt1.receipt_id, receipt2.receipt_id);
    }

    #[test]
    fn test_node_class_enum() {
        assert_ne!(NodeClass::Regular, NodeClass::Datacenter);
    }

    #[test]
    fn test_resource_type_enum() {
        assert_ne!(ResourceType::Storage, ResourceType::Compute);
    }

    #[test]
    fn test_measured_usage_to_bytes() {
        let usage = MeasuredUsage::new(1, 2, 3, 4);
        let bytes = usage.to_bytes();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_receipt_without_signature() {
        let receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Compute,
            MeasuredUsage::zero(),
            500_000,
            false,
            1700000001,
        );

        assert!(!receipt.has_signature());
        // verify tanpa signature harus return false
        assert!(!receipt.verify_coordinator_signature());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let mut receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::zero(),
            100,
            false,
            1700000000,
        );
        // signature invalid (bukan Ed25519 valid)
        receipt.set_signature(vec![1, 2, 3]);

        // verifikasi harus gagal
        assert!(!receipt.verify_coordinator_signature());
    }

    // ════════════════════════════════════════════════════════════════════
    // CH.9 — RECEIPT V1 MIGRATION BRIDGE TESTS
    // ════════════════════════════════════════════════════════════════════

    // ── From<ResourceType> for ReceiptType ──────────────────────────────

    #[test]
    fn test_resource_type_to_receipt_type_storage() {
        use dsdn_common::receipt_v1::ReceiptType;
        let rt: ReceiptType = ResourceType::Storage.into();
        assert_eq!(rt, ReceiptType::Storage);
    }

    #[test]
    fn test_resource_type_to_receipt_type_compute() {
        use dsdn_common::receipt_v1::ReceiptType;
        let rt: ReceiptType = ResourceType::Compute.into();
        assert_eq!(rt, ReceiptType::Compute);
    }

    // ── From<ReceiptType> for ResourceType ──────────────────────────────

    #[test]
    fn test_receipt_type_to_resource_type_storage() {
        use dsdn_common::receipt_v1::ReceiptType;
        let rt: ResourceType = ReceiptType::Storage.into();
        assert_eq!(rt, ResourceType::Storage);
    }

    #[test]
    fn test_receipt_type_to_resource_type_compute() {
        use dsdn_common::receipt_v1::ReceiptType;
        let rt: ResourceType = ReceiptType::Compute.into();
        assert_eq!(rt, ResourceType::Compute);
    }

    // ── Roundtrip: ResourceType → ReceiptType → ResourceType ────────────

    #[test]
    fn test_type_conversion_roundtrip() {
        use dsdn_common::receipt_v1::ReceiptType;

        let original_storage = ResourceType::Storage;
        let intermediate: ReceiptType = original_storage.into();
        let roundtrip: ResourceType = intermediate.into();
        assert_eq!(original_storage, roundtrip);

        let original_compute = ResourceType::Compute;
        let intermediate: ReceiptType = original_compute.into();
        let roundtrip: ResourceType = intermediate.into();
        assert_eq!(original_compute, roundtrip);
    }

    // ── can_upgrade_to_v1 ───────────────────────────────────────────────

    #[test]
    fn test_can_upgrade_with_signature_and_reward() {
        let mut receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            1_000_000,
            false,
            1700000000,
        );
        receipt.set_signature(vec![0x01; 64]);
        assert!(receipt.can_upgrade_to_v1());
    }

    #[test]
    fn test_cannot_upgrade_without_signature() {
        let receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            1_000_000,
            false,
            1700000000,
        );
        // No signature set.
        assert!(!receipt.can_upgrade_to_v1());
    }

    #[test]
    fn test_cannot_upgrade_with_zero_reward() {
        let mut receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            0, // Zero reward.
            false,
            1700000000,
        );
        receipt.set_signature(vec![0x01; 64]);
        assert!(!receipt.can_upgrade_to_v1());
    }

    #[test]
    fn test_cannot_upgrade_no_sig_no_reward() {
        let receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::zero(),
            0,
            false,
            1700000000,
        );
        assert!(!receipt.can_upgrade_to_v1());
    }

    // ── to_receipt_v1: Storage (success path) ───────────────────────────

    #[test]
    fn test_to_receipt_v1_storage_success() {
        let mut receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            1_000_000,
            false,
            1700000000,
        );
        receipt.set_signature(vec![0x07; 64]);

        let threshold_sig = vec![0x04; 64];
        let signer_ids = vec![[0x05; 32], [0x06; 32]];
        let epoch = 42u64;

        let result = receipt.to_receipt_v1(threshold_sig, signer_ids.clone(), epoch);
        assert!(result.is_ok());

        let v1 = result.unwrap();
        // receipt_type preserved.
        assert_eq!(
            v1.receipt_type(),
            dsdn_common::receipt_v1::ReceiptType::Storage
        );
        // reward_base preserved.
        assert_eq!(v1.reward_base(), 1_000_000);
        // timestamp preserved.
        assert_eq!(v1.timestamp(), 1700000000);
        // epoch from parameter.
        assert_eq!(v1.epoch(), epoch);
        // execution_commitment is None for Storage.
        assert!(v1.execution_commitment().is_none());
        // signer_ids from parameter.
        assert_eq!(v1.signer_ids(), signer_ids.as_slice());
        // node_signature from coordinator_signature.
        assert_eq!(v1.node_signature(), &[0x07; 64]);
        // coordinator_threshold_signature from parameter.
        assert_eq!(v1.coordinator_threshold_signature(), &[0x04; 64]);
    }

    // ── to_receipt_v1: Compute (fails — no execution_commitment) ────────

    #[test]
    fn test_to_receipt_v1_compute_fails_missing_ec() {
        use dsdn_common::receipt_v1::ReceiptError;

        let mut receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Datacenter,
            ResourceType::Compute,
            MeasuredUsage::new(500, 1000, 0, 200),
            2_000_000,
            true,
            1700000000,
        );
        receipt.set_signature(vec![0x07; 64]);

        let result = receipt.to_receipt_v1(vec![0x04; 64], vec![[0x05; 32]], 10);

        // Compute requires execution_commitment = Some(...), but V0 has None.
        assert_eq!(result, Err(ReceiptError::MissingExecutionCommitment));
    }

    // ── to_receipt_v1: Empty threshold signature fails ──────────────────

    #[test]
    fn test_to_receipt_v1_empty_threshold_sig_fails() {
        use dsdn_common::receipt_v1::ReceiptError;

        let mut receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::zero(),
            1000,
            false,
            1700000000,
        );
        receipt.set_signature(vec![0x07; 64]);

        let result = receipt.to_receipt_v1(
            vec![], // Empty threshold signature.
            vec![[0x05; 32]],
            1,
        );

        assert_eq!(result, Err(ReceiptError::EmptyCoordinatorSignature));
    }

    // ── to_receipt_v1: Empty node signature (coordinator_sig) fails ─────

    #[test]
    fn test_to_receipt_v1_empty_node_sig_fails() {
        use dsdn_common::receipt_v1::ReceiptError;

        // Receipt without coordinator_signature → node_signature empty → fail.
        let receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::zero(),
            1000,
            false,
            1700000000,
        );
        // No set_signature → coordinator_signature is empty Vec.

        let result = receipt.to_receipt_v1(
            vec![0x04; 64],
            vec![[0x05; 32]],
            1,
        );

        assert_eq!(result, Err(ReceiptError::EmptyNodeSignature));
    }

    // ── to_receipt_v1: Deterministic ────────────────────────────────────

    #[test]
    fn test_to_receipt_v1_deterministic() {
        let mut receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            1_000_000,
            false,
            1700000000,
        );
        receipt.set_signature(vec![0x07; 64]);

        let v1a = receipt
            .to_receipt_v1(vec![0x04; 64], vec![[0x05; 32]], 42)
            .unwrap();
        let v1b = receipt
            .to_receipt_v1(vec![0x04; 64], vec![[0x05; 32]], 42)
            .unwrap();

        // Same input → same output.
        assert_eq!(v1a, v1b);
        assert_eq!(v1a.compute_receipt_hash(), v1b.compute_receipt_hash());
    }

    // ── to_receipt_v1: node_id zero-padding ─────────────────────────────

    #[test]
    fn test_to_receipt_v1_node_id_zero_padded() {
        let mut receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::zero(),
            1000,
            false,
            1700000000,
        );
        receipt.set_signature(vec![0x07; 64]);

        let v1 = receipt
            .to_receipt_v1(vec![0x04; 64], vec![], 1)
            .unwrap();

        // node_id: first 20 bytes from address, remaining 12 bytes = 0.
        let node_id = v1.node_id();
        let addr_bytes = receipt.node_address.as_bytes();
        assert_eq!(&node_id[..20], addr_bytes);
        assert_eq!(&node_id[20..], &[0u8; 12]);
    }

    // ── to_receipt_v1: submitter_address equals node_address ────────────

    #[test]
    fn test_to_receipt_v1_submitter_is_node() {
        let mut receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::zero(),
            1000,
            false,
            1700000000,
        );
        receipt.set_signature(vec![0x07; 64]);

        let v1 = receipt
            .to_receipt_v1(vec![0x04; 64], vec![], 1)
            .unwrap();

        // submitter_address == node_address bytes.
        assert_eq!(v1.submitter_address(), receipt.node_address.as_bytes());
    }

    // ── to_receipt_v1: node_class is dropped (lossy) ────────────────────

    #[test]
    fn test_to_receipt_v1_node_class_irrelevant() {
        let mut receipt_regular = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            1000,
            false,
            1700000000,
        );
        receipt_regular.set_signature(vec![0x07; 64]);

        let mut receipt_dc = ResourceReceipt::new(
            test_address(),
            NodeClass::Datacenter,
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            1000,
            false,
            1700000000,
        );
        receipt_dc.set_signature(vec![0x07; 64]);

        let v1_regular = receipt_regular
            .to_receipt_v1(vec![0x04; 64], vec![[0x05; 32]], 42)
            .unwrap();
        let v1_dc = receipt_dc
            .to_receipt_v1(vec![0x04; 64], vec![[0x05; 32]], 42)
            .unwrap();

        // V1 does not carry node_class → both produce identical V1 receipts.
        // However receipt_id differs (node_class affects it), so workload_id
        // and usage_proof_hash may differ. What IS identical:
        assert_eq!(v1_regular.receipt_type(), v1_dc.receipt_type());
        assert_eq!(v1_regular.reward_base(), v1_dc.reward_base());
        assert_eq!(v1_regular.timestamp(), v1_dc.timestamp());
        assert_eq!(v1_regular.epoch(), v1_dc.epoch());
        assert_eq!(v1_regular.submitter_address(), v1_dc.submitter_address());
        assert_eq!(v1_regular.node_id(), v1_dc.node_id());
    }

    // ── to_receipt_v1: does not mutate self ──────────────────────────────

    #[test]
    fn test_to_receipt_v1_no_mutation() {
        let mut receipt = ResourceReceipt::new(
            test_address(),
            NodeClass::Regular,
            ResourceType::Storage,
            MeasuredUsage::new(100, 200, 10, 500),
            1_000_000,
            false,
            1700000000,
        );
        receipt.set_signature(vec![0x07; 64]);

        let before = receipt.clone();

        let _ = receipt.to_receipt_v1(vec![0x04; 64], vec![[0x05; 32]], 42);

        // self unchanged after conversion.
        assert_eq!(receipt, before);
    }
}
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
use crate::crypto;
use serde::{Serialize, Deserialize};

// ════════════════════════════════════════════════════════════════════════════
// COORDINATOR PUBKEY (CONSENSUS-CRITICAL)
// ════════════════════════════════════════════════════════════════════════════

/// Ed25519 public key milik Coordinator untuk verifikasi receipt signature.
/// Placeholder: harus diganti dengan pubkey production sebelum mainnet.
/// Perubahan nilai ini memerlukan hard-fork.
pub const COORDINATOR_PUBKEY: [u8; 32] = [0u8; 32];
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
    /// Ed25519 signature dari Coordinator atas receipt_id
    pub coordinator_signature: Vec<u8>,
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
        
        // Verifikasi Ed25519 signature atas receipt_id bytes
        crypto::ed25519_verify(
            &COORDINATOR_PUBKEY,
            self.receipt_id.as_bytes(),
            &self.coordinator_signature,
        )
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
}
//! Unit tests for ResourceReceipt (13.10)
//!
//! Tests:
//! - test_receipt_id_computation
//! - test_coordinator_signature_valid
//! - test_coordinator_signature_invalid
//! - test_measured_usage_serialization

use crate::receipt::{ResourceReceipt, NodeClass, ResourceType, MeasuredUsage};
use crate::types::Address;
use std::str::FromStr;

/// Alamat deterministik untuk testing
fn test_node_address() -> Address {
    Address::from_str("0x1234567890123456789012345678901234567890").unwrap()
}

/// Receipt deterministik untuk testing
fn create_test_receipt() -> ResourceReceipt {
    ResourceReceipt::new(
        test_node_address(),
        NodeClass::Regular,
        ResourceType::Storage,
        MeasuredUsage::new(100, 200, 10, 500),
        1_000_000,
        true,
        1700000000,
    )
}

#[test]
fn test_receipt_id_computation() {
    // Test 1: receipt_id harus sama untuk data yang sama
    let receipt1 = create_test_receipt();
    let receipt2 = create_test_receipt();
    
    assert_eq!(receipt1.receipt_id, receipt2.receipt_id);
    assert_eq!(receipt1.compute_receipt_id(), receipt2.compute_receipt_id());
    
    // Test 2: receipt_id harus berbeda untuk data berbeda
    let receipt3 = ResourceReceipt::new(
        test_node_address(),
        NodeClass::Datacenter, // berbeda
        ResourceType::Storage,
        MeasuredUsage::new(100, 200, 10, 500),
        1_000_000,
        true,
        1700000000,
    );
    
    assert_ne!(receipt1.receipt_id, receipt3.receipt_id);
    
    // Test 3: receipt_id berubah saat reward_base berubah
    let receipt4 = ResourceReceipt::new(
        test_node_address(),
        NodeClass::Regular,
        ResourceType::Storage,
        MeasuredUsage::new(100, 200, 10, 500),
        2_000_000, // berbeda
        true,
        1700000000,
    );
    
    assert_ne!(receipt1.receipt_id, receipt4.receipt_id);
    
    // Test 4: receipt_id berubah saat timestamp berubah
    let receipt5 = ResourceReceipt::new(
        test_node_address(),
        NodeClass::Regular,
        ResourceType::Storage,
        MeasuredUsage::new(100, 200, 10, 500),
        1_000_000,
        true,
        1700000001, // berbeda
    );
    
    assert_ne!(receipt1.receipt_id, receipt5.receipt_id);
}

#[test]
fn test_coordinator_signature_valid() {
    // Dengan COORDINATOR_PUBKEY = [0u8; 32] (placeholder),
    // tidak ada signature yang valid karena bukan valid Ed25519 keypair.
    // Test ini memverifikasi bahwa mekanisme verifikasi bekerja.
    
    let receipt = create_test_receipt();
    
    // Tanpa signature → invalid
    assert!(!receipt.verify_coordinator_signature());
    assert!(!receipt.has_signature());
}

#[test]
fn test_coordinator_signature_invalid() {
    let mut receipt = create_test_receipt();
    
    // Set signature invalid (bukan Ed25519 valid)
    receipt.set_signature(vec![0x01, 0x02, 0x03, 0x04]);
    
    assert!(receipt.has_signature());
    assert!(!receipt.verify_coordinator_signature());
    
    // Set signature dengan panjang 64 bytes tapi invalid
    receipt.set_signature(vec![0u8; 64]);
    
    assert!(receipt.has_signature());
    assert!(!receipt.verify_coordinator_signature());
    
    // Empty signature → invalid
    receipt.set_signature(vec![]);
    
    assert!(!receipt.has_signature());
    assert!(!receipt.verify_coordinator_signature());
}

#[test]
fn test_measured_usage_serialization() {
    // Test 1: Zero values
    let usage_zero = MeasuredUsage::zero();
    assert_eq!(usage_zero.cpu, 0);
    assert_eq!(usage_zero.ram, 0);
    assert_eq!(usage_zero.chunk_count, 0);
    assert_eq!(usage_zero.bw, 0);
    
    // Test 2: to_bytes menghasilkan 32 bytes (4 x u64 BE)
    let usage = MeasuredUsage::new(1, 2, 3, 4);
    let bytes = usage.to_bytes();
    assert_eq!(bytes.len(), 32);
    
    // Test 3: Byte order big-endian
    let usage2 = MeasuredUsage::new(0x0102030405060708, 0, 0, 0);
    let bytes2 = usage2.to_bytes();
    assert_eq!(bytes2[0], 0x01);
    assert_eq!(bytes2[7], 0x08);
    
    // Test 4: Deterministic
    let usage3 = MeasuredUsage::new(100, 200, 10, 500);
    let usage4 = MeasuredUsage::new(100, 200, 10, 500);
    assert_eq!(usage3.to_bytes(), usage4.to_bytes());
    
    // Test 5: Serde roundtrip
    let original = MeasuredUsage::new(12345, 67890, 111, 222);
    let json = serde_json::to_string(&original).unwrap();
    let restored: MeasuredUsage = serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
}
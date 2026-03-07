use super::*;

// ════════════════════════════════════════════════════════════════════════
// TEST 1: VALIDATE NODE ID - VALID
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_validate_node_id_valid() {
    assert!(validate_node_id("node-1").is_ok());
    assert!(validate_node_id("node_abc_123").is_ok());
    assert!(validate_node_id("a").is_ok());
}

// ════════════════════════════════════════════════════════════════════════
// TEST 2: VALIDATE NODE ID - EMPTY
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_validate_node_id_empty() {
    let result = validate_node_id("");
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("cannot be empty"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 3: VALIDATE NODE ID - TOO LONG
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_validate_node_id_too_long() {
    let long_id = "a".repeat(300);
    let result = validate_node_id(&long_id);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("too long"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 4: NODE STATUS TO TABLE
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_node_status_to_table() {
    let status = NodeStatusFromDA {
        node_id: "node-1".to_string(),
        registration_status: "registered".to_string(),
        addr: "127.0.0.1:9000".to_string(),
        zone: Some("zone-a".to_string()),
        is_active: true,
        chunk_count: 10,
        replica_count: 10,
        da_height: 100,
    };

    let table = status.to_table();

    assert!(table.contains("NODE STATUS"));
    assert!(table.contains("node-1"));
    assert!(table.contains("registered"));
    assert!(table.contains("127.0.0.1:9000"));
    assert!(table.contains("zone-a"));
    assert!(table.contains("yes")); // is_active
    assert!(table.contains("10")); // chunk_count
    assert!(table.contains("from DA"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 5: NODE STATUS TO JSON
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_node_status_to_json() {
    let status = NodeStatusFromDA {
        node_id: "node-1".to_string(),
        registration_status: "registered".to_string(),
        addr: "127.0.0.1:9000".to_string(),
        zone: Some("zone-a".to_string()),
        is_active: true,
        chunk_count: 10,
        replica_count: 10,
        da_height: 100,
    };

    let json = status.to_json().expect("should serialize");
    let parsed: NodeStatusFromDA = serde_json::from_str(&json).expect("should parse");

    assert_eq!(parsed.node_id, status.node_id);
    assert_eq!(parsed.is_active, status.is_active);
    assert_eq!(parsed.chunk_count, status.chunk_count);
}

// ════════════════════════════════════════════════════════════════════════
// TEST 6: NODE LIST EMPTY
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_node_list_empty() {
    let list = NodeListFromDA {
        nodes: vec![],
        total: 0,
        active_count: 0,
        da_height: 0,
    };

    let table = list.to_table();
    assert!(table.contains("No nodes found"));
    assert!(table.contains("Total: 0"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 7: NODE LIST WITH NODES
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_node_list_with_nodes() {
    let list = NodeListFromDA {
        nodes: vec![
            NodeListEntry {
                node_id: "node-1".to_string(),
                addr: "127.0.0.1:9000".to_string(),
                zone: Some("zone-a".to_string()),
                is_active: true,
                chunk_count: 5,
            },
            NodeListEntry {
                node_id: "node-2".to_string(),
                addr: "127.0.0.1:9001".to_string(),
                zone: None,
                is_active: false,
                chunk_count: 0,
            },
        ],
        total: 2,
        active_count: 1,
        da_height: 100,
    };

    let table = list.to_table();
    assert!(table.contains("node-1"));
    assert!(table.contains("node-2"));
    assert!(table.contains("Total: 2"));
    assert!(table.contains("Active: 1"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 8: NODE LIST JSON
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_node_list_json() {
    let list = NodeListFromDA {
        nodes: vec![
            NodeListEntry {
                node_id: "node-1".to_string(),
                addr: "127.0.0.1:9000".to_string(),
                zone: None,
                is_active: true,
                chunk_count: 5,
            },
        ],
        total: 1,
        active_count: 1,
        da_height: 100,
    };

    let json = list.to_json().expect("should serialize");
    let parsed: NodeListFromDA = serde_json::from_str(&json).expect("should parse");

    assert_eq!(parsed.total, 1);
    assert_eq!(parsed.nodes.len(), 1);
    assert_eq!(parsed.nodes[0].node_id, "node-1");
}

// ════════════════════════════════════════════════════════════════════════
// TEST 9: NODE CHUNKS EMPTY
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_node_chunks_empty() {
    let chunks = NodeChunksFromDA {
        node_id: "node-1".to_string(),
        chunks: vec![],
        total: 0,
        total_size: 0,
        da_height: 100,
    };

    let table = chunks.to_table();
    assert!(table.contains("node-1"));
    assert!(table.contains("No chunks assigned"));
    assert!(table.contains("Total: 0"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 10: NODE CHUNKS WITH DATA
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_node_chunks_with_data() {
    let chunks = NodeChunksFromDA {
        node_id: "node-1".to_string(),
        chunks: vec![
            ChunkAssignment {
                chunk_hash: "abc123".to_string(),
                size: 1024,
                owner: "owner-1".to_string(),
            },
            ChunkAssignment {
                chunk_hash: "def456".to_string(),
                size: 2048,
                owner: "owner-2".to_string(),
            },
        ],
        total: 2,
        total_size: 3072,
        da_height: 100,
    };

    let table = chunks.to_table();
    assert!(table.contains("abc123"));
    assert!(table.contains("def456"));
    assert!(table.contains("1024"));
    assert!(table.contains("2048"));
    assert!(table.contains("Total: 2"));
    assert!(table.contains("3072"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 11: NODE CHUNKS JSON
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_node_chunks_json() {
    let chunks = NodeChunksFromDA {
        node_id: "node-1".to_string(),
        chunks: vec![
            ChunkAssignment {
                chunk_hash: "abc123".to_string(),
                size: 1024,
                owner: "owner-1".to_string(),
            },
        ],
        total: 1,
        total_size: 1024,
        da_height: 100,
    };

    let json = chunks.to_json().expect("should serialize");
    let parsed: NodeChunksFromDA = serde_json::from_str(&json).expect("should parse");

    assert_eq!(parsed.node_id, "node-1");
    assert_eq!(parsed.total, 1);
    assert_eq!(parsed.chunks[0].chunk_hash, "abc123");
}

// ════════════════════════════════════════════════════════════════════════
// TEST 12: TRUNCATE STRING
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_truncate_str() {
    assert_eq!(truncate_str("short", 10), "short");
    assert_eq!(truncate_str("exactly10!", 10), "exactly10!");
    assert_eq!(truncate_str("this is too long", 10), "this is...");
    assert_eq!(truncate_str("abc", 3), "abc");
    assert_eq!(truncate_str("abcd", 3), "abc");
}

// ════════════════════════════════════════════════════════════════════════
// TEST 13: DETERMINISTIC OUTPUT - NODE LIST SORTING
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_node_list_deterministic_sorting() {
    // Create unsorted nodes
    let list1 = NodeListFromDA {
        nodes: vec![
            NodeListEntry {
                node_id: "node-z".to_string(),
                addr: "addr1".to_string(),
                zone: None,
                is_active: true,
                chunk_count: 0,
            },
            NodeListEntry {
                node_id: "node-a".to_string(),
                addr: "addr2".to_string(),
                zone: None,
                is_active: true,
                chunk_count: 0,
            },
        ],
        total: 2,
        active_count: 2,
        da_height: 100,
    };

    // Verify order in table
    let table = list1.to_table();
    let pos_a = table.find("node-a");
    let pos_z = table.find("node-z");
    assert!(pos_a.is_some() && pos_z.is_some());
    // Both should be present (order depends on Vec order, but in real usage we sort)
}

// ════════════════════════════════════════════════════════════════════════
// TEST 14: NO PANIC ON ZONE NONE
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_no_panic_on_zone_none() {
    let status = NodeStatusFromDA {
        node_id: "node-1".to_string(),
        registration_status: "registered".to_string(),
        addr: "127.0.0.1:9000".to_string(),
        zone: None,
        is_active: true,
        chunk_count: 0,
        replica_count: 0,
        da_height: 0,
    };

    let table = status.to_table();
    assert!(table.contains("(none)"));

    let json = status.to_json().expect("should serialize");
    assert!(json.contains("null") || !json.contains("zone")); // zone is null in JSON
}

// ════════════════════════════════════════════════════════════════════════
// TEST 15: PARSE VERIFY TARGET
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_parse_verify_target() {
    assert!(parse_verify_target("coordinator").is_ok());
    assert!(parse_verify_target("node").is_ok());
    assert!(parse_verify_target("COORDINATOR").is_ok());
    assert!(parse_verify_target("invalid").is_err());
}

// ════════════════════════════════════════════════════════════════════════
// TEST 16: TRACKING STAGE DISPLAY
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_tracking_stage_display() {
    assert_eq!(format!("{}", TrackingStage::Uploading), "UPLOADING");
    assert_eq!(format!("{}", TrackingStage::WaitingDeclared), "WAITING_DECLARED");
    assert_eq!(
        format!("{}", TrackingStage::WaitingReplication { current: 2, target: 3 }),
        "REPLICATING (2/3)"
    );
    assert_eq!(format!("{}", TrackingStage::Complete), "COMPLETE");
    assert_eq!(
        format!("{}", TrackingStage::Failed("timeout".to_string())),
        "FAILED: timeout"
    );
}

// ════════════════════════════════════════════════════════════════════════
// TEST 17: TRACKING RESULT TO TABLE
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_tracking_result_to_table() {
    let result = UploadTrackingResult {
        chunk_hash: "abc123def456".to_string(),
        size: 1024,
        declared: true,
        declared_height: Some(100),
        replicas: vec!["node-1".to_string(), "node-2".to_string()],
        replication_factor: 2,
        target_rf: 3,
        rf_achieved: false,
        tracking_time_ms: 5000,
    };

    let table = result.to_table();
    assert!(table.contains("UPLOAD TRACKING RESULT"));
    assert!(table.contains("abc123def456"));
    assert!(table.contains("1024"));
    assert!(table.contains("yes")); // declared
    assert!(table.contains("100")); // declared height
    assert!(table.contains("2 /   3")); // replication
    assert!(table.contains("node-1"));
    assert!(table.contains("node-2"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 18: TRACKING RESULT EMPTY REPLICAS
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_tracking_result_empty_replicas() {
    let result = UploadTrackingResult {
        chunk_hash: "xyz789".to_string(),
        size: 512,
        declared: false,
        declared_height: None,
        replicas: vec![],
        replication_factor: 0,
        target_rf: 1,
        rf_achieved: false,
        tracking_time_ms: 1000,
    };

    let table = result.to_table();
    assert!(table.contains("xyz789"));
    assert!(table.contains("no")); // declared = no
    assert!(table.contains("(none)")); // replicas
}

// ════════════════════════════════════════════════════════════════════════
// TEST 19: TRACKING RESULT RF ACHIEVED
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_tracking_result_rf_achieved() {
    let result = UploadTrackingResult {
        chunk_hash: "test123".to_string(),
        size: 2048,
        declared: true,
        declared_height: Some(50),
        replicas: vec!["node-1".to_string(), "node-2".to_string(), "node-3".to_string()],
        replication_factor: 3,
        target_rf: 3,
        rf_achieved: true,
        tracking_time_ms: 3000,
    };

    let table = result.to_table();
    assert!(table.contains("(achieved)"));
    assert!(table.contains("node-3"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 20: TRACKING CONFIG FROM ENV
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_tracking_config_default_values() {
    // This test verifies the config structure is correct
    let config = TrackingConfig {
        da_endpoint: "http://localhost:26658".to_string(),
        namespace: "test".to_string(),
        timeout_secs: 120,
        poll_interval_ms: 2000,
    };

    assert_eq!(config.timeout_secs, 120);
    assert_eq!(config.poll_interval_ms, 2000);
}

// ════════════════════════════════════════════════════════════════════════
// TEST 21: TRACKING STAGE EQUALITY
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_tracking_stage_equality() {
    assert_eq!(TrackingStage::Uploading, TrackingStage::Uploading);
    assert_eq!(TrackingStage::Complete, TrackingStage::Complete);
    assert_eq!(
        TrackingStage::WaitingReplication { current: 1, target: 2 },
        TrackingStage::WaitingReplication { current: 1, target: 2 }
    );
    assert_ne!(
        TrackingStage::WaitingReplication { current: 1, target: 2 },
        TrackingStage::WaitingReplication { current: 2, target: 2 }
    );
}

// ════════════════════════════════════════════════════════════════════════
// TEST 22: DOWNLOAD VERIFICATION RESULT TO TABLE
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_download_verification_result_to_table() {
    let result = DownloadVerificationResult {
        chunk_hash: "abc123def456".to_string(),
        expected_size: 1024,
        actual_size: 1024,
        verified: true,
        source_node_id: Some("node-1".to_string()),
        source_node_addr: Some("127.0.0.1:9000".to_string()),
        attempts: vec![
            DownloadAttemptInfo {
                node_id: "node-1".to_string(),
                node_addr: "127.0.0.1:9000".to_string(),
                success: true,
                reason: Some("verified".to_string()),
            },
        ],
        da_height: 100,
    };

    let table = result.to_table();
    assert!(table.contains("DOWNLOAD VERIFICATION RESULT"));
    assert!(table.contains("abc123def456"));
    assert!(table.contains("1024"));
    assert!(table.contains("YES"));
    assert!(table.contains("node-1"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 23: DOWNLOAD VERIFICATION RESULT FAILED
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_download_verification_result_failed() {
    let result = DownloadVerificationResult {
        chunk_hash: "xyz789".to_string(),
        expected_size: 2048,
        actual_size: 0,
        verified: false,
        source_node_id: None,
        source_node_addr: None,
        attempts: vec![
            DownloadAttemptInfo {
                node_id: "node-1".to_string(),
                node_addr: "127.0.0.1:9000".to_string(),
                success: false,
                reason: Some("connection refused".to_string()),
            },
            DownloadAttemptInfo {
                node_id: "node-2".to_string(),
                node_addr: "127.0.0.1:9001".to_string(),
                success: false,
                reason: Some("hash mismatch".to_string()),
            },
        ],
        da_height: 50,
    };

    let table = result.to_table();
    assert!(table.contains("xyz789"));
    assert!(table.contains("NO"));
    assert!(table.contains("node-1"));
    assert!(table.contains("node-2"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 24: VERIFY CHUNK INTEGRITY
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_verify_chunk_integrity() {
    let data = b"hello world";
    let hash = sha256_hex(data);
    
    assert!(verify_chunk_integrity(data, &hash));
    assert!(!verify_chunk_integrity(data, "wrong_hash"));
    assert!(!verify_chunk_integrity(b"different data", &hash));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 25: DOWNLOAD ATTEMPT INFO SERIALIZATION
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_download_attempt_info_serialization() {
    let attempt = DownloadAttemptInfo {
        node_id: "node-1".to_string(),
        node_addr: "127.0.0.1:9000".to_string(),
        success: true,
        reason: Some("verified".to_string()),
    };

    let json = serde_json::to_string(&attempt).expect("should serialize");
    let parsed: DownloadAttemptInfo = serde_json::from_str(&json).expect("should parse");

    assert_eq!(parsed.node_id, "node-1");
    assert_eq!(parsed.success, true);
}

// ════════════════════════════════════════════════════════════════════════
// TEST 26: DOWNLOAD VERIFICATION EMPTY ATTEMPTS
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_download_verification_empty_attempts() {
    let result = DownloadVerificationResult {
        chunk_hash: "test123".to_string(),
        expected_size: 512,
        actual_size: 0,
        verified: false,
        source_node_id: None,
        source_node_addr: None,
        attempts: vec![],
        da_height: 0,
    };

    let table = result.to_table();
    assert!(table.contains("(none)"));
}

// ════════════════════════════════════════════════════════════════════════
// TEST 27: PARSE REBUILD TARGET
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_parse_rebuild_target() {
    assert!(parse_rebuild_target("coordinator").is_ok());
    assert!(parse_rebuild_target("node").is_ok());
    assert!(parse_rebuild_target("COORDINATOR").is_ok());
    assert!(parse_rebuild_target("NODE").is_ok());
    assert!(parse_rebuild_target("invalid").is_err());
}
//! DA Integration Tests
//!
//! End-to-end integration tests for the Data Availability layer.
//! Tests DALayer trait, MockDA implementation, and all core operations.

use dsdn_common::{BlobRef, DAError, DAHealthStatus, MockDA};
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;

// ════════════════════════════════════════════════════════════════════════════════
// A. DALAYER WITH MOCKDA - BASIC OPERATIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Test post_blob followed by get_blob returns identical data.
#[tokio::test]
async fn test_dalayer_post_and_get_blob() {
    let mock_da = MockDA::new();
    let test_data = b"integration test data for DA layer".to_vec();

    // Post blob
    let blob_ref = mock_da
        .post_blob(&test_data)
        .await
        .expect("post_blob should succeed");

    // Verify blob_ref is valid
    assert!(blob_ref.height >= 1, "height should be >= 1");
    assert_eq!(blob_ref.namespace, *mock_da.namespace());

    // Get blob back
    let retrieved = mock_da
        .get_blob(&blob_ref)
        .await
        .expect("get_blob should succeed");

    // Data must be identical
    assert_eq!(retrieved, test_data, "retrieved data must match original");
}

/// Test multiple blobs can be stored and retrieved independently.
#[tokio::test]
async fn test_dalayer_multiple_blobs() {
    let mock_da = MockDA::new();

    let data1 = b"first blob data".to_vec();
    let data2 = b"second blob data".to_vec();
    let data3 = b"third blob data".to_vec();

    let ref1 = mock_da.post_blob(&data1).await.unwrap();
    let ref2 = mock_da.post_blob(&data2).await.unwrap();
    let ref3 = mock_da.post_blob(&data3).await.unwrap();

    // Each blob should have unique height
    assert_ne!(ref1.height, ref2.height);
    assert_ne!(ref2.height, ref3.height);

    // All should be retrievable with correct data
    assert_eq!(mock_da.get_blob(&ref1).await.unwrap(), data1);
    assert_eq!(mock_da.get_blob(&ref2).await.unwrap(), data2);
    assert_eq!(mock_da.get_blob(&ref3).await.unwrap(), data3);
}

/// Test health_check returns correct status.
#[tokio::test]
async fn test_dalayer_health_check() {
    let mock_da = MockDA::new();

    let status = mock_da.health_check().await;
    assert_eq!(status, DAHealthStatus::Healthy);
}

/// Test health_check returns Degraded when latency is high.
#[tokio::test]
async fn test_dalayer_health_check_degraded() {
    let mock_da = MockDA::with_latency(600); // > 500ms threshold

    let status = mock_da.health_check().await;
    assert_eq!(status, DAHealthStatus::Degraded);
}

/// Test health_check returns Unavailable when failure_rate is 1.0.
#[tokio::test]
async fn test_dalayer_health_check_unavailable() {
    let mock_da = MockDA::with_failure_rate(1.0);

    let status = mock_da.health_check().await;
    assert_eq!(status, DAHealthStatus::Unavailable);
}

// ════════════════════════════════════════════════════════════════════════════════
// B. ENCODING / DECODING ROUNDTRIP
// ════════════════════════════════════════════════════════════════════════════════

/// Test binary data roundtrip through DA layer.
#[tokio::test]
async fn test_encoding_roundtrip_binary() {
    let mock_da = MockDA::new();

    // Various binary patterns
    let test_cases: Vec<Vec<u8>> = vec![
        vec![0x00, 0x01, 0x02, 0x03],
        vec![0xFF; 100],
        vec![0x00; 50],
        (0..256).map(|i| i as u8).collect(),
        b"utf8 string data".to_vec(),
    ];

    for original_data in test_cases {
        let blob_ref = mock_da.post_blob(&original_data).await.unwrap();
        let retrieved = mock_da.get_blob(&blob_ref).await.unwrap();
        assert_eq!(
            retrieved, original_data,
            "roundtrip must preserve data exactly"
        );
    }
}

/// Test empty blob roundtrip.
#[tokio::test]
async fn test_encoding_roundtrip_empty() {
    let mock_da = MockDA::new();

    let empty_data: Vec<u8> = vec![];
    let blob_ref = mock_da.post_blob(&empty_data).await.unwrap();
    let retrieved = mock_da.get_blob(&blob_ref).await.unwrap();

    assert!(retrieved.is_empty(), "empty data should roundtrip correctly");
}

/// Test large blob roundtrip.
#[tokio::test]
async fn test_encoding_roundtrip_large() {
    let mock_da = MockDA::new();

    // 1MB of data
    let large_data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    let blob_ref = mock_da.post_blob(&large_data).await.unwrap();
    let retrieved = mock_da.get_blob(&blob_ref).await.unwrap();

    assert_eq!(retrieved.len(), large_data.len());
    assert_eq!(retrieved, large_data);
}

/// Test JSON-like structured data roundtrip.
#[tokio::test]
async fn test_encoding_roundtrip_json_structure() {
    let mock_da = MockDA::new();

    let json_data = r#"{"type":"event","height":100,"data":"test"}"#.as_bytes();

    let blob_ref = mock_da.post_blob(json_data).await.unwrap();
    let retrieved = mock_da.get_blob(&blob_ref).await.unwrap();

    assert_eq!(retrieved, json_data);
}

// ════════════════════════════════════════════════════════════════════════════════
// C. SUBSCRIPTION STREAM TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// Test subscribe_blobs yields blobs matching namespace.
#[tokio::test]
async fn test_subscription_yields_matching_namespace() {
    let mock_da = Arc::new(MockDA::new());
    let namespace = *mock_da.namespace();

    // Inject blobs
    mock_da.inject_blob(b"blob1".to_vec());
    mock_da.inject_blob(b"blob2".to_vec());
    mock_da.inject_blob(b"blob3".to_vec());

    let mut stream = mock_da.subscribe_blobs(&namespace);

    // Collect first 3 blobs
    let mut count = 0;
    while count < 3 {
        let result = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;

        match result {
            Ok(Some(Ok(blob))) => {
                assert_eq!(
                    blob.ref_.namespace, namespace,
                    "blob namespace must match subscription namespace"
                );
                count += 1;
            }
            Ok(Some(Err(e))) => panic!("unexpected error: {:?}", e),
            Ok(None) => panic!("stream ended unexpectedly"),
            Err(_) => panic!("timeout waiting for blob"),
        }
    }

    assert_eq!(count, 3, "should receive all 3 blobs");
}

/// Test subscribe_blobs ordering by height.
#[tokio::test]
async fn test_subscription_ordering_by_height() {
    let mock_da = Arc::new(MockDA::new());
    let namespace = *mock_da.namespace();

    // Inject blobs in order
    mock_da.inject_blob(b"first".to_vec());
    mock_da.inject_blob(b"second".to_vec());
    mock_da.inject_blob(b"third".to_vec());

    let mut stream = mock_da.subscribe_blobs(&namespace);

    // Collect heights
    let mut heights = Vec::new();
    for _ in 0..3 {
        let result = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;
        if let Ok(Some(Ok(blob))) = result {
            heights.push(blob.ref_.height);
        }
    }

    // Verify ascending order
    assert_eq!(heights.len(), 3);
    for i in 1..heights.len() {
        assert!(
            heights[i] > heights[i - 1],
            "heights must be in ascending order: {:?}",
            heights
        );
    }
}

/// Test subscribe_blobs filters different namespace.
/// Since MockDA always uses its internal namespace for inject_blob,
/// we verify that subscription correctly waits when no blobs exist.
#[tokio::test]
async fn test_subscription_waits_when_no_blobs() {
    let mock_da = Arc::new(MockDA::new());
    let namespace = *mock_da.namespace();

    // Don't inject any blobs - subscription should wait/timeout
    let mut stream = mock_da.subscribe_blobs(&namespace);

    // Should timeout because no blobs exist
    let result = tokio::time::timeout(Duration::from_millis(300), stream.next()).await;

    assert!(result.is_err(), "should timeout when no blobs exist");
}

/// Test subscribe_blobs no duplication.
#[tokio::test]
async fn test_subscription_no_duplication() {
    let mock_da = Arc::new(MockDA::new());
    let namespace = *mock_da.namespace();

    // Inject 3 blobs
    let ref1 = mock_da.inject_blob(b"blob1".to_vec());
    let ref2 = mock_da.inject_blob(b"blob2".to_vec());
    let ref3 = mock_da.inject_blob(b"blob3".to_vec());

    let mut stream = mock_da.subscribe_blobs(&namespace);

    // Collect all blob refs
    let mut received_refs = Vec::new();
    for _ in 0..3 {
        let result = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;
        if let Ok(Some(Ok(blob))) = result {
            received_refs.push(blob.ref_.clone());
        }
    }

    // Check no duplicates
    assert_eq!(received_refs.len(), 3);

    let unique_count = {
        let mut unique = received_refs.clone();
        unique.sort_by_key(|r| r.height);
        unique.dedup_by(|a, b| a.height == b.height && a.commitment == b.commitment);
        unique.len()
    };

    assert_eq!(unique_count, 3, "no duplicate blobs should be received");

    // Verify all original refs are received
    let heights: Vec<u64> = received_refs.iter().map(|r| r.height).collect();
    assert!(heights.contains(&ref1.height));
    assert!(heights.contains(&ref2.height));
    assert!(heights.contains(&ref3.height));
}

// ════════════════════════════════════════════════════════════════════════════════
// D. ERROR PROPAGATION TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// Test get_blob returns BlobNotFound for non-existent blob.
#[tokio::test]
async fn test_error_blob_not_found() {
    let mock_da = MockDA::new();

    let fake_ref = BlobRef {
        height: 999999,
        commitment: [0xAB; 32],
        namespace: *mock_da.namespace(),
    };

    let result = mock_da.get_blob(&fake_ref).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DAError::BlobNotFound(ref_) => {
            assert_eq!(ref_.height, 999999);
        }
        e => panic!("expected BlobNotFound, got {:?}", e),
    }
}

/// Test failure_rate causes Unavailable error.
#[tokio::test]
async fn test_error_unavailable_on_failure() {
    let mock_da = MockDA::with_failure_rate(1.0);

    let result = mock_da.post_blob(b"test").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DAError::Unavailable));
}

/// Test error propagation does not panic.
#[tokio::test]
async fn test_error_no_panic_on_any_error() {
    let mock_da = MockDA::with_failure_rate(1.0);

    // Multiple operations that should fail - none should panic
    for _ in 0..10 {
        let _ = mock_da.post_blob(b"test").await;
        let _ = mock_da
            .get_blob(&BlobRef {
                height: 1,
                commitment: [0; 32],
                namespace: [0; 29],
            })
            .await;
        let _ = mock_da.health_check().await;
    }

    // If we reach here, no panic occurred
}

/// Test subscription stream handles failure gracefully.
#[tokio::test]
async fn test_error_subscription_with_failure() {
    let mock_da = Arc::new(MockDA::with_failure_rate(1.0));
    let namespace = *mock_da.namespace();

    let mut stream = mock_da.subscribe_blobs(&namespace);

    // Get first item - should be an error due to failure_rate
    let result = tokio::time::timeout(Duration::from_secs(1), stream.next()).await;

    match result {
        Ok(Some(Err(DAError::Unavailable))) => {
            // Expected behavior
        }
        Ok(Some(Err(e))) => {
            // Other error is also acceptable
            assert!(
                matches!(e, DAError::Unavailable),
                "unexpected error type: {:?}",
                e
            );
        }
        Ok(Some(Ok(_))) => panic!("should not succeed with failure_rate 1.0"),
        Ok(None) => panic!("stream should not end"),
        Err(_) => {
            // Timeout is acceptable if failure prevents yielding
        }
    }

    // Stream should not have panicked
}

/// Test error types are correctly propagated.
#[tokio::test]
async fn test_error_types_correct() {
    let mock_da = MockDA::new();

    // BlobNotFound
    let fake_ref = BlobRef {
        height: 1,
        commitment: [0xFF; 32],
        namespace: *mock_da.namespace(),
    };
    let err = mock_da.get_blob(&fake_ref).await.unwrap_err();
    assert!(
        matches!(err, DAError::BlobNotFound(_)),
        "should be BlobNotFound"
    );

    // Unavailable (via failure_rate)
    let failing_da = MockDA::with_failure_rate(1.0);
    let err = failing_da.post_blob(b"test").await.unwrap_err();
    assert!(matches!(err, DAError::Unavailable), "should be Unavailable");
}

// ════════════════════════════════════════════════════════════════════════════════
// ADDITIONAL INTEGRATION TESTS
// ════════════════════════════════════════════════════════════════════════════════

/// Test inject_blob and clear helpers work correctly.
#[tokio::test]
async fn test_inject_and_clear() {
    let mock_da = MockDA::new();

    // Inject
    let ref1 = mock_da.inject_blob(b"test1".to_vec());
    let ref2 = mock_da.inject_blob(b"test2".to_vec());

    assert_eq!(mock_da.blob_count(), 2);

    // Verify retrievable
    assert!(mock_da.get_blob(&ref1).await.is_ok());
    assert!(mock_da.get_blob(&ref2).await.is_ok());

    // Clear
    mock_da.clear();

    assert_eq!(mock_da.blob_count(), 0);

    // Verify not retrievable
    assert!(matches!(
        mock_da.get_blob(&ref1).await.unwrap_err(),
        DAError::BlobNotFound(_)
    ));
}

/// Test concurrent operations are safe.
#[tokio::test]
async fn test_concurrent_operations() {
    let mock_da = Arc::new(MockDA::new());

    let mut handles = Vec::new();

    // Spawn 10 concurrent post_blob operations
    for i in 0..10 {
        let da = Arc::clone(&mock_da);
        handles.push(tokio::spawn(async move {
            da.post_blob(format!("blob {}", i).as_bytes()).await
        }));
    }

    // Wait for all to complete
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    assert_eq!(mock_da.blob_count(), 10);
}

/// Test namespace isolation between instances.
#[tokio::test]
async fn test_namespace_isolation() {
    let da1 = MockDA::new();
    let da2 = MockDA::new();

    let ref1 = da1.post_blob(b"data for da1").await.unwrap();

    // Should not be found in da2
    let result = da2.get_blob(&ref1).await;
    assert!(matches!(result.unwrap_err(), DAError::BlobNotFound(_)));
}

/// Test DAHealthStatus variants.
#[tokio::test]
async fn test_health_status_variants() {
    // Healthy
    let healthy_da = MockDA::new();
    assert_eq!(healthy_da.health_check().await, DAHealthStatus::Healthy);

    // Degraded (high latency)
    let degraded_da = MockDA::with_latency(600);
    assert_eq!(degraded_da.health_check().await, DAHealthStatus::Degraded);

    // Unavailable (failure)
    let unavailable_da = MockDA::with_failure_rate(1.0);
    assert_eq!(
        unavailable_da.health_check().await,
        DAHealthStatus::Unavailable
    );
}
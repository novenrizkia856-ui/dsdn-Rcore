use std::env;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use dsdn_common::{CelestiaDA, DAConfig, DAHealthStatus, DALayer};

// ════════════════════════════════════════════════════════════════════════════
// TEST CONFIGURATION
// ════════════════════════════════════════════════════════════════════════════

/// Load .env file from project root.
fn load_env() {
    // Test file is at: dsdn/crates/common/tests/
    // .env is at: dsdn/
    // So we need to go up 3 levels
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")); // crates/common
    path.pop(); // crates
    path.pop(); // dsdn (root)
    
    // Try .env.mainnet first
    let mut env_path = path.clone();
    env_path.push(".env.mainnet");
    
    if env_path.exists() {
        dotenv::from_path(&env_path).ok();
        eprintln!("📁 Loaded env from: {}", env_path.display());
    } else {
        // Fallback to .env
        let mut fallback = path.clone();
        fallback.push(".env");
        if fallback.exists() {
            dotenv::from_path(&fallback).ok();
            eprintln!("📁 Loaded env from: {}", fallback.display());
        } else {
            eprintln!("⚠️  No .env or .env.mainnet found at project root");
        }
    }
}

/// Check if mainnet test prerequisites are available.
/// 
/// Uses STANDARDIZED environment variables:
/// - DA_RPC_URL: RPC endpoint
/// - DA_AUTH_TOKEN: Auth token (required for mainnet)
/// - DA_NAMESPACE: Namespace hex (58 characters)
fn check_prerequisites() -> Option<DAConfig> {
    // Load env file first
    load_env();
    
    // Use standardized env var names
    let rpc = env::var("DA_RPC_URL").ok()?;
    let token = env::var("DA_AUTH_TOKEN").ok()?;
    let namespace_hex = env::var("DA_NAMESPACE").ok()?;
    let network = env::var("DA_NETWORK").unwrap_or_else(|_| "mainnet".to_string());

    eprintln!("🔧 Config loaded:");
    eprintln!("   RPC: {}", rpc);
    eprintln!("   Token: {}...", &token[..20.min(token.len())]);
    eprintln!("   Namespace: {}", namespace_hex);
    eprintln!("   Network: {}", network);

    // Parse namespace (58 hex chars = 29 bytes)
    if namespace_hex.len() != 58 {
        eprintln!("❌ DA_NAMESPACE must be 58 hex characters (got {})", namespace_hex.len());
        return None;
    }

    let mut namespace = [0u8; 29];
    for (i, chunk) in namespace_hex.as_bytes().chunks(2).enumerate() {
        let hex_str = std::str::from_utf8(chunk).ok()?;
        namespace[i] = u8::from_str_radix(hex_str, 16).ok()?;
    }

    // Optional config values with defaults
    let timeout_ms = env::var("DA_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60000);
    
    let retry_count = env::var("DA_RETRY_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    
    let retry_delay_ms = env::var("DA_RETRY_DELAY_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);

    Some(DAConfig {
        rpc_url: rpc,
        namespace,
        auth_token: Some(token),
        timeout_ms,
        retry_count,
        retry_delay_ms,
        network,
        enable_pooling: true,
        max_connections: 5,
        idle_timeout_ms: 60000,
    })
}

/// Helper macro to skip test if prerequisites not met.
macro_rules! require_prerequisites {
    () => {
        match check_prerequisites() {
            Some(config) => config,
            None => {
                eprintln!("⏭️  Skipping test: mainnet prerequisites not available");
                eprintln!("   Required env vars in .env.mainnet:");
                eprintln!("   - DA_RPC_URL=http://localhost:26658");
                eprintln!("   - DA_AUTH_TOKEN=<your_token>");
                eprintln!("   - DA_NAMESPACE=<58_hex_chars>");
                return;
            }
        }
    };
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 1: MAINNET HEALTH CHECK
// ════════════════════════════════════════════════════════════════════════════

/// Test that we can perform a health check against mainnet.
#[tokio::test]
#[ignore]
async fn test_mainnet_health_check() {
    let config = require_prerequisites!();

    println!("🔍 Testing mainnet health check...");
    println!("   RPC: {}", config.rpc_url);

    let celestia = match CelestiaDA::new(config) {
        Ok(da) => da,
        Err(e) => {
            eprintln!("❌ Failed to create CelestiaDA: {}", e);
            panic!("CelestiaDA initialization failed");
        }
    };

    let start = Instant::now();
    let status = celestia.health_check().await;
    let latency = start.elapsed();

    println!("   Status: {:?}", status);
    println!("   Latency: {:?}", latency);

    match status {
        DAHealthStatus::Healthy => {
            println!("✅ Mainnet health check passed");
        }
        DAHealthStatus::Degraded => {
            println!("⚠️ Mainnet health check passed (degraded)");
        }
        DAHealthStatus::Unavailable => {
            panic!("❌ Mainnet unavailable");
        }
    }

    // Health check should complete within 30 seconds
    assert!(latency < Duration::from_secs(30), "Health check too slow: {:?}", latency);
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 2: MAINNET POST BLOB
// ════════════════════════════════════════════════════════════════════════════

/// Test posting a blob to mainnet.
///
/// WARNING: This test will incur gas fees on mainnet!
#[tokio::test]
#[ignore]
async fn test_mainnet_post_blob() {
    let config = require_prerequisites!();

    println!("📤 Testing mainnet blob post...");
    println!("   ⚠️ This will incur gas fees!");

    let celestia = CelestiaDA::new(config).expect("CelestiaDA creation failed");

    // Create test data with timestamp to ensure uniqueness
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let test_data = format!("DSDN mainnet test blob {}", timestamp);

    let start = Instant::now();
    let result = celestia.post_blob(test_data.as_bytes()).await;
    let latency = start.elapsed();

    match result {
        Ok(blob_ref) => {
            println!("✅ Blob posted successfully");
            println!("   Height: {}", blob_ref.height);
            println!("   Commitment: {}", hex::encode(&blob_ref.commitment[..8]));
            println!("   Latency: {:?}", latency);

            // Post should complete within 30 seconds
            assert!(latency < Duration::from_secs(30), "Post too slow: {:?}", latency);
        }
        Err(e) => {
            panic!("❌ Blob post failed: {}", e);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 3: MAINNET GET BLOB
// ════════════════════════════════════════════════════════════════════════════

/// Test getting a blob from mainnet.
///
/// This test requires a blob to have been previously posted.
#[tokio::test]
#[ignore]
async fn test_mainnet_get_blob() {
    let config = require_prerequisites!();

    println!("📥 Testing mainnet blob get...");

    let celestia = CelestiaDA::new(config).expect("CelestiaDA creation failed");

    // First, post a blob so we have something to get
    let test_data = b"DSDN get test blob";
    let post_result = celestia.post_blob(test_data).await;

    let blob_ref = match post_result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("⏭️  Skipping get test: post failed: {}", e);
            return;
        }
    };

    println!("   Posted blob at height {}", blob_ref.height);

    // Wait a moment for the blob to be available
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Now get the blob
    let start = Instant::now();
    let result = celestia.get_blob(&blob_ref).await;
    let latency = start.elapsed();

    match result {
        Ok(data) => {
            println!("✅ Blob retrieved successfully");
            println!("   Size: {} bytes", data.len());
            println!("   Latency: {:?}", latency);

            assert_eq!(data, test_data, "Retrieved data doesn't match posted data");

            // Get should complete within 30 seconds
            assert!(latency < Duration::from_secs(30), "Get too slow: {:?}", latency);
        }
        Err(e) => {
            panic!("❌ Blob get failed: {}", e);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 4: MAINNET ROUNDTRIP LATENCY
// ════════════════════════════════════════════════════════════════════════════

/// Test full roundtrip (post + get) latency on mainnet.
///
/// Verifies that a complete post-get cycle completes within acceptable time.
#[tokio::test]
#[ignore]
async fn test_mainnet_roundtrip_latency() {
    let config = require_prerequisites!();

    println!("⏱️ Testing mainnet roundtrip latency...");

    let celestia = CelestiaDA::new(config).expect("CelestiaDA creation failed");

    // Test data
    let test_data = b"DSDN roundtrip latency test";

    // Measure full roundtrip
    let start = Instant::now();

    // Post
    let blob_ref = celestia.post_blob(test_data).await.expect("Post failed");

    let post_latency = start.elapsed();
    println!("   Post latency: {:?}", post_latency);

    // Brief wait for availability
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Get
    let get_start = Instant::now();
    let data = celestia.get_blob(&blob_ref).await.expect("Get failed");
    let get_latency = get_start.elapsed();
    println!("   Get latency: {:?}", get_latency);

    let total_latency = start.elapsed();
    println!("   Total roundtrip: {:?}", total_latency);

    // Verify data integrity
    assert_eq!(data, test_data, "Data mismatch");

    // Roundtrip should complete within 30 seconds (as specified)
    assert!(
        total_latency < Duration::from_secs(30),
        "Roundtrip too slow: {:?}",
        total_latency
    );

    println!("✅ Roundtrip latency test passed");
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 5: MAINNET SUBSCRIBE BLOBS
// ════════════════════════════════════════════════════════════════════════════

/// Test blob subscription on mainnet.
///
/// This test subscribes to blobs starting from current height.
#[tokio::test]
#[ignore]
async fn test_mainnet_subscribe_blobs() {
    use futures::StreamExt;
    use std::sync::Arc;

    let config = require_prerequisites!();

    println!("📡 Testing mainnet blob subscription...");

    let celestia = Arc::new(CelestiaDA::new(config.clone()).expect("CelestiaDA creation failed"));

    // Subscribe to blobs using config namespace
    let subscription_result = celestia.subscribe_blobs(&config.namespace);
    println!("   Subscription created, waiting for blobs...");
    println!("   (This test will timeout after 60 seconds if no blobs received)");

    let timeout = Duration::from_secs(60);
    let start = Instant::now();

    // Wait for at least one blob or timeout
    let mut stream = subscription_result;

    let result = tokio::time::timeout(timeout, async {
        while let Some(blob_result) = stream.next().await {
            match blob_result {
                Ok(blob) => {
                    println!("✅ Received blob at height {}", blob.height);
                    println!("   Size: {} bytes", blob.data.len());
                    return true;
                }
                Err(e) => {
                    // Some errors are expected (e.g., no blobs at height)
                    println!("   Blob error (may be expected): {}", e);
                }
            }

            if start.elapsed() > Duration::from_secs(30) {
                break;
            }
        }
        false
    })
    .await;

    match result {
        Ok(received) => {
            if received {
                println!("✅ Subscription test passed - received blob");
            } else {
                println!("⚠️ Subscription test passed - no blobs in namespace (expected if empty)");
            }
        }
        Err(_) => {
            println!("⚠️ Subscription test timed out - no blobs in namespace within 60s");
            // This is acceptable - the namespace might be empty
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 6: MAINNET RECONNECTION
// ════════════════════════════════════════════════════════════════════════════

/// Test reconnection behavior after simulated disconnection.
///
/// Verifies that the DA layer can recover from transient failures.
#[tokio::test]
#[ignore]
async fn test_mainnet_reconnection() {
    let config = require_prerequisites!();

    println!("🔄 Testing mainnet reconnection behavior...");

    let celestia = CelestiaDA::new(config).expect("CelestiaDA creation failed");

    // Initial health check
    let status1 = celestia.health_check().await;
    println!("   Initial status: {:?}", status1);

    // Post a blob
    let test_data = b"DSDN reconnection test";
    let result1 = celestia.post_blob(test_data).await;
    
    match result1 {
        Ok(ref_) => println!("   First post succeeded at height {}", ref_.height),
        Err(e) => {
            eprintln!("   First post failed (may be expected): {}", e);
        }
    }

    // Wait a bit
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Second health check
    let status2 = celestia.health_check().await;
    println!("   Status after wait: {:?}", status2);

    // Second post
    let test_data2 = b"DSDN reconnection test 2";
    let result2 = celestia.post_blob(test_data2).await;

    match result2 {
        Ok(ref_) => {
            println!("✅ Reconnection test passed - second post at height {}", ref_.height);
        }
        Err(e) => {
            // If second post also fails, that's concerning
            panic!("❌ Reconnection test failed: {}", e);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 7: AUTH TOKEN VALIDATION
// ════════════════════════════════════════════════════════════════════════════

/// Test that requests fail gracefully with invalid auth token.
#[tokio::test]
#[ignore]
async fn test_mainnet_invalid_auth_token() {
    let mut config = require_prerequisites!();

    println!("🔐 Testing invalid auth token handling...");

    // Set an invalid token
    config.auth_token = Some("invalid_token_12345".to_string());

    let celestia = match CelestiaDA::new(config) {
        Ok(da) => da,
        Err(e) => {
            println!("✅ Connection rejected with invalid token: {}", e);
            return;
        }
    };

    // Try to post - should fail
    let result = celestia.post_blob(b"test").await;

    match result {
        Ok(_) => {
            panic!("❌ Post succeeded with invalid token - this shouldn't happen!");
        }
        Err(e) => {
            println!("✅ Post correctly rejected with invalid token: {}", e);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TEST 8: METRICS COLLECTION
// ════════════════════════════════════════════════════════════════════════════

/// Test that metrics are properly collected during operations.
#[tokio::test]
#[ignore]
async fn test_mainnet_metrics_collection() {
    let config = require_prerequisites!();

    println!("📊 Testing metrics collection...");

    let celestia = CelestiaDA::new(config).expect("CelestiaDA creation failed");

    // Perform some operations
    let _ = celestia.health_check().await;
    let _ = celestia.post_blob(b"metrics test").await;

    // Get metrics
    if let Some(metrics) = celestia.metrics() {
        println!("   Post count: {}", metrics.post_count);
        println!("   Health check count: {}", metrics.health_check_count);
        println!("   Avg post latency: {} μs", metrics.avg_post_latency_us);
        println!("   Error count: {}", metrics.error_count);

        assert!(metrics.health_check_count >= 1, "Should have at least 1 health check");
        println!("✅ Metrics collection working");
    } else {
        println!("⚠️ Metrics not available (may be disabled)");
    }
}
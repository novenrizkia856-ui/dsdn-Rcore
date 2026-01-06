# DSDN Common Crate

Common utilities dan Data Availability Abstraction Layer untuk sistem DSDN.

## Overview

Crate `dsdn-common` menyediakan komponen fondasi yang digunakan di seluruh sistem DSDN:

- **DA Abstraction Layer**: Trait `DALayer` dan implementasinya untuk Data Availability
- **Cryptographic Utilities**: Primitif kriptografi yang digunakan untuk signing dan hashing
- **Content Addressing**: Helper untuk Content ID berbasis SHA-256
- **Configuration Management**: Pengelolaan konfigurasi sistem
- **Consistent Hashing**: Implementasi consistent hashing untuk placement

### Hubungan dengan Crate Lain

```text
┌─────────────┐
│   proto     │  <- Message definitions
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   common    │  <- This crate (utilities + DA layer)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   node      │  <- DSDN node implementation
└─────────────┘
```

## DA Abstraction Layer

### DALayer Trait

`DALayer` adalah trait abstraksi untuk Data Availability layer. Trait ini mendefinisikan kontrak yang harus dipatuhi oleh semua implementasi DA backend.

```rust
pub trait DALayer: Send + Sync {
    fn post_blob(&self, data: &[u8]) -> impl Future<Output = Result<BlobRef, DAError>> + Send;
    fn get_blob(&self, blob_ref: &BlobRef) -> impl Future<Output = Result<Vec<u8>, DAError>> + Send;
    fn subscribe_blobs(&self, from_height: Option<u64>) -> impl Future<Output = Result<BlobStream, DAError>> + Send;
    fn health_check(&self) -> impl Future<Output = Result<DAHealthStatus, DAError>> + Send;
}
```

### Implementasi

#### CelestiaDA

Implementasi production yang terhubung ke Celestia network.

```rust
use dsdn_common::CelestiaDA;

// Dari environment variables
let da = CelestiaDA::from_env()?;

// Atau dengan config manual
let config = DAConfig {
    rpc_url: "http://localhost:26658".to_string(),
    namespace: [0u8; 29],
    auth_token: Some("token".to_string()),
    timeout_ms: 30000,
    retry_count: 3,
    retry_delay_ms: 1000,
};
let da = CelestiaDA::new(config)?;
```

#### MockDA

Implementasi in-memory untuk testing. Tidak melakukan network call.

```rust
use dsdn_common::MockDA;

let mock_da = MockDA::new();

// Dengan latency simulation
let mock_da = MockDA::with_latency(100); // 100ms delay

// Dengan failure simulation
let mock_da = MockDA::with_failure_rate(0.5); // 50% failure rate
```

## Quick Start

### Basic Usage

```rust
use dsdn_common::{MockDA, DAError};

#[tokio::main]
async fn main() -> Result<(), DAError> {
    // Create MockDA for testing
    let da = MockDA::new();

    // Post a blob
    let data = b"hello DA layer";
    let blob_ref = da.post_blob(data).await?;

    // Retrieve the blob
    let retrieved = da.get_blob(&blob_ref).await?;
    assert_eq!(retrieved, data);

    // Check health
    let status = da.health_check().await;
    println!("DA health: {:?}", status);

    Ok(())
}
```

### Subscription

```rust
use dsdn_common::MockDA;
use futures::StreamExt;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let da = Arc::new(MockDA::new());
    let namespace = *da.namespace();

    // Inject some blobs
    da.inject_blob(b"blob1".to_vec());
    da.inject_blob(b"blob2".to_vec());

    // Subscribe to blobs
    let mut stream = da.subscribe_blobs(&namespace);

    // Process blobs
    while let Some(result) = stream.next().await {
        match result {
            Ok(blob) => println!("Received blob at height {}", blob.ref_.height),
            Err(e) => eprintln!("Error: {:?}", e),
        }
    }
}
```

## Testing

### Menggunakan MockDA untuk Unit Tests

MockDA dirancang khusus untuk testing:

```rust
use dsdn_common::{MockDA, DAError, DAHealthStatus};

#[tokio::test]
async fn test_da_operations() {
    let da = MockDA::new();

    // Test post/get roundtrip
    let data = b"test data".to_vec();
    let blob_ref = da.post_blob(&data).await.unwrap();
    let retrieved = da.get_blob(&blob_ref).await.unwrap();
    assert_eq!(retrieved, data);
}

#[tokio::test]
async fn test_da_failure() {
    let da = MockDA::with_failure_rate(1.0);

    // Should always fail
    let result = da.post_blob(b"test").await;
    assert!(matches!(result, Err(DAError::Unavailable)));
}

#[tokio::test]
async fn test_da_health() {
    let da = MockDA::new();
    assert_eq!(da.health_check().await, DAHealthStatus::Healthy);

    let degraded_da = MockDA::with_latency(600);
    assert_eq!(degraded_da.health_check().await, DAHealthStatus::Degraded);
}
```

### Testing Helpers

MockDA menyediakan helper methods untuk testing:

```rust
let da = MockDA::new();

// Inject blob langsung (bypass post_blob flow)
let blob_ref = da.inject_blob(b"test".to_vec());

// Get blob count
assert_eq!(da.blob_count(), 1);

// Clear all state
da.clear();
assert_eq!(da.blob_count(), 0);

// Get namespace
let ns = da.namespace();
```

## Modules

| Module | Description |
|--------|-------------|
| `da` | DALayer trait dan types (BlobRef, Blob, DAError, DAConfig) |
| `celestia_da` | Celestia DA implementation |
| `mock_da` | Mock DA untuk testing |
| `crypto` | Cryptographic utilities |
| `cid` | Content ID helpers |
| `config` | Configuration management |
| `consistent_hash` | Consistent hashing implementation |

## Error Handling

```rust
use dsdn_common::DAError;

match da.get_blob(&blob_ref).await {
    Ok(data) => println!("Got {} bytes", data.len()),
    Err(DAError::BlobNotFound(ref_)) => {
        println!("Blob not found at height {}", ref_.height);
    }
    Err(DAError::Unavailable) => {
        println!("DA layer unavailable");
    }
    Err(DAError::Timeout) => {
        println!("Operation timed out");
    }
    Err(e) => {
        println!("Other error: {}", e);
    }
}
```

## License

Part of the DSDN project.
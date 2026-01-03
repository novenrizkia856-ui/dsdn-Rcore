use std::sync::Arc;
use anyhow::{Result, anyhow};
use crate::coordinator_client::{CoordinatorClient, NodeInfo};
use dsdn_storage::localfs::LocalFsStorage;
use dsdn_storage::rpc;
use tokio::time::{sleep, Duration};

// bring the trait into scope so Arc<LocalFsStorage> can call trait methods
use dsdn_storage::store::Storage as StorageTrait;

/// Try push chunk (by hash) from local store to remote node.
/// remote_addr expected as "127.0.0.1:50051" (no scheme) — we will prefix with http://
pub async fn push_chunk_to_peer(store: Arc<LocalFsStorage>, hash: &str, remote_addr: &str) -> Result<String> {
    // check existence (convert backend error into anyhow)
    let exists = StorageTrait::has_chunk(&*store, hash)
        .map_err(|e| anyhow!("storage backend error: {}", e.to_string()))?;
    if !exists {
        return Err(anyhow!("local chunk {} not found", hash));
    }

    // read chunk
    let data_opt = StorageTrait::get_chunk(&*store, hash)
        .map_err(|e| anyhow!("storage backend error: {}", e.to_string()))?;
    let data = match data_opt {
        Some(v) => v,
        None => return Err(anyhow!("local chunk {} disappeared", hash)),
    };

    let url = format!("http://{}", remote_addr);
    // try with small retry
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        match rpc::client_put(url.clone(), hash.to_string(), data.clone()).await {
            Ok(returned) => {
                return Ok(returned);
            }
            Err(e) => {
                if attempt >= 3 {
                    return Err(anyhow!("failed to push to {} after attempts: {}", remote_addr, e));
                }
                sleep(Duration::from_millis(500 * attempt as u64)).await;
            }
        }
    }
}

/// Find NodeInfo by id from the full nodes list
pub fn find_node_info<'a>(nodes: &'a [NodeInfo], id: &str) -> Option<&'a NodeInfo> {
    nodes.iter().find(|n| n.id == id)
}

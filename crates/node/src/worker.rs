use std::sync::Arc;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use anyhow::Result;
use crate::state::NodeState;
use crate::coordinator_client::CoordinatorClient;
use dsdn_storage::localfs::LocalFsStorage;
use crate::replicator::{push_chunk_to_peer, find_node_info};
use std::collections::HashSet;
use tracing::{info, warn, error};

/// Background worker that scans local objects and attempts to self-heal/replicate to reach RF.
pub struct Worker {
    pub store: Arc<LocalFsStorage>,
    pub state: Arc<NodeState>,
    pub coord: Arc<CoordinatorClient>,
    pub node_id: String,
    pub rf: usize,
    pub interval_secs: u64,
    shutdown: Arc<Notify>,
}

impl Worker {
    pub fn new(
        store: Arc<LocalFsStorage>,
        state: Arc<NodeState>,
        coord: Arc<CoordinatorClient>,
        node_id: String,
        rf: usize,
        interval_secs: u64,
        shutdown: Arc<Notify>,
    ) -> Self {
        Self {
            store,
            state,
            coord,
            node_id,
            rf,
            interval_secs,
            shutdown,
        }
    }

    pub fn start(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!("worker started: scanning every {}s", self.interval_secs);
            loop {
                tokio::select! {
                    _ = self.shutdown.notified() => {
                        info!("worker shutting down");
                        break;
                    }
                    _ = sleep(Duration::from_secs(self.interval_secs)) => {
                        if let Err(e) = self.run_once().await {
                            warn!("worker run failed: {}", e);
                        }
                    }
                }
            }
        })
    }

    async fn run_once(&self) -> Result<()> {
        // list local object hashes
        let local_hashes = self.state.list_local_object_hashes()?;
        info!("worker found {} local objects", local_hashes.len());

        // ensure registration & mark_healed for each local file
        for hash in &local_hashes {
            // attempt register object to coordinator
            let size = 0u64; // size unknown for now; coordinator accepts 0
            let _ = self.coord.register_object(hash, size).await;
            let _ = self.coord.mark_replica_healed(hash, &self.node_id).await;
        }

        // for each registered object (we can get from coordinator or from local)
        // check placement and current replicas, then push missing
        for hash in &local_hashes {
            // get target placement
            let placement = match self.coord.placement_for_hash(hash, self.rf).await {
                Ok(p) => p,
                Err(e) => {
                    warn!("placement error for {}: {}", hash, e);
                    continue;
                }
            };
            // get current metadata
            let meta = match self.coord.get_object(hash).await {
                Ok(Some(m)) => m,
                Ok(None) => {
                    // probably created via register_object above; continue
                    continue;
                }
                Err(e) => {
                    warn!("get_object error for {}: {}", hash, e);
                    continue;
                }
            };

            // determine missing nodes in placement
            let mut missing = vec![];
            let current_replicas: HashSet<_> = meta.replicas.iter().cloned().collect();
            for target in &placement {
                if !current_replicas.contains(target) {
                    missing.push(target.clone());
                }
            }

            if missing.is_empty() {
                info!("{} already satisfied RF ({}).", hash, placement.len());
                continue;
            }

            // list all nodes to map id->addr
            let all_nodes = match self.coord.list_nodes().await {
                Ok(n) => n,
                Err(e) => {
                    warn!("failed list_nodes: {}", e);
                    continue;
                }
            };

            // try to push to missing nodes
            for m in missing {
                // find peer addr
                if let Some(peer) = find_node_info(&all_nodes, &m) {
                    let peer_addr = &peer.addr;
                    info!("attempting push {} -> {} (addr {})", hash, m, peer_addr);
                    match push_chunk_to_peer(self.store.clone(), hash, peer_addr).await {
                        Ok(returned_hash) => {
                            info!("pushed {} -> {} returned {}", hash, m, returned_hash);
                            // mark healed in coordinator
                            if let Err(e) = self.coord.mark_replica_healed(hash, &m).await {
                                warn!("mark_replica_healed failed for {} on {}: {}", hash, m, e);
                            }
                        }
                        Err(e) => {
                            warn!("push to {} failed: {}", m, e);
                        }
                    }
                } else {
                    warn!("no info for node id {}", m);
                }
            }
        }

        Ok(())
    }
}

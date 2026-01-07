//! Coordinator library: in-memory registry, placement, scheduling, and DA consumption.
//!
//! This crate provides the core Coordinator functionality for DSDN:
//!
//! - **Node Registry**: Track registered storage nodes
//! - **Object Placement**: Consistent hashing for replica placement
//! - **Scheduling**: Score-based node selection for workloads
//! - **DA Consumer**: Event consumption from Data Availability layer

use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use serde::{Serialize, Deserialize};

use dsdn_common::consistent_hash::NodeDesc;

pub mod scheduler;
pub mod da_consumer;
pub mod state_machine;

pub use scheduler::{NodeStats, Workload, Scheduler};
pub use da_consumer::{DAConsumer, DADerivedState, ChunkMeta, ReplicaInfo};
pub use state_machine::{
    StateMachine, DAEvent, DAEventType, DAEventPayload, StateError, EventHandler,
    NodeRegisteredPayload, NodeUnregisteredPayload, ChunkDeclaredPayload, ChunkRemovedPayload,
    ReplicaAddedPayload, ReplicaRemovedPayload, ZoneAssignedPayload, ZoneUnassignedPayload,
};

/// Node info stored in coordinator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub zone: String,
    pub addr: String,
    pub capacity_gb: u64,
    pub meta: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub hash: String,
    pub size: u64,
    pub replicas: Vec<String>,
}

#[derive(Clone)]
pub struct Coordinator {
    nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    objects: Arc<RwLock<HashMap<String, ObjectMeta>>>,
    // per-node runtime statistics
    node_stats: Arc<RwLock<HashMap<String, NodeStats>>>,
    // scheduler instance (weights)
    scheduler: Arc<RwLock<Scheduler>>,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            objects: Arc::new(RwLock::new(HashMap::new())),
            node_stats: Arc::new(RwLock::new(HashMap::new())),
            scheduler: Arc::new(RwLock::new(Scheduler::default())),
        }
    }

    /// Register or update node info
    pub fn register_node(&self, info: NodeInfo) {
        self.nodes.write().insert(info.id.clone(), info);
    }

    /// Update node runtime stats (replace)
    pub fn update_node_stats(&self, node_id: &str, stats: NodeStats) {
        self.node_stats.write().insert(node_id.to_string(), stats);
    }

    /// Get node stats if any
    pub fn get_node_stats(&self, node_id: &str) -> Option<NodeStats> {
        self.node_stats.read().get(node_id).cloned()
    }

    /// List nodes
    pub fn list_nodes(&self) -> Vec<NodeInfo> {
        self.nodes.read().values().cloned().collect()
    }

    /// Register object metadata (initially no replicas)
    pub fn register_object(&self, hash: String, size: u64) {
        let mut objs = self.objects.write();
        objs.entry(hash.clone()).or_insert(ObjectMeta {
            hash,
            size,
            replicas: vec![],
        });
    }

    pub fn get_object(&self, hash: &str) -> Option<ObjectMeta> {
        self.objects.read().get(hash).cloned()
    }

    /// mark replica missing (remove node id from object's replica list)
    pub fn mark_replica_missing(&self, hash: &str, node_id: &str) {
        let mut objs = self.objects.write();
        if let Some(obj) = objs.get_mut(hash) {
            obj.replicas.retain(|nid| nid != node_id);
        }
    }

    /// mark replica healed (add node id if missing)
    pub fn mark_replica_healed(&self, hash: &str, node_id: &str) {
        let mut objs = self.objects.write();
        if let Some(obj) = objs.get_mut(hash) {
            if !obj.replicas.contains(&node_id.to_string()) {
                obj.replicas.push(node_id.to_string());
            }
        } else {
            // create if not exists
            objs.insert(hash.to_string(), ObjectMeta {
                hash: hash.to_string(),
                size: 0,
                replicas: vec![node_id.to_string()],
            });
        }
    }

    /// Placement: choose up to rf node ids for given object hash, prefer distinct zones, based on consistent hashing.
    pub fn placement_for_hash(&self, hash: &str, rf: usize) -> Vec<String> {
        let nodes = self.list_nodes();
        if nodes.is_empty() {
            return vec![];
        }
        let descs: Vec<NodeDesc> = nodes.into_iter().map(|n| NodeDesc {
            id: n.id,
            zone: n.zone,
            weight: (n.capacity_gb.max(1) as u32),
        }).collect();
        let sel = dsdn_common::consistent_hash::select_nodes(&descs, hash, rf);
        sel
    }

    /// Scheduling: pick best node id for given workload.
    /// Returns None if no node meets soft requirements.
    pub fn schedule(&self, workload: &Workload) -> Option<String> {
        let nodes = self.list_nodes();
        if nodes.is_empty() { return None; }
        let stats_map = self.node_stats.read();
        let scheduler = self.scheduler.read().clone();
        // iterate nodes, compute score only for nodes that meet requirements
        let mut best: Option<(String, f64)> = None;
        for n in nodes {
            let stats = stats_map.get(&n.id).cloned().unwrap_or_default();
            if !scheduler.meets(&stats, workload) {
                continue;
            }
            let score = scheduler.score(&stats);
            match &best {
                None => best = Some((n.id.clone(), score)),
                Some((best_id, best_score)) => {
                    if score > *best_score {
                        best = Some((n.id.clone(), score));
                    } else if (score - *best_score).abs() < 1e-9 {
                        // tie-breaker deterministic: pick lexicographically smaller id
                        if n.id < *best_id {
                            best = Some((n.id.clone(), score));
                        }
                    }
                }
            }
        }
        best.map(|(id, _)| id)
    }

    /// set scheduler weights (optional)
    pub fn set_scheduler(&self, s: Scheduler) {
        *self.scheduler.write() = s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_list() {
        let c = Coordinator::new();
        let n = NodeInfo {
            id: "node1".into(),
            zone: "z1".into(),
            addr: "127.0.0.1:7001".into(),
            capacity_gb: 10,
            meta: serde_json::json!({}),
        };
        c.register_node(n.clone());
        let nodes = c.list_nodes();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "node1");
    }

    #[test]
    fn test_placement_three_zones() {
        let c = Coordinator::new();
        // Register 5 nodes in zones a,b,c
        c.register_node(NodeInfo { id: "n1".into(), zone: "a".into(), addr: "a:1".into(), capacity_gb: 10, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "n2".into(), zone: "b".into(), addr: "b:1".into(), capacity_gb: 10, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "n3".into(), zone: "c".into(), addr: "c:1".into(), capacity_gb: 10, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "n4".into(), zone: "a".into(), addr: "a:2".into(), capacity_gb: 10, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "n5".into(), zone: "b".into(), addr: "b:2".into(), capacity_gb: 10, meta: serde_json::json!({}) });

        let selection = c.placement_for_hash("some-object-hash", 3);
        // expect up to 3 nodes, ideally 3 distinct zones
        assert!(selection.len() <= 3);
        let mut zones = std::collections::HashSet::new();
        for id in &selection {
            let node = c.list_nodes().into_iter().find(|n| &n.id == id).unwrap();
            zones.insert(node.zone);
        }
        assert_eq!(zones.len(), selection.len()); // distinct zones
    }

    #[test]
    fn test_scheduler_simple_choice() {
        let c = Coordinator::new();
        // register nodes
        c.register_node(NodeInfo { id: "a".into(), zone: "z1".into(), addr: "a:1".into(), capacity_gb: 100, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "b".into(), zone: "z1".into(), addr: "b:1".into(), capacity_gb: 100, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "c".into(), zone: "z1".into(), addr: "c:1".into(), capacity_gb: 100, meta: serde_json::json!({}) });

        // set stats so that 'b' is best
        c.update_node_stats("a", NodeStats { cpu_free: 0.2, ram_free_mb: 2000.0, gpu_free: 0.0, latency_ms: 10.0, io_pressure: 0.3 });
        c.update_node_stats("b", NodeStats { cpu_free: 0.9, ram_free_mb: 4000.0, gpu_free: 1.0, latency_ms: 5.0, io_pressure: 0.05 });
        c.update_node_stats("c", NodeStats { cpu_free: 0.5, ram_free_mb: 1000.0, gpu_free: 0.0, latency_ms: 20.0, io_pressure: 0.1 });

        let wl = Workload { cpu_req: Some(0.1), ram_req_mb: Some(512.0), gpu_req: None, max_latency_ms: None, io_tolerance: None };
        let chosen = c.schedule(&wl).expect("should pick a node");
        assert_eq!(chosen, "b");
    }

    #[test]
    fn test_scheduler_requirement_filtering() {
        let c = Coordinator::new();
        c.register_node(NodeInfo { id: "n1".into(), zone: "z1".into(), addr: "a:1".into(), capacity_gb: 10, meta: serde_json::json!({}) });
        c.register_node(NodeInfo { id: "n2".into(), zone: "z1".into(), addr: "b:1".into(), capacity_gb: 10, meta: serde_json::json!({}) });

        c.update_node_stats("n1", NodeStats { cpu_free: 0.9, ram_free_mb: 1024.0, gpu_free: 0.0, latency_ms: 2.0, io_pressure: 0.0 });
        c.update_node_stats("n2", NodeStats { cpu_free: 0.9, ram_free_mb: 256.0, gpu_free: 0.0, latency_ms: 2.0, io_pressure: 0.0 });

        // workload requires at least 512 MB - only n1 qualifies
        let wl = Workload { cpu_req: None, ram_req_mb: Some(512.0), gpu_req: None, max_latency_ms: None, io_tolerance: None };
        let chosen = c.schedule(&wl).expect("should pick n1");
        assert_eq!(chosen, "n1");
    }
}
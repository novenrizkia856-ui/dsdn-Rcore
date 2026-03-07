use anyhow::Result;
use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════
// NODE STATUS TYPES (derived from DA events)
// ════════════════════════════════════════════════════════════════════════════

/// Node status derived from DA events.
/// All fields are computed from DA events only - NO RPC to node/coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatusFromDA {
    /// Node ID (from NodeRegistered event).
    pub node_id: String,
    /// Registration status: "registered" or "unregistered".
    pub registration_status: String,
    /// Node address (from NodeRegistered event).
    pub addr: String,
    /// Zone assignment (from NodeRegistered event, may be None).
    pub zone: Option<String>,
    /// Whether node is active (registered and not unregistered).
    pub is_active: bool,
    /// Number of chunks assigned (count of ReplicaAdded - ReplicaRemoved).
    pub chunk_count: usize,
    /// Number of replicas this node holds (same as chunk_count for single-replica model).
    pub replica_count: usize,
    /// DA height when this status was derived.
    pub da_height: u64,
}

impl NodeStatusFromDA {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌─────────────────────────────────────────────────────────────────┐\n");
        output.push_str("│                    NODE STATUS (from DA)                        │\n");
        output.push_str("├─────────────────────┬───────────────────────────────────────────┤\n");
        output.push_str(&format!("│ Node ID             │ {:41} │\n", truncate_str(&self.node_id, 41)));
        output.push_str(&format!("│ Registration        │ {:41} │\n", self.registration_status));
        output.push_str(&format!("│ Address             │ {:41} │\n", truncate_str(&self.addr, 41)));
        output.push_str(&format!("│ Zone                │ {:41} │\n", self.zone.as_deref().unwrap_or("(none)")));
        output.push_str(&format!("│ Active              │ {:41} │\n", if self.is_active { "yes" } else { "no" }));
        output.push_str(&format!("│ Chunk Count         │ {:41} │\n", self.chunk_count));
        output.push_str(&format!("│ Replica Count       │ {:41} │\n", self.replica_count));
        output.push_str(&format!("│ DA Height           │ {:41} │\n", self.da_height));
        output.push_str("├─────────────────────┴───────────────────────────────────────────┤\n");
        output.push_str("│ Note: All data derived from DA events only                      │\n");
        output.push_str("└─────────────────────────────────────────────────────────────────┘\n");
        output
    }

    /// Format as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize node status: {}", e))
    }
}

/// Node list entry for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeListEntry {
    pub node_id: String,
    pub addr: String,
    pub zone: Option<String>,
    pub is_active: bool,
    pub chunk_count: usize,
}

/// Node list result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeListFromDA {
    /// List of nodes (sorted by node_id for determinism).
    pub nodes: Vec<NodeListEntry>,
    /// Total count.
    pub total: usize,
    /// Count of active nodes.
    pub active_count: usize,
    /// DA height when this list was derived.
    pub da_height: u64,
}

impl NodeListFromDA {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌──────────────────────────┬──────────────────────┬────────────┬────────┬────────┐\n");
        output.push_str("│ Node ID                  │ Address              │ Zone       │ Active │ Chunks │\n");
        output.push_str("├──────────────────────────┼──────────────────────┼────────────┼────────┼────────┤\n");
        
        if self.nodes.is_empty() {
            output.push_str("│                          No nodes found in DA events                          │\n");
        } else {
            for node in &self.nodes {
                output.push_str(&format!(
                    "│ {:24} │ {:20} │ {:10} │ {:6} │ {:>6} │\n",
                    truncate_str(&node.node_id, 24),
                    truncate_str(&node.addr, 20),
                    truncate_str(node.zone.as_deref().unwrap_or("-"), 10),
                    if node.is_active { "yes" } else { "no" },
                    node.chunk_count
                ));
            }
        }
        
        output.push_str("├──────────────────────────┴──────────────────────┴────────────┴────────┴────────┤\n");
        output.push_str(&format!("│ Total: {} | Active: {} | DA Height: {:>10}                            │\n",
            self.total, self.active_count, self.da_height));
        output.push_str("└─────────────────────────────────────────────────────────────────────────────────┘\n");
        output
    }

    /// Format as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize node list: {}", e))
    }
}

/// Chunk assignment entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkAssignment {
    pub chunk_hash: String,
    pub size: u64,
    pub owner: String,
}

/// Node chunks result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeChunksFromDA {
    pub node_id: String,
    /// Chunks assigned to this node (sorted by chunk_hash for determinism).
    pub chunks: Vec<ChunkAssignment>,
    /// Total count.
    pub total: usize,
    /// Total size in bytes.
    pub total_size: u64,
    /// DA height when this was derived.
    pub da_height: u64,
}

impl NodeChunksFromDA {
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Chunks assigned to node: {}\n", self.node_id));
        output.push_str("┌────────────────────────────────────────────────────────────────┬────────────┬──────────────────────┐\n");
        output.push_str("│ Chunk Hash                                                     │       Size │ Owner                │\n");
        output.push_str("├────────────────────────────────────────────────────────────────┼────────────┼──────────────────────┤\n");
        
        if self.chunks.is_empty() {
            output.push_str("│                              No chunks assigned                                                  │\n");
        } else {
            for chunk in &self.chunks {
                output.push_str(&format!(
                    "│ {:62} │ {:>10} │ {:20} │\n",
                    truncate_str(&chunk.chunk_hash, 62),
                    chunk.size,
                    truncate_str(&chunk.owner, 20)
                ));
            }
        }
        
        output.push_str("├────────────────────────────────────────────────────────────────┴────────────┴──────────────────────┤\n");
        output.push_str(&format!("│ Total: {} chunks | Size: {} bytes | DA Height: {:>10}                                   │\n",
            self.total, self.total_size, self.da_height));
        output.push_str("└─────────────────────────────────────────────────────────────────────────────────────────────────────┘\n");
        output
    }

    /// Format as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize node chunks: {}", e))
    }
}

/// Truncate string with ellipsis.
pub(crate) fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}
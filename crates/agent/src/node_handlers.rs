use anyhow::Result;

use crate::cmd_da;
use crate::cmd_verify;
use crate::da_types::{
    NodeStatusFromDA, NodeListEntry, NodeListFromDA,
    ChunkAssignment, NodeChunksFromDA,
};

// ════════════════════════════════════════════════════════════════════════════
// NODE COMMAND HANDLERS (all data from DA events)
// ════════════════════════════════════════════════════════════════════════════

/// Validate node_id is not empty.
pub(crate) fn validate_node_id(node_id: &str) -> Result<()> {
    if node_id.is_empty() {
        anyhow::bail!("node_id cannot be empty");
    }
    if node_id.len() > 256 {
        anyhow::bail!("node_id too long (max 256 characters)");
    }
    Ok(())
}

/// Handle `agent node status <node_id>` command.
/// ALL data is derived from DA events only - NO RPC to node or coordinator.
pub(crate) async fn handle_node_status(node_id: &str, json_output: bool) -> Result<()> {
    // Validate input
    validate_node_id(node_id)?;

    // Rebuild state from DA events only
    let config = cmd_da::DAConfig::from_env();
    let state = cmd_verify::rebuild_state_from_da(&config).await?;

    // Find node in DA-derived state
    let node_info = state.nodes.get(node_id);

    match node_info {
        Some(info) => {
            // Count chunks assigned to this node (from ReplicaAdded events)
            let chunk_count = state.chunks.values()
                .filter(|c| c.replicas.contains(&node_id.to_string()))
                .count();

            let status = NodeStatusFromDA {
                node_id: node_id.to_string(),
                registration_status: if info.active { "registered".to_string() } else { "unregistered".to_string() },
                addr: info.addr.clone(),
                zone: info.zone.clone(),
                is_active: info.active,
                chunk_count,
                replica_count: chunk_count, // In current model, 1 replica per assignment
                da_height: state.last_height,
            };

            if json_output {
                println!("{}", status.to_json()?);
            } else {
                print!("{}", status.to_table());
            }
        }
        None => {
            anyhow::bail!(
                "node '{}' not found in DA events. Searched {} registered nodes at DA height {}.",
                node_id,
                state.nodes.len(),
                state.last_height
            );
        }
    }

    Ok(())
}

/// Handle `agent node list` command.
/// ALL data is derived from DA events only - NO RPC to node or coordinator.
pub(crate) async fn handle_node_list(json_output: bool) -> Result<()> {
    // Rebuild state from DA events only
    let config = cmd_da::DAConfig::from_env();
    let state = cmd_verify::rebuild_state_from_da(&config).await?;

    // Build list from DA-derived state
    let mut nodes: Vec<NodeListEntry> = state.nodes.values()
        .map(|info| {
            let chunk_count = state.chunks.values()
                .filter(|c| c.replicas.contains(&info.node_id))
                .count();

            NodeListEntry {
                node_id: info.node_id.clone(),
                addr: info.addr.clone(),
                zone: info.zone.clone(),
                is_active: info.active,
                chunk_count,
            }
        })
        .collect();

    // Sort by node_id for deterministic output
    nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));

    let active_count = nodes.iter().filter(|n| n.is_active).count();

    let result = NodeListFromDA {
        total: nodes.len(),
        active_count,
        nodes,
        da_height: state.last_height,
    };

    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_table());
    }

    Ok(())
}

/// Handle `agent node chunks <node_id>` command.
/// ALL data is derived from DA events only - NO RPC to node or coordinator.
pub(crate) async fn handle_node_chunks(node_id: &str, json_output: bool) -> Result<()> {
    // Validate input
    validate_node_id(node_id)?;

    // Rebuild state from DA events only
    let config = cmd_da::DAConfig::from_env();
    let state = cmd_verify::rebuild_state_from_da(&config).await?;

    // Verify node exists in DA
    if !state.nodes.contains_key(node_id) {
        anyhow::bail!(
            "node '{}' not found in DA events. Cannot list chunks for unknown node.",
            node_id
        );
    }

    // Find chunks assigned to this node (from ReplicaAdded/ReplicaRemoved events)
    let mut chunks: Vec<ChunkAssignment> = state.chunks.values()
        .filter(|c| c.replicas.contains(&node_id.to_string()))
        .map(|c| ChunkAssignment {
            chunk_hash: c.chunk_hash.clone(),
            size: c.size,
            owner: c.owner.clone(),
        })
        .collect();

    // Sort by chunk_hash for deterministic output
    chunks.sort_by(|a, b| a.chunk_hash.cmp(&b.chunk_hash));

    let total_size: u64 = chunks.iter().map(|c| c.size).sum();

    let result = NodeChunksFromDA {
        node_id: node_id.to_string(),
        total: chunks.len(),
        total_size,
        chunks,
        da_height: state.last_height,
    };

    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_table());
    }

    Ok(())
}
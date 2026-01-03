//! Simple consistent hashing with virtual nodes and zone-awareness.
//! The select_nodes function chooses up to `rf` node ids from the provided
//! node list preferring distinct zones when possible.

use std::collections::BTreeMap;

/// Node descriptor used as input to select_nodes
#[derive(Clone, Debug)]
pub struct NodeDesc {
    pub id: String,
    pub zone: String,
    pub weight: u32, // used to create virtual nodes
}

/// FNV-ish u64 from bytes (we'll use sha256 then pick first 8 bytes or simple fold)
fn u64_from_bytes(b: &[u8]) -> u64 {
    use std::convert::TryInto;
    if b.len() >= 8 {
        let arr: [u8; 8] = b[0..8].try_into().unwrap();
        u64::from_be_bytes(arr)
    } else {
        // fallback pad
        let mut tmp = [0u8; 8];
        for (i, v) in b.iter().enumerate() {
            tmp[i] = *v;
        }
        u64::from_be_bytes(tmp)
    }
}

/// Build a ring: mapping from vnode hash -> node index
/// vnode_count is base number of virtual nodes per weight unit (default 100).
fn build_ring(nodes: &[NodeDesc], vnode_count: u32) -> BTreeMap<u64, usize> {
    use sha2::{Digest, Sha256};
    let mut ring = BTreeMap::new();
    for (idx, n) in nodes.iter().enumerate() {
        let weight = n.weight.max(1);
        let vnodes = vnode_count.saturating_mul(weight);
        for v in 0..vnodes {
            let mut hasher = Sha256::new();
            hasher.update(n.id.as_bytes());
            hasher.update(b":");
            hasher.update(v.to_string().as_bytes());
            let sum = hasher.finalize();
            let key = u64_from_bytes(&sum);
            // if collision happens, BTreeMap will keep both different keys; collisions extremely unlikely
            ring.insert(key, idx);
        }
    }
    ring
}

/// Select up to rf nodes for a given key (hex string or arbitrary). Try to ensure distinct zones.
/// returns vector of node ids in selection order (length <= rf)
pub fn select_nodes(nodes: &[NodeDesc], key: &str, rf: usize) -> Vec<String> {
    use sha2::{Digest, Sha256};

    if nodes.is_empty() || rf == 0 {
        return vec![];
    }

    // build ring with 64 vnodes default per weight unit (reasonable small for dev)
    let ring = build_ring(nodes, 64);

    // compute key u64
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let sum = hasher.finalize();
    let key_u64 = u64_from_bytes(&sum);

    // iterate ring starting from first >= key_u64, wrap around if needed
    let mut selected: Vec<String> = Vec::new();
    let mut selected_zones = std::collections::HashSet::new();

    // We will iterate over ring entries starting from lower_bound(key_u64).
    // To easily iterate we collect keys in Vec
    let keys: Vec<u64> = ring.keys().cloned().collect();
    if keys.is_empty() {
        return vec![];
    }
    // find start index
    let mut idx = match keys.binary_search(&key_u64) {
        Ok(i) => i,
        Err(i) => {
            if i >= keys.len() { 0 } else { i }
        }
    };

    // iterate up to ring.len() times, selecting nodes, prefer different zones
    let mut attempts = 0;
    while selected.len() < rf && attempts < keys.len() {
        let k = keys[idx];
        let node_idx = ring[&k];
        let node = &nodes[node_idx];
        // try to prefer new zone — if zone new or still not enough choices, accept
        if !selected_zones.contains(&node.zone) {
            selected.push(node.id.clone());
            selected_zones.insert(node.zone.clone());
        } else {
            // if we already have selected nodes from rf distinct zones but still need fill (rare),
            // permit same-zone selection later; but here we only add same-zone if not enough unique zones.
            if selected.len() + (keys.len() - attempts) <= rf {
                // forced accept to fill remaining slots
                selected.push(node.id.clone());
            } else {
                // skip for now (try to find different zone)
            }
        }

        attempts += 1;
        idx += 1;
        if idx >= keys.len() {
            idx = 0;
        }
    }

    // If we didn't reach rf (e.g., too few nodes / zones), fill with distinct node ids ignoring zones
    if selected.len() < rf {
        // iterate nodes and add until reach rf, avoid duplicates
        for n in nodes {
            if selected.len() >= rf { break; }
            if !selected.contains(&n.id) {
                selected.push(n.id.clone());
            }
        }
    }

    selected.truncate(rf);
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_nodes_basic() {
        let nodes = vec![
            NodeDesc { id: "n1".into(), zone: "a".into(), weight: 1 },
            NodeDesc { id: "n2".into(), zone: "b".into(), weight: 1 },
            NodeDesc { id: "n3".into(), zone: "c".into(), weight: 1 },
            NodeDesc { id: "n4".into(), zone: "a".into(), weight: 1 },
            NodeDesc { id: "n5".into(), zone: "b".into(), weight: 1 },
        ];

        let sel = select_nodes(&nodes, "object-123", 3);
        // Expect up to 3 nodes; prefer different zones
        assert!(sel.len() <= 3);
        let zones: std::collections::HashSet<_> = sel.iter().map(|id| {
            nodes.iter().find(|n| n.id == *id).unwrap().zone.clone()
        }).collect();
        // ideally distinct zones count == sel.len()
        assert_eq!(zones.len(), sel.len());
    }
}

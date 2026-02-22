//! # Peer Store (peers.dat)
//!
//! Persistent peer cache agar node bisa bootstrap cepat tanpa DNS resolve.
//! Format: JSON (debug-friendly, bisa diedit manual saat troubleshoot).
//!
//! ## Atomic Write
//!
//! Write selalu ke temp file dulu, lalu rename. Ini mencegah corruption
//! jika node crash di tengah write.
//!
//! ## Garbage Collection
//!
//! - Entries tidak terlihat > 30 hari → otomatis dihapus
//! - Entries suspicious (10x fail berturut) → prioritas rendah
//! - Max 10.000 entries (overflow → hapus yang score terendah)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::net::SocketAddr;

use super::types::{PeerEntry, PeerStatus, PeerSource, current_unix_time};
use super::identity::NetworkId;
use super::scoring::PeerScorer;
use super::config::ConnectionLimits;

// ════════════════════════════════════════════════════════════════════════════
// PEER STORE
// ════════════════════════════════════════════════════════════════════════════

/// Persistent peer cache.
///
/// Menyimpan semua known peers ke disk (peers.dat).
/// Di-load saat startup sebagai sumber pertama bootstrap.
pub struct PeerStore {
    /// All known peers, keyed by "IP:Port"
    peers: HashMap<String, PeerEntry>,
    /// Path ke file peers.dat
    file_path: PathBuf,
    /// Network ID untuk filtering
    network_id: NetworkId,
    /// Limits
    limits: ConnectionLimits,
    /// Dirty flag — true jika ada perubahan sejak last save
    dirty: bool,
}

impl PeerStore {
    /// Buat PeerStore baru.
    ///
    /// Tidak otomatis load dari disk — panggil `load()` setelah construct.
    pub fn new(file_path: &str, network_id: NetworkId, limits: ConnectionLimits) -> Self {
        Self {
            peers: HashMap::new(),
            file_path: PathBuf::from(file_path),
            network_id,
            limits,
            dirty: false,
        }
    }

    /// Load peers dari disk (peers.dat).
    ///
    /// Jika file tidak ada → OK, mulai dengan store kosong.
    /// Jika file corrupt → log warning, mulai dengan store kosong.
    pub fn load(&mut self) -> Result<usize, anyhow::Error> {
        if !self.file_path.exists() {
            println!("   ℹ peers.dat not found, starting with empty store");
            return Ok(0);
        }

        let content = match std::fs::read_to_string(&self.file_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("   ⚠️ Failed to read peers.dat: {} — starting fresh", e);
                return Ok(0);
            }
        };

        let entries: Vec<PeerEntry> = match serde_json::from_str(&content) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("   ⚠️ Failed to parse peers.dat: {} — starting fresh", e);
                return Ok(0);
            }
        };

        let mut loaded = 0;
        for entry in entries {
            // Filter: hanya load peer dari network yang sama
            if entry.network_id == self.network_id {
                self.peers.insert(entry.store_key(), entry);
                loaded += 1;
            }
        }

        println!("   ✓ Loaded {} peers from peers.dat", loaded);
        Ok(loaded)
    }

    /// Save peers ke disk (atomic write).
    ///
    /// 1. Write ke temp file (peers.dat.tmp)
    /// 2. Rename temp → peers.dat
    /// 3. Ini atomic di sebagian besar OS/filesystem
    pub fn save(&mut self) -> Result<(), anyhow::Error> {
        if !self.dirty {
            return Ok(());
        }

        let entries: Vec<&PeerEntry> = self.peers.values().collect();
        let json = serde_json::to_string_pretty(&entries)?;

        let tmp_path = self.file_path.with_extension("dat.tmp");

        // Write ke temp
        std::fs::write(&tmp_path, &json)?;

        // Atomic rename
        std::fs::rename(&tmp_path, &self.file_path)?;

        self.dirty = false;
        Ok(())
    }

    /// Insert atau update peer.
    ///
    /// Jika peer sudah ada, update metadata yang berubah.
    /// Jika peer baru, insert dan enforce max entries.
    pub fn upsert(&mut self, mut entry: PeerEntry) {
        let key = entry.store_key();

        // Jika sudah ada, merge metadata
        if let Some(existing) = self.peers.get(&key) {
            // Preserve historical counters
            entry.first_seen = existing.first_seen;
            if existing.success_count > entry.success_count {
                entry.success_count = existing.success_count;
            }
            if existing.failure_count > entry.failure_count {
                entry.failure_count = existing.failure_count;
            }
        }

        // Recompute score
        PeerScorer::update_score(&mut entry);

        self.peers.insert(key, entry);
        self.dirty = true;

        // Enforce max entries
        self.enforce_max_entries();
    }

    /// Remove peer by address string.
    pub fn remove(&mut self, addr_key: &str) -> Option<PeerEntry> {
        self.dirty = true;
        self.peers.remove(addr_key)
    }

    /// Get peer by address string.
    pub fn get(&self, addr_key: &str) -> Option<&PeerEntry> {
        self.peers.get(addr_key)
    }

    /// Get mutable peer by address string.
    pub fn get_mut(&mut self, addr_key: &str) -> Option<&mut PeerEntry> {
        self.dirty = true;
        self.peers.get_mut(addr_key)
    }

    /// Get all peers sorted by score descending (best first).
    pub fn get_all_sorted(&self) -> Vec<&PeerEntry> {
        let mut entries: Vec<&PeerEntry> = self.peers.values().collect();
        entries.sort_by(|a, b| b.score.cmp(&a.score));
        entries
    }

    /// Get connectable peers (not banned, not currently connected).
    pub fn get_connectable(&self) -> Vec<&PeerEntry> {
        let mut entries: Vec<&PeerEntry> = self.peers.values()
            .filter(|p| !p.is_banned())
            .filter(|p| !matches!(p.status, PeerStatus::Connected))
            .collect();
        entries.sort_by(|a, b| b.score.cmp(&a.score));
        entries
    }

    /// Get connected peers.
    pub fn get_connected(&self) -> Vec<&PeerEntry> {
        self.peers.values()
            .filter(|p| matches!(p.status, PeerStatus::Connected))
            .collect()
    }

    /// Get peers by service type.
    pub fn get_by_service_type(&self, service_type: super::types::ServiceType) -> Vec<&PeerEntry> {
        self.peers.values()
            .filter(|p| p.service_type == service_type)
            .collect()
    }

    /// Count total peers.
    pub fn count(&self) -> usize {
        self.peers.len()
    }

    /// Count connected peers.
    pub fn count_connected(&self) -> usize {
        self.peers.values()
            .filter(|p| matches!(p.status, PeerStatus::Connected))
            .count()
    }

    /// Check if address exists in store.
    pub fn contains(&self, addr_key: &str) -> bool {
        self.peers.contains_key(addr_key)
    }

    // ════════════════════════════════════════════════════════════════════════
    // GARBAGE COLLECTION
    // ════════════════════════════════════════════════════════════════════════

    /// Run garbage collection.
    ///
    /// Hapus:
    /// 1. Peer yang expired ban (unban)
    /// 2. Peer yang tidak terlihat > max_age
    /// 3. Enforce max entries (hapus yang score terendah)
    ///
    /// Returns jumlah entries yang dihapus.
    pub fn garbage_collect(&mut self) -> usize {
        let now = current_unix_time();
        let max_age = self.limits.peer_max_age_secs;
        let mut removed = 0;

        // Phase 1: Unban expired peers
        for peer in self.peers.values_mut() {
            if let PeerStatus::Banned { until } = peer.status {
                if now >= until {
                    peer.status = PeerStatus::Disconnected;
                }
            }
        }

        // Phase 2: Remove stale peers (not seen in max_age)
        let stale_keys: Vec<String> = self.peers.iter()
            .filter(|(_, p)| {
                p.last_seen > 0 && now.saturating_sub(p.last_seen) > max_age
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in stale_keys {
            self.peers.remove(&key);
            removed += 1;
        }

        // Phase 3: Enforce max entries
        removed += self.enforce_max_entries();

        if removed > 0 {
            self.dirty = true;
            println!("   🗑 GC: removed {} stale peers, {} remaining", removed, self.peers.len());
        }

        removed
    }

    /// Enforce max entries limit. Returns count of removed entries.
    fn enforce_max_entries(&mut self) -> usize {
        let max = self.limits.max_peer_store_entries as usize;
        if self.peers.len() <= max {
            return 0;
        }

        // Sort by score ascending (worst first)
        let mut scored: Vec<(String, i64)> = self.peers.iter()
            .map(|(k, p)| (k.clone(), p.score))
            .collect();
        scored.sort_by(|a, b| a.1.cmp(&b.1));

        // Remove worst until within limit
        let to_remove = self.peers.len() - max;
        let mut removed = 0;
        for (key, _) in scored.into_iter().take(to_remove) {
            // Never remove connected peers
            if let Some(peer) = self.peers.get(&key) {
                if matches!(peer.status, PeerStatus::Connected) {
                    continue;
                }
            }
            self.peers.remove(&key);
            removed += 1;
        }

        removed
    }

    /// Recompute scores for all peers.
    pub fn recompute_all_scores(&mut self) {
        for peer in self.peers.values_mut() {
            PeerScorer::update_score(peer);
        }
        self.dirty = true;
    }

    /// Get store stats for observability.
    pub fn stats(&self) -> PeerStoreStats {
        let mut stats = PeerStoreStats::default();
        stats.total = self.peers.len();

        for peer in self.peers.values() {
            match peer.status {
                PeerStatus::Connected => stats.connected += 1,
                PeerStatus::Disconnected => stats.disconnected += 1,
                PeerStatus::Discovered => stats.discovered += 1,
                PeerStatus::Connecting => stats.connecting += 1,
                PeerStatus::Banned { .. } => stats.banned += 1,
            }

            match peer.source {
                PeerSource::DnsSeed => stats.from_dns += 1,
                PeerSource::StaticConfig => stats.from_static += 1,
                PeerSource::PeerExchange => stats.from_pex += 1,
                PeerSource::Inbound => stats.from_inbound += 1,
                PeerSource::Manual => stats.from_manual += 1,
                PeerSource::PeerCache => stats.from_cache += 1,
            }
        }

        stats
    }
}

/// Statistics dari PeerStore untuk observability/monitoring.
#[derive(Debug, Clone, Default)]
pub struct PeerStoreStats {
    pub total: usize,
    pub connected: usize,
    pub disconnected: usize,
    pub discovered: usize,
    pub connecting: usize,
    pub banned: usize,
    pub from_dns: usize,
    pub from_static: usize,
    pub from_pex: usize,
    pub from_inbound: usize,
    pub from_manual: usize,
    pub from_cache: usize,
}

impl std::fmt::Display for PeerStoreStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Peers: {} total ({} connected, {} disconnected, {} banned) | \
             Sources: dns={} static={} pex={} inbound={} manual={} cache={}",
            self.total, self.connected, self.disconnected, self.banned,
            self.from_dns, self.from_static, self.from_pex,
            self.from_inbound, self.from_manual, self.from_cache,
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn make_store() -> PeerStore {
        let tmp = std::env::temp_dir().join("dsdn_test_peers.dat");
        PeerStore::new(
            tmp.to_str().unwrap(),
            NetworkId::Devnet,
            ConnectionLimits::default(),
        )
    }

    fn make_entry(ip: &str) -> PeerEntry {
        let addr = SocketAddr::from_str(ip).unwrap();
        PeerEntry::new(addr, NetworkId::Devnet, PeerSource::Manual)
    }

    #[test]
    fn test_store_upsert_and_get() {
        let mut store = make_store();
        let entry = make_entry("10.0.0.1:45831");
        store.upsert(entry.clone());

        assert_eq!(store.count(), 1);
        assert!(store.contains("10.0.0.1:45831"));
        assert!(store.get("10.0.0.1:45831").is_some());
    }

    #[test]
    fn test_store_upsert_merges_counters() {
        let mut store = make_store();

        let mut entry1 = make_entry("10.0.0.1:45831");
        entry1.success_count = 10;
        store.upsert(entry1);

        let mut entry2 = make_entry("10.0.0.1:45831");
        entry2.success_count = 5; // lower
        store.upsert(entry2);

        // Should preserve higher count
        let peer = store.get("10.0.0.1:45831").unwrap();
        assert_eq!(peer.success_count, 10);
    }

    #[test]
    fn test_store_remove() {
        let mut store = make_store();
        store.upsert(make_entry("10.0.0.1:45831"));
        assert_eq!(store.count(), 1);

        store.remove("10.0.0.1:45831");
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_store_get_connectable_excludes_banned() {
        let mut store = make_store();

        let mut good = make_entry("10.0.0.1:45831");
        good.status = PeerStatus::Disconnected;
        store.upsert(good);

        let mut banned = make_entry("10.0.0.2:45831");
        banned.ban(3600);
        store.upsert(banned);

        let connectable = store.get_connectable();
        assert_eq!(connectable.len(), 1);
        assert_eq!(connectable[0].addr.to_string(), "10.0.0.1:45831");
    }

    #[test]
    fn test_store_enforce_max_entries() {
        let limits = ConnectionLimits {
            max_peer_store_entries: 3,
            ..Default::default()
        };
        let mut store = PeerStore::new(
            std::env::temp_dir().join("dsdn_test_max.dat").to_str().unwrap(),
            NetworkId::Devnet, limits,
        );

        for i in 1..=5 {
            store.upsert(make_entry(&format!("10.0.0.{}:45831", i)));
        }

        // Should be capped at 3
        assert!(store.count() <= 3);
    }

    #[test]
    fn test_store_gc_removes_stale() {
        let limits = ConnectionLimits {
            peer_max_age_secs: 1, // 1 second for testing
            ..Default::default()
        };
        let mut store = PeerStore::new(
            std::env::temp_dir().join("dsdn_test_gc.dat").to_str().unwrap(),
            NetworkId::Devnet, limits,
        );

        let mut entry = make_entry("10.0.0.1:45831");
        entry.last_seen = 1; // very old
        store.upsert(entry);

        let removed = store.garbage_collect();
        assert_eq!(removed, 1);
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_store_save_load_roundtrip() {
        let tmp = std::env::temp_dir().join("dsdn_test_peers_roundtrip.dat");
        // Cleanup
        let _ = std::fs::remove_file(&tmp);

        let tmp_str = tmp.to_str().unwrap();
        let mut store1 = PeerStore::new(tmp_str, NetworkId::Devnet, ConnectionLimits::default());
        store1.upsert(make_entry("10.0.0.1:45831"));
        store1.upsert(make_entry("10.0.0.2:45831"));
        store1.save().unwrap();

        let mut store2 = PeerStore::new(tmp_str, NetworkId::Devnet, ConnectionLimits::default());
        let loaded = store2.load().unwrap();
        assert_eq!(loaded, 2);
        assert!(store2.contains("10.0.0.1:45831"));

        // Cleanup
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_store_stats() {
        let mut store = make_store();

        let mut p1 = make_entry("10.0.0.1:45831");
        p1.status = PeerStatus::Connected;
        p1.source = PeerSource::DnsSeed;
        store.upsert(p1);

        let mut p2 = make_entry("10.0.0.2:45831");
        p2.source = PeerSource::PeerExchange;
        store.upsert(p2);

        let stats = store.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.from_dns, 1);
        assert_eq!(stats.from_pex, 1);
    }
}
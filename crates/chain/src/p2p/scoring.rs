//! # Peer Scoring
//!
//! Algoritma scoring deterministik untuk peer selection.
//! Node memprioritaskan connect ke peer dengan score tertinggi.
//!
//! ## Formula (sesuai Tahap 21 v2)
//!
//! ```text
//! score = BASE_SCORE
//!       + (success_count * SUCCESS_WEIGHT)
//!       - (failure_count * FAILURE_WEIGHT)
//!       + recency_bonus
//!       - staleness_penalty
//!       + source_bonus
//!       + role_bonus          ← NEW: REQUIRED +20, OPTIONAL +5, SKIP +0
//!       + class_bonus         ← NEW: DataCenter +5 jika butuh kapasitas
//!       - suspicious_penalty
//! ```
//!
//! ## Role Bonus (NEW)
//!
//! Berdasarkan RoleDependencyMatrix:
//! - REQUIRED role: +20 (prioritas tinggi)
//! - OPTIONAL role: +5
//! - SKIP role: +0
//!
//! ## Class Bonus (NEW)
//!
//! - DataCenter peer: +5 (kapasitas lebih besar, lebih reliable)
//! - Reguler peer: +0

use super::types::{
    PeerEntry, PeerSource, NodeRole, NodeClass, RoleDependency,
    current_unix_time, role_dependency,
};

// ════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

const BASE_SCORE: i64 = 10;
const SUCCESS_WEIGHT: i64 = 2;
const FAILURE_WEIGHT: i64 = 3;
const SUSPICIOUS_PENALTY: i64 = 20;
const BANNED_PENALTY: i64 = 1000;

// Recency thresholds (in seconds)
const ONE_HOUR: u64 = 3600;
const ONE_DAY: u64 = 86400;
const SEVEN_DAYS: u64 = 7 * ONE_DAY;
const THIRTY_DAYS: u64 = 30 * ONE_DAY;

// Recency bonuses
const RECENCY_BONUS_1H: i64 = 10;
const RECENCY_BONUS_24H: i64 = 5;

// Staleness penalties
const STALE_7D_PENALTY: i64 = 5;
const STALE_30D_PENALTY: i64 = 10;

// Source bonuses (anti-eclipse)
const SOURCE_BONUS_MANUAL: i64 = 3;
const SOURCE_BONUS_DNS: i64 = 2;
const SOURCE_BONUS_INBOUND: i64 = 1;
const SOURCE_BONUS_PEX: i64 = 0;

// Role bonuses (NEW — sesuai Tahap 21 v2)
const ROLE_BONUS_REQUIRED: i64 = 20;
const ROLE_BONUS_OPTIONAL: i64 = 5;
const ROLE_BONUS_SKIP: i64 = 0;

// Class bonus (NEW)
const CLASS_BONUS_DATACENTER: i64 = 5;
const CLASS_BONUS_REGULER: i64 = 0;

// ════════════════════════════════════════════════════════════════════════════
// PEER SCORE
// ════════════════════════════════════════════════════════════════════════════

/// Breakdown detail skor peer — untuk debugging dan observability.
#[derive(Debug, Clone, Default)]
pub struct PeerScore {
    pub base: i64,
    pub success_component: i64,
    pub failure_component: i64,
    pub recency_bonus: i64,
    pub staleness_penalty: i64,
    pub source_bonus: i64,
    pub role_bonus: i64,
    pub class_bonus: i64,
    pub suspicious_penalty: i64,
    pub banned_penalty: i64,
    pub total: i64,
}

impl PeerScore {
    pub fn compute(&mut self) {
        self.total = self.base
            + self.success_component
            - self.failure_component
            + self.recency_bonus
            - self.staleness_penalty
            + self.source_bonus
            + self.role_bonus
            + self.class_bonus
            - self.suspicious_penalty
            - self.banned_penalty;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PEER SCORER
// ════════════════════════════════════════════════════════════════════════════

/// Peer scoring engine.
///
/// Stateless — setiap call ke `score()` menghasilkan output yang sama
/// untuk input yang sama (deterministic).
pub struct PeerScorer;

impl PeerScorer {
    /// Hitung skor untuk satu peer.
    ///
    /// Score tinggi = peer yang lebih baik.
    /// Score negatif = peer yang buruk (banned, suspicious).
    ///
    /// `our_role`: Role node kita — digunakan untuk hitung role_bonus
    /// berdasarkan RoleDependencyMatrix.
    pub fn score(peer: &PeerEntry, our_role: NodeRole) -> PeerScore {
        let now = current_unix_time();
        let mut s = PeerScore::default();

        // Base score
        s.base = BASE_SCORE;

        // Success/failure components (capped untuk mencegah overflow)
        s.success_component = (peer.success_count as i64).min(500) * SUCCESS_WEIGHT;
        s.failure_component = (peer.failure_count as i64).min(500) * FAILURE_WEIGHT;

        // Recency bonus berdasarkan last_success
        if peer.last_success > 0 {
            let age = now.saturating_sub(peer.last_success);
            if age < ONE_HOUR {
                s.recency_bonus = RECENCY_BONUS_1H;
            } else if age < ONE_DAY {
                s.recency_bonus = RECENCY_BONUS_24H;
            }
        }

        // Staleness penalty berdasarkan last_seen
        if peer.last_seen > 0 {
            let age = now.saturating_sub(peer.last_seen);
            if age > THIRTY_DAYS {
                s.staleness_penalty = STALE_30D_PENALTY;
            } else if age > SEVEN_DAYS {
                s.staleness_penalty = STALE_7D_PENALTY;
            }
        }

        // Source bonus (anti-eclipse)
        s.source_bonus = match peer.source {
            PeerSource::Manual | PeerSource::StaticConfig => SOURCE_BONUS_MANUAL,
            PeerSource::DnsSeed => SOURCE_BONUS_DNS,
            PeerSource::Inbound => SOURCE_BONUS_INBOUND,
            PeerSource::PeerExchange => SOURCE_BONUS_PEX,
            PeerSource::PeerCache => SOURCE_BONUS_INBOUND,
        };

        // Role bonus (NEW — berdasarkan RoleDependencyMatrix)
        s.role_bonus = match role_dependency(our_role, peer.role) {
            RoleDependency::Required => ROLE_BONUS_REQUIRED,
            RoleDependency::Optional => ROLE_BONUS_OPTIONAL,
            RoleDependency::Skip => ROLE_BONUS_SKIP,
        };

        // Class bonus (NEW — DataCenter peer lebih reliable)
        s.class_bonus = match peer.node_class {
            Some(NodeClass::DataCenter) => CLASS_BONUS_DATACENTER,
            Some(NodeClass::Reguler) => CLASS_BONUS_REGULER,
            None => 0,
        };

        // Suspicious penalty
        if peer.is_suspicious() {
            s.suspicious_penalty = SUSPICIOUS_PENALTY;
        }

        // Banned penalty
        if peer.is_banned() {
            s.banned_penalty = BANNED_PENALTY;
        }

        s.compute();
        s
    }

    /// Hitung dan update skor di PeerEntry in-place.
    pub fn update_score(peer: &mut PeerEntry, our_role: NodeRole) {
        let s = Self::score(peer, our_role);
        peer.score = s.total;
    }

    /// Sort peers by score descending (best first).
    pub fn sort_by_score(peers: &mut [PeerEntry]) {
        peers.sort_by(|a, b| b.score.cmp(&a.score));
    }

    /// Select top N peers by score.
    pub fn select_top(peers: &[PeerEntry], n: usize) -> Vec<&PeerEntry> {
        let mut indexed: Vec<(usize, i64)> = peers.iter().enumerate()
            .map(|(i, p)| (i, p.score))
            .collect();
        indexed.sort_by(|a, b| b.1.cmp(&a.1));
        indexed.into_iter()
            .take(n)
            .map(|(i, _)| &peers[i])
            .collect()
    }

    /// Check source diversity.
    ///
    /// Returns (total_peers, unique_sources).
    /// Untuk anti-eclipse, unique_sources harus > 1.
    pub fn check_source_diversity(peers: &[PeerEntry]) -> (usize, usize) {
        use std::collections::HashSet;
        let sources: HashSet<_> = peers.iter()
            .filter(|p| matches!(p.status, super::types::PeerStatus::Connected))
            .map(|p| std::mem::discriminant(&p.source))
            .collect();
        let connected = peers.iter()
            .filter(|p| matches!(p.status, super::types::PeerStatus::Connected))
            .count();
        (connected, sources.len())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::*;
    use super::super::identity::NetworkId;
    use std::net::SocketAddr;
    use std::str::FromStr;

    fn make_test_peer(source: PeerSource, role: NodeRole, node_class: Option<NodeClass>) -> PeerEntry {
        let addr = SocketAddr::from_str("10.0.0.1:45831").unwrap();
        let mut p = PeerEntry::new(addr, NetworkId::Devnet, source);
        p.role = role;
        p.node_class = node_class;
        p
    }

    #[test]
    fn test_fresh_peer_has_base_score() {
        let peer = make_test_peer(PeerSource::Manual, NodeRole::StorageCompute, Some(NodeClass::Reguler));
        let score = PeerScorer::score(&peer, NodeRole::StorageCompute);
        assert!(score.total > 0);
        assert_eq!(score.base, BASE_SCORE);
    }

    #[test]
    fn test_successful_peer_scores_higher() {
        let mut good_peer = make_test_peer(PeerSource::Manual, NodeRole::StorageCompute, Some(NodeClass::Reguler));
        good_peer.success_count = 50;
        good_peer.last_success = current_unix_time();

        let mut bad_peer = make_test_peer(PeerSource::Manual, NodeRole::StorageCompute, Some(NodeClass::Reguler));
        bad_peer.failure_count = 50;

        let good_score = PeerScorer::score(&good_peer, NodeRole::StorageCompute);
        let bad_score = PeerScorer::score(&bad_peer, NodeRole::StorageCompute);
        assert!(good_score.total > bad_score.total);
    }

    #[test]
    fn test_banned_peer_has_negative_score() {
        let mut peer = make_test_peer(PeerSource::Manual, NodeRole::Validator, None);
        peer.ban(3600);
        let score = PeerScorer::score(&peer, NodeRole::Validator);
        assert!(score.total < 0, "banned peer should have negative score, got {}", score.total);
    }

    #[test]
    fn test_source_bonus_ordering() {
        let manual = PeerScorer::score(
            &make_test_peer(PeerSource::Manual, NodeRole::StorageCompute, Some(NodeClass::Reguler)),
            NodeRole::StorageCompute,
        );
        let dns = PeerScorer::score(
            &make_test_peer(PeerSource::DnsSeed, NodeRole::StorageCompute, Some(NodeClass::Reguler)),
            NodeRole::StorageCompute,
        );
        let pex = PeerScorer::score(
            &make_test_peer(PeerSource::PeerExchange, NodeRole::StorageCompute, Some(NodeClass::Reguler)),
            NodeRole::StorageCompute,
        );

        assert!(manual.source_bonus > dns.source_bonus);
        assert!(dns.source_bonus > pex.source_bonus);
    }

    #[test]
    fn test_suspicious_penalty_applied() {
        let mut peer = make_test_peer(PeerSource::Manual, NodeRole::StorageCompute, Some(NodeClass::Reguler));
        for _ in 0..10 {
            peer.record_failure();
        }
        assert!(peer.is_suspicious());
        let score = PeerScorer::score(&peer, NodeRole::StorageCompute);
        assert!(score.suspicious_penalty > 0);
    }

    // ── NEW: Role bonus tests ──────────────────────────────────

    #[test]
    fn test_role_bonus_required() {
        // StorageCompute needs StorageCompute → REQUIRED → +20
        let peer = make_test_peer(PeerSource::Manual, NodeRole::StorageCompute, Some(NodeClass::Reguler));
        let score = PeerScorer::score(&peer, NodeRole::StorageCompute);
        assert_eq!(score.role_bonus, ROLE_BONUS_REQUIRED);
    }

    #[test]
    fn test_role_bonus_optional() {
        // StorageCompute needs Validator → OPTIONAL → +5
        let peer = make_test_peer(PeerSource::Manual, NodeRole::Validator, None);
        let score = PeerScorer::score(&peer, NodeRole::StorageCompute);
        assert_eq!(score.role_bonus, ROLE_BONUS_OPTIONAL);
    }

    #[test]
    fn test_role_bonus_skip() {
        // StorageCompute needs Bootstrap → SKIP → +0
        let peer = make_test_peer(PeerSource::Manual, NodeRole::Bootstrap, None);
        let score = PeerScorer::score(&peer, NodeRole::StorageCompute);
        assert_eq!(score.role_bonus, ROLE_BONUS_SKIP);
    }

    #[test]
    fn test_required_role_scores_higher_than_optional() {
        // Coordinator peer (REQUIRED) should score higher than Validator peer (OPTIONAL)
        // when scored from StorageCompute perspective
        let coord_peer = make_test_peer(PeerSource::Manual, NodeRole::Coordinator, None);
        let validator_peer = make_test_peer(PeerSource::Manual, NodeRole::Validator, None);

        let coord_score = PeerScorer::score(&coord_peer, NodeRole::StorageCompute);
        let val_score = PeerScorer::score(&validator_peer, NodeRole::StorageCompute);

        assert!(coord_score.total > val_score.total,
            "REQUIRED role ({}) should score higher than OPTIONAL role ({})",
            coord_score.total, val_score.total);
    }

    // ── NEW: Class bonus tests ──────────────────────────────────

    #[test]
    fn test_class_bonus_datacenter() {
        let dc_peer = make_test_peer(PeerSource::Manual, NodeRole::StorageCompute, Some(NodeClass::DataCenter));
        let score = PeerScorer::score(&dc_peer, NodeRole::Coordinator);
        assert_eq!(score.class_bonus, CLASS_BONUS_DATACENTER);
    }

    #[test]
    fn test_class_bonus_reguler() {
        let reg_peer = make_test_peer(PeerSource::Manual, NodeRole::StorageCompute, Some(NodeClass::Reguler));
        let score = PeerScorer::score(&reg_peer, NodeRole::Coordinator);
        assert_eq!(score.class_bonus, CLASS_BONUS_REGULER);
    }

    #[test]
    fn test_datacenter_scores_higher_than_reguler() {
        let dc_peer = make_test_peer(PeerSource::Manual, NodeRole::StorageCompute, Some(NodeClass::DataCenter));
        let reg_peer = make_test_peer(PeerSource::Manual, NodeRole::StorageCompute, Some(NodeClass::Reguler));

        let dc_score = PeerScorer::score(&dc_peer, NodeRole::Coordinator);
        let reg_score = PeerScorer::score(&reg_peer, NodeRole::Coordinator);

        assert!(dc_score.total > reg_score.total);
    }

    #[test]
    fn test_sort_by_score() {
        let mut peers = vec![
            make_test_peer(PeerSource::PeerExchange, NodeRole::Bootstrap, None),      // SKIP + low source
            make_test_peer(PeerSource::Manual, NodeRole::StorageCompute, Some(NodeClass::DataCenter)), // REQUIRED + high source + DC
            make_test_peer(PeerSource::DnsSeed, NodeRole::Coordinator, None),          // REQUIRED + mid source
        ];

        // Compute scores from StorageCompute perspective
        for p in &mut peers {
            PeerScorer::update_score(p, NodeRole::StorageCompute);
        }

        PeerScorer::sort_by_score(&mut peers);

        // StorageCompute:DataCenter (REQUIRED + DC bonus + Manual bonus) should be first
        assert_eq!(peers[0].role, NodeRole::StorageCompute);
        assert_eq!(peers[0].node_class, Some(NodeClass::DataCenter));
    }
}
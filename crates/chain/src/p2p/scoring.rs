//! # Peer Scoring
//!
//! Algoritma scoring deterministik untuk peer selection.
//! Node memprioritaskan connect ke peer dengan score tertinggi.
//!
//! ## Formula
//!
//! ```text
//! score = BASE_SCORE
//!       + (success_count * SUCCESS_WEIGHT)
//!       - (failure_count * FAILURE_WEIGHT)
//!       + recency_bonus
//!       - staleness_penalty
//!       + source_bonus
//!       - suspicious_penalty
//! ```
//!
//! ## Recency Bonus
//!
//! - Last connect < 1 jam: +10
//! - Last connect < 24 jam: +5
//! - Otherwise: +0
//!
//! ## Staleness Penalty
//!
//! - Last seen > 7 hari: -5
//! - Last seen > 30 hari: -10
//!
//! ## Source Bonus (Anti-Eclipse)
//!
//! - Manual/StaticConfig: +3 (operator trust)
//! - DnsSeed: +2 (infrastructure trust)
//! - PeerExchange: +0 (no bonus, unverified)
//! - Inbound: +1 (peer initiated)

use super::types::{PeerEntry, PeerSource, current_unix_time};

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
    pub fn score(peer: &PeerEntry) -> PeerScore {
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
            PeerSource::PeerCache => SOURCE_BONUS_INBOUND, // cache = previously known
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
    pub fn update_score(peer: &mut PeerEntry) {
        let s = Self::score(peer);
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

    fn make_test_peer(source: PeerSource) -> PeerEntry {
        let addr = SocketAddr::from_str("10.0.0.1:8080").unwrap();
        PeerEntry::new(addr, NetworkId::Devnet, source)
    }

    #[test]
    fn test_fresh_peer_has_base_score() {
        let peer = make_test_peer(PeerSource::Manual);
        let score = PeerScorer::score(&peer);
        assert!(score.total > 0);
        assert_eq!(score.base, BASE_SCORE);
    }

    #[test]
    fn test_successful_peer_scores_higher() {
        let mut good_peer = make_test_peer(PeerSource::Manual);
        good_peer.success_count = 50;
        good_peer.last_success = current_unix_time();

        let mut bad_peer = make_test_peer(PeerSource::Manual);
        bad_peer.failure_count = 50;

        let good_score = PeerScorer::score(&good_peer);
        let bad_score = PeerScorer::score(&bad_peer);
        assert!(good_score.total > bad_score.total);
    }

    #[test]
    fn test_banned_peer_has_negative_score() {
        let mut peer = make_test_peer(PeerSource::Manual);
        peer.ban(3600);
        let score = PeerScorer::score(&peer);
        assert!(score.total < 0, "banned peer should have negative score, got {}", score.total);
    }

    #[test]
    fn test_source_bonus_ordering() {
        let manual = PeerScorer::score(&make_test_peer(PeerSource::Manual));
        let dns = PeerScorer::score(&make_test_peer(PeerSource::DnsSeed));
        let pex = PeerScorer::score(&make_test_peer(PeerSource::PeerExchange));

        assert!(manual.source_bonus > dns.source_bonus);
        assert!(dns.source_bonus > pex.source_bonus);
    }

    #[test]
    fn test_suspicious_penalty_applied() {
        let mut peer = make_test_peer(PeerSource::Manual);
        for _ in 0..10 {
            peer.record_failure();
        }
        assert!(peer.is_suspicious());
        let score = PeerScorer::score(&peer);
        assert!(score.suspicious_penalty > 0);
    }

    #[test]
    fn test_sort_by_score() {
        let mut peers = vec![
            make_test_peer(PeerSource::PeerExchange),
            make_test_peer(PeerSource::Manual),
            make_test_peer(PeerSource::DnsSeed),
        ];

        // Compute scores
        for p in &mut peers {
            PeerScorer::update_score(p);
        }

        PeerScorer::sort_by_score(&mut peers);

        // Manual should be first (highest source bonus)
        assert_eq!(peers[0].source, PeerSource::Manual);
    }
}
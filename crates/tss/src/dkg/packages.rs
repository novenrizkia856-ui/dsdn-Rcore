//! # DKG Round Packages
//!
//! Module ini mendefinisikan struktur data untuk package yang dikirim
//! dalam setiap round DKG protocol.
//!
//! ## Round 1: Commitment Broadcast
//!
//! `Round1Package` wraps `frost_ed25519::keys::dkg::round1::Package` yang berisi:
//! - Feldman VSS commitments (t compressed Edwards Y curve points)
//! - Schnorr proof of knowledge of the secret polynomial constant term
//!
//! ## Round 2: Secret Share Distribution
//!
//! `Round2Package` wraps `frost_ed25519::keys::dkg::round2::Package` yang berisi:
//! - Secret share evaluation untuk recipient tertentu
//! - Routing information (from, to)
//!
//! ## Kriptografi
//!
//! Semua kriptografi menggunakan `frost-ed25519` (ZCash Foundation):
//! - Commitments: Feldman Verifiable Secret Sharing (VSS) over Ed25519
//! - Proofs: Schnorr proof of knowledge (DLEQ-style)
//! - Shares: Polynomial evaluation pada Ed25519 scalar field
//!
//! Verifikasi commitment dan proof dilakukan secara otomatis oleh
//! frost library saat `frost::keys::dkg::part2()` dipanggil.

use frost_ed25519 as frost;

use crate::types::{ParticipantId, SessionId};

// ════════════════════════════════════════════════════════════════════════════════
// ROUND 1 PACKAGE
// ════════════════════════════════════════════════════════════════════════════════

/// Package yang dikirim oleh participant dalam Round 1 DKG.
///
/// `Round1Package` wraps real FROST DKG round 1 package yang di-broadcast
/// ke semua participants. Package berisi Feldman VSS commitments dan
/// Schnorr proof of knowledge.
///
/// ## Verifikasi
///
/// Verifikasi commitment dan proof dilakukan secara otomatis oleh frost library
/// saat `frost::keys::dkg::part2()` dipanggil dalam `process_round1()`.
/// Tidak perlu (dan tidak boleh) memverifikasi secara manual.
///
/// ## Contoh
///
/// ```rust,ignore
/// // Round1Package dibuat secara internal oleh generate_round1()
/// let round1_pkg = participant.generate_round1()?;
/// println!("From: {:?}", round1_pkg.participant_id());
/// ```
#[derive(Debug, Clone)]
pub struct Round1Package {
    /// Identifier dari participant yang mengirim package ini.
    participant_id: ParticipantId,

    /// Real FROST DKG round 1 package.
    ///
    /// Berisi:
    /// - `VerifiableSecretSharingCommitment`: t compressed Edwards Y points
    /// - `proof_of_knowledge`: Schnorr proof (R, z) sebagai Signature
    frost_package: frost::keys::dkg::round1::Package,
}

impl Round1Package {
    /// Membuat `Round1Package` baru.
    ///
    /// # Arguments
    ///
    /// * `participant_id` - Identifier dari sender
    /// * `frost_package` - Real FROST DKG round 1 package dari `part1()`
    #[must_use]
    pub fn new(
        participant_id: ParticipantId,
        frost_package: frost::keys::dkg::round1::Package,
    ) -> Self {
        Self {
            participant_id,
            frost_package,
        }
    }

    /// Mengembalikan participant ID dari sender.
    #[must_use]
    pub fn participant_id(&self) -> &ParticipantId {
        &self.participant_id
    }

    /// Mengembalikan reference ke internal frost round 1 package.
    #[must_use]
    pub fn frost_package(&self) -> &frost::keys::dkg::round1::Package {
        &self.frost_package
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// ROUND 2 PACKAGE
// ════════════════════════════════════════════════════════════════════════════════

/// Package yang dikirim dari satu participant ke participant lain dalam Round 2 DKG.
///
/// `Round2Package` wraps real FROST DKG round 2 package yang berisi
/// secret share evaluation untuk recipient tertentu. Share diverifikasi
/// terhadap VSS commitments dari Round 1 oleh frost library.
///
/// ## Keamanan
///
/// Share dalam round 2 package TIDAK dienkripsi pada protocol level.
/// Dalam deployment production, transport-layer encryption (TLS) harus
/// digunakan untuk melindungi share saat transit.
///
/// ## Contoh
///
/// ```rust,ignore
/// // Round2Packages dibuat secara internal oleh process_round1()
/// let round2_pkgs = participant.process_round1(&all_round1_packages)?;
/// for pkg in &round2_pkgs {
///     println!("From {} to {}", pkg.from_participant().to_hex(), pkg.to_participant().to_hex());
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Round2Package {
    /// Session ID untuk DKG session.
    session_id: SessionId,

    /// Participant ID dari sender.
    from_participant: ParticipantId,

    /// Participant ID dari recipient.
    to_participant: ParticipantId,

    /// Real FROST DKG round 2 package.
    ///
    /// Berisi secret share evaluation f_i(j) dimana i = sender, j = recipient.
    frost_package: frost::keys::dkg::round2::Package,
}

impl Round2Package {
    /// Membuat `Round2Package` baru.
    ///
    /// # Arguments
    ///
    /// * `session_id` - DKG session identifier
    /// * `from_participant` - Sender participant ID
    /// * `to_participant` - Recipient participant ID
    /// * `frost_package` - Real FROST DKG round 2 package dari `part2()`
    #[must_use]
    pub fn new(
        session_id: SessionId,
        from_participant: ParticipantId,
        to_participant: ParticipantId,
        frost_package: frost::keys::dkg::round2::Package,
    ) -> Self {
        Self {
            session_id,
            from_participant,
            to_participant,
            frost_package,
        }
    }

    /// Mengembalikan session ID.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Mengembalikan sender participant ID.
    #[must_use]
    pub fn from_participant(&self) -> &ParticipantId {
        &self.from_participant
    }

    /// Mengembalikan recipient participant ID.
    #[must_use]
    pub fn to_participant(&self) -> &ParticipantId {
        &self.to_participant
    }

    /// Mengembalikan reference ke internal frost round 2 package.
    #[must_use]
    pub fn frost_package(&self) -> &frost::keys::dkg::round2::Package {
        &self.frost_package
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::BTreeMap;

    /// Helper: generate frost DKG round1 data for a single participant.
    fn generate_round1_data(
        identifier: frost::Identifier,
        max_signers: u16,
        min_signers: u16,
        rng: &mut ChaCha20Rng,
    ) -> (frost::keys::dkg::round1::SecretPackage, frost::keys::dkg::round1::Package) {
        frost::keys::dkg::part1(identifier, max_signers, min_signers, rng)
            .expect("part1 must succeed with valid params")
    }

    /// Helper: create a deterministic frost Identifier from u16.
    fn frost_id(n: u16) -> frost::Identifier {
        frost::Identifier::try_from(n).expect("nonzero u16 must produce valid Identifier")
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND1PACKAGE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_round1_package_new() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let id = frost_id(1);
        let (_secret, frost_pkg) = generate_round1_data(id, 5, 3, &mut rng);
        let participant = ParticipantId::from_bytes([0x01; 32]);

        let package = Round1Package::new(participant.clone(), frost_pkg);

        assert_eq!(package.participant_id(), &participant);
    }

    #[test]
    fn test_round1_package_clone() {
        let mut rng = ChaCha20Rng::seed_from_u64(43);
        let id = frost_id(1);
        let (_secret, frost_pkg) = generate_round1_data(id, 3, 2, &mut rng);
        let participant = ParticipantId::from_bytes([0xAA; 32]);

        let package = Round1Package::new(participant.clone(), frost_pkg);
        let cloned = package.clone();

        assert_eq!(cloned.participant_id(), &participant);
    }

    #[test]
    fn test_round1_package_debug() {
        let mut rng = ChaCha20Rng::seed_from_u64(44);
        let id = frost_id(2);
        let (_secret, frost_pkg) = generate_round1_data(id, 3, 2, &mut rng);
        let participant = ParticipantId::from_bytes([0xBB; 32]);

        let package = Round1Package::new(participant, frost_pkg);
        let debug = format!("{:?}", package);

        assert!(debug.contains("Round1Package"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ROUND2PACKAGE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_round2_package_new_and_accessors() {
        let mut rng = ChaCha20Rng::seed_from_u64(50);

        // Run part1 for two participants
        let id1 = frost_id(1);
        let id2 = frost_id(2);
        let (secret1, pkg1) = generate_round1_data(id1, 2, 2, &mut rng);
        let (_secret2, pkg2) = generate_round1_data(id2, 2, 2, &mut rng);

        // Run part2 for participant 1
        let mut round1_packages = BTreeMap::new();
        round1_packages.insert(id2, pkg2);

        let (_r2_secret, r2_packages) =
            frost::keys::dkg::part2(secret1, &round1_packages)
                .expect("part2 must succeed");

        // Take the package for participant 2
        let frost_r2_pkg = r2_packages.get(&id2).expect("must have package for id2");

        let session = SessionId::from_bytes([0x11; 32]);
        let from = ParticipantId::from_bytes([0x01; 32]);
        let to = ParticipantId::from_bytes([0x02; 32]);

        let package = Round2Package::new(
            session.clone(),
            from.clone(),
            to.clone(),
            frost_r2_pkg.clone(),
        );

        assert_eq!(package.session_id(), &session);
        assert_eq!(package.from_participant(), &from);
        assert_eq!(package.to_participant(), &to);
    }

    #[test]
    fn test_round2_package_clone() {
        let mut rng = ChaCha20Rng::seed_from_u64(51);
        let id1 = frost_id(1);
        let id2 = frost_id(2);
        let (secret1, _pkg1) = generate_round1_data(id1, 2, 2, &mut rng);
        let (_secret2, pkg2) = generate_round1_data(id2, 2, 2, &mut rng);

        let mut round1_packages = BTreeMap::new();
        round1_packages.insert(id2, pkg2);

        let (_r2_secret, r2_packages) =
            frost::keys::dkg::part2(secret1, &round1_packages)
                .expect("part2 must succeed");

        let frost_r2_pkg = r2_packages.get(&id2).expect("must have package for id2");

        let session = SessionId::from_bytes([0x11; 32]);
        let from = ParticipantId::from_bytes([0x01; 32]);
        let to = ParticipantId::from_bytes([0x02; 32]);

        let package = Round2Package::new(session.clone(), from.clone(), to.clone(), frost_r2_pkg.clone());
        let cloned = package.clone();

        assert_eq!(cloned.session_id(), &session);
        assert_eq!(cloned.from_participant(), &from);
        assert_eq!(cloned.to_participant(), &to);
    }

    #[test]
    fn test_round2_package_debug() {
        let mut rng = ChaCha20Rng::seed_from_u64(52);
        let id1 = frost_id(1);
        let id2 = frost_id(2);
        let (secret1, _pkg1) = generate_round1_data(id1, 2, 2, &mut rng);
        let (_secret2, pkg2) = generate_round1_data(id2, 2, 2, &mut rng);

        let mut round1_packages = BTreeMap::new();
        round1_packages.insert(id2, pkg2);

        let (_r2_secret, r2_packages) =
            frost::keys::dkg::part2(secret1, &round1_packages)
                .expect("part2 must succeed");

        let frost_r2_pkg = r2_packages.get(&id2).expect("must have");
        let session = SessionId::from_bytes([0x11; 32]);
        let from = ParticipantId::from_bytes([0x01; 32]);
        let to = ParticipantId::from_bytes([0x02; 32]);

        let package = Round2Package::new(session, from, to, frost_r2_pkg.clone());
        let debug = format!("{:?}", package);

        assert!(debug.contains("Round2Package"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_packages_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Round1Package>();
        assert_send_sync::<Round2Package>();
    }
}
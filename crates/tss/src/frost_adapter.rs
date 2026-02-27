//! # FROST Crypto Adapter Module
//!
//! Adapter layer antara tipe internal crate `tss` dan library resmi
//! `frost-ed25519` (ZCash Foundation).
//!
//! Module ini menyediakan fungsi konversi dua arah (bidirectional) untuk:
//! - [`GroupPublicKey`] ↔ [`frost_ed25519::VerifyingKey`]
//! - [`SecretShare`] ↔ [`frost_ed25519::keys::SigningShare`]
//! - [`FrostSignature`] ↔ [`frost_ed25519::Signature`]
//! - [`SigningCommitment`] ↔ [`frost_ed25519::round1::SigningCommitments`]
//! - [`FrostSignatureShare`] ↔ [`frost_ed25519::round2::SignatureShare`]
//! - [`KeyShare`] ↔ [`frost_ed25519::keys::KeyPackage`]
//! - [`SignerId`] → [`frost_ed25519::Identifier`] (via `deserialize`, for signing rounds)
//!
//! Serta mapping error dari `frost_ed25519::Error` ke [`TSSError`].
//!
//! ## Invariants
//!
//! Semua konversi:
//! - Deterministic (output identik untuk input identik)
//! - Byte-identical setelah roundtrip
//! - Tidak menggunakan `unsafe`, `transmute`, `unwrap`, `expect`, atau `panic`
//! - Mengembalikan `Result<T, TSSError>`
//! - Memvalidasi panjang dan encoding secara eksplisit
//!
//! ## Catatan Kriptografis
//!
//! - Ed25519 public key (VerifyingKey) = 32-byte compressed Edwards Y point
//! - Ed25519 scalar (SigningShare, SignatureShare) = 32-byte little-endian
//! - Ed25519 signature = 64-byte (R ‖ s), R = compressed Edwards Y, s = scalar LE
//! - frost Identifier = nonzero scalar pada Ed25519 scalar field (little-endian)
//!
//! ## Batasan Konversi KeyShare ↔ KeyPackage
//!
//! Konversi `KeyShare → KeyPackage` bersifat **lossy**: field `total` (max_signers)
//! hilang karena `KeyPackage` tidak menyimpannya. Konversi balik
//! `KeyPackage → KeyShare` membutuhkan parameter `total` dari caller.
//!
//! Konversi `ParticipantId → frost::Identifier` **dapat gagal** jika bytes
//! ParticipantId bukan nonzero scalar valid pada Ed25519 scalar field.
//!
//! ## DKG Identifier Derivation
//!
//! Untuk DKG, `ParticipantId` dikonversi ke `frost::Identifier` menggunakan
//! `frost::Identifier::derive()` (hash-to-field), yang menjamin nonzero scalar
//! untuk input apapun. Ini berbeda dari `deserialize()` yang membutuhkan input
//! berupa valid scalar bytes.

use frost_ed25519 as frost;

use crate::error::TSSError;
use crate::primitives::{
    FrostSignature, FrostSignatureShare, GroupPublicKey, ParticipantPublicKey, SecretShare,
    SigningCommitment, PUBLIC_KEY_SIZE, SCALAR_SIZE, SIGNATURE_SIZE,
};
use crate::types::{ParticipantId, SignerId};

// Re-export frost_ed25519 crate agar consumer dapat mengakses tipe frost
// tanpa menambahkan dependency sendiri.
pub use frost_ed25519;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR MAPPING
// ════════════════════════════════════════════════════════════════════════════════

/// Mengkonversi `frost_ed25519::Error` ke [`TSSError`].
///
/// Mapping:
/// - Error yang mengandung "serialization" / "deserialization" → [`TSSError::Serialization`]
/// - Semua error lainnya → [`TSSError::Crypto`]
///
/// Pesan error asli dipreservasi secara penuh melalui `Display` implementation.
///
/// ## Auditability
///
/// Pesan error frost TIDAK di-strip atau di-transform. Caller mendapatkan
/// full error message untuk diagnostics.
pub fn map_frost_error(e: frost::Error) -> TSSError {
    let msg = e.to_string();
    // frost_core::Error::SerializationError menampilkan "Serialization Error"
    // frost_core::Error::DeserializationError menampilkan "Deserialization Error"
    let msg_lower = msg.to_lowercase();
    if msg_lower.contains("serialization") || msg_lower.contains("deserialization") {
        TSSError::Serialization(msg)
    } else {
        TSSError::Crypto(msg)
    }
}

/// Membuat [`TSSError::Crypto`] dengan pesan context.
fn crypto_err(context: &str, detail: &str) -> TSSError {
    TSSError::Crypto(format!("frost_adapter: {}: {}", context, detail))
}

/// Membuat [`TSSError::Serialization`] dengan pesan context.
fn serialization_err(context: &str, detail: &str) -> TSSError {
    TSSError::Serialization(format!("frost_adapter: {}: {}", context, detail))
}

// ════════════════════════════════════════════════════════════════════════════════
// 1) GroupPublicKey <-> frost::VerifyingKey
// ════════════════════════════════════════════════════════════════════════════════

/// Mengkonversi [`GroupPublicKey`] ke [`frost::VerifyingKey`].
///
/// `GroupPublicKey` internal menyimpan 32-byte compressed Edwards Y point.
/// `frost::VerifyingKey::deserialize()` menerima exact 32 bytes
/// dan memvalidasi bahwa bytes merepresentasikan valid curve point.
///
/// # Errors
///
/// Mengembalikan [`TSSError::Crypto`] jika bytes bukan valid Ed25519 point.
pub fn group_pubkey_to_verifying_key(
    key: &GroupPublicKey,
) -> Result<frost::VerifyingKey, TSSError> {
    frost::VerifyingKey::deserialize(key.as_bytes())
        .map_err(map_frost_error)
}

/// Mengkonversi [`frost::VerifyingKey`] ke [`GroupPublicKey`].
///
/// `frost::VerifyingKey::serialize()` mengembalikan 32-byte compressed Edwards Y.
/// `GroupPublicKey::from_bytes()` menerima exact `[u8; 32]`.
///
/// # Errors
///
/// Mengembalikan [`TSSError`] jika serialization gagal atau bytes tidak valid.
pub fn verifying_key_to_group_pubkey(
    key: &frost::VerifyingKey,
) -> Result<GroupPublicKey, TSSError> {
    let bytes = key.serialize().map_err(map_frost_error)?;

    let byte_array: [u8; PUBLIC_KEY_SIZE] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| serialization_err(
            "verifying_key_to_group_pubkey",
            &format!(
                "unexpected serialized length: expected {}, got {}",
                PUBLIC_KEY_SIZE,
                bytes.len()
            ),
        ))?;

    GroupPublicKey::from_bytes(byte_array)
}

// ════════════════════════════════════════════════════════════════════════════════
// 2) SecretShare <-> frost::keys::SigningShare
// ════════════════════════════════════════════════════════════════════════════════

/// Mengkonversi [`SecretShare`] ke [`frost::keys::SigningShare`].
///
/// Kedua tipe menyimpan 32-byte Ed25519 scalar (little-endian).
/// `frost::keys::SigningShare::deserialize()` memvalidasi bahwa bytes
/// merepresentasikan nonzero scalar dalam Ed25519 scalar field.
///
/// # Errors
///
/// Mengembalikan [`TSSError::Crypto`] jika bytes bukan valid nonzero scalar.
pub fn secret_share_to_signing_share(
    share: &SecretShare,
) -> Result<frost::keys::SigningShare, TSSError> {
    frost::keys::SigningShare::deserialize(share.as_bytes())
        .map_err(map_frost_error)
}

/// Mengkonversi [`frost::keys::SigningShare`] ke [`SecretShare`].
///
/// # Errors
///
/// Mengembalikan [`TSSError`] jika serialization gagal atau bytes tidak valid.
pub fn signing_share_to_secret_share(
    share: &frost::keys::SigningShare,
) -> Result<SecretShare, TSSError> {
    // SigningShare::serialize() returns Vec<u8> directly (scalar wrapper)
    let bytes = share.serialize();

    let byte_array: [u8; SCALAR_SIZE] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| serialization_err(
            "signing_share_to_secret_share",
            &format!(
                "unexpected serialized length: expected {}, got {}",
                SCALAR_SIZE,
                bytes.len()
            ),
        ))?;

    SecretShare::from_bytes(byte_array)
}

// ════════════════════════════════════════════════════════════════════════════════
// 3) FrostSignature <-> frost::Signature
// ════════════════════════════════════════════════════════════════════════════════

/// Mengkonversi [`FrostSignature`] ke [`frost::Signature`].
///
/// Kedua tipe menyimpan 64-byte signature dalam format R ‖ s:
/// - R: 32-byte compressed Edwards Y point
/// - s: 32-byte scalar (little-endian)
///
/// # Errors
///
/// Mengembalikan [`TSSError::Crypto`] jika bytes bukan valid signature format.
pub fn frost_sig_to_signature(
    sig: &FrostSignature,
) -> Result<frost::Signature, TSSError> {
    frost::Signature::deserialize(sig.as_bytes())
        .map_err(map_frost_error)
}

/// Mengkonversi [`frost::Signature`] ke [`FrostSignature`].
///
/// # Errors
///
/// Mengembalikan [`TSSError`] jika serialization gagal atau bytes tidak valid.
pub fn signature_to_frost_sig(
    sig: &frost::Signature,
) -> Result<FrostSignature, TSSError> {
    let bytes = sig.serialize().map_err(map_frost_error)?;

    let byte_array: [u8; SIGNATURE_SIZE] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| serialization_err(
            "signature_to_frost_sig",
            &format!(
                "unexpected serialized length: expected {}, got {}",
                SIGNATURE_SIZE,
                bytes.len()
            ),
        ))?;

    FrostSignature::from_bytes(byte_array)
}

// ════════════════════════════════════════════════════════════════════════════════
// 4) SigningCommitment <-> frost::round1::SigningCommitments
// ════════════════════════════════════════════════════════════════════════════════

/// Mengkonversi [`SigningCommitment`] ke [`frost::round1::SigningCommitments`].
///
/// `SigningCommitment` internal menyimpan hiding (32 bytes) dan binding (32 bytes)
/// sebagai compressed Edwards Y points.
///
/// Konversi dilakukan via component-level: setiap 32-byte array dikonversi
/// ke `frost::round1::NonceCommitment` via `deserialize`, lalu digabung
/// menjadi `SigningCommitments::new(hiding, binding)`.
///
/// Pendekatan component-level menghindari ketergantungan pada header format
/// dari frost compound serialization (69 bytes = 5-byte header + 2×32 bytes).
///
/// # Errors
///
/// Mengembalikan [`TSSError::Crypto`] jika bytes bukan valid curve points.
pub fn commitment_to_signing_commitments(
    commitment: &SigningCommitment,
) -> Result<frost::round1::SigningCommitments, TSSError> {
    let hiding = frost::round1::NonceCommitment::deserialize(commitment.hiding())
        .map_err(|e| crypto_err(
            "commitment_to_signing_commitments (hiding)",
            &e.to_string(),
        ))?;

    let binding = frost::round1::NonceCommitment::deserialize(commitment.binding())
        .map_err(|e| crypto_err(
            "commitment_to_signing_commitments (binding)",
            &e.to_string(),
        ))?;

    Ok(frost::round1::SigningCommitments::new(hiding, binding))
}

/// Mengkonversi [`frost::round1::SigningCommitments`] ke [`SigningCommitment`].
///
/// Akses komponen via `hiding()` dan `binding()` getters, serialize masing-masing
/// ke 32-byte compressed Edwards Y, lalu construct `SigningCommitment::from_parts`.
///
/// # Errors
///
/// Mengembalikan [`TSSError`] jika serialization gagal atau bytes tidak valid.
pub fn signing_commitments_to_commitment(
    commitments: &frost::round1::SigningCommitments,
) -> Result<SigningCommitment, TSSError> {
    let hiding_bytes = commitments.hiding().serialize()
        .map_err(|e| serialization_err(
            "signing_commitments_to_commitment (hiding)",
            &e.to_string(),
        ))?;

    let binding_bytes = commitments.binding().serialize()
        .map_err(|e| serialization_err(
            "signing_commitments_to_commitment (binding)",
            &e.to_string(),
        ))?;

    let hiding_array: [u8; 32] = hiding_bytes
        .as_slice()
        .try_into()
        .map_err(|_| serialization_err(
            "signing_commitments_to_commitment",
            &format!(
                "hiding: unexpected length: expected 32, got {}",
                hiding_bytes.len()
            ),
        ))?;

    let binding_array: [u8; 32] = binding_bytes
        .as_slice()
        .try_into()
        .map_err(|_| serialization_err(
            "signing_commitments_to_commitment",
            &format!(
                "binding: unexpected length: expected 32, got {}",
                binding_bytes.len()
            ),
        ))?;

    SigningCommitment::from_parts(hiding_array, binding_array)
}

// ════════════════════════════════════════════════════════════════════════════════
// 5) FrostSignatureShare <-> frost::round2::SignatureShare
// ════════════════════════════════════════════════════════════════════════════════

/// Mengkonversi [`FrostSignatureShare`] ke [`frost::round2::SignatureShare`].
///
/// Kedua tipe menyimpan 32-byte partial signature scalar (little-endian).
///
/// # Errors
///
/// Mengembalikan [`TSSError::Crypto`] jika bytes bukan valid scalar.
pub fn sig_share_to_signature_share(
    share: &FrostSignatureShare,
) -> Result<frost::round2::SignatureShare, TSSError> {
    frost::round2::SignatureShare::deserialize(share.as_bytes())
        .map_err(map_frost_error)
}

/// Mengkonversi [`frost::round2::SignatureShare`] ke [`FrostSignatureShare`].
///
/// # Errors
///
/// Mengembalikan [`TSSError`] jika serialization gagal atau bytes tidak valid.
pub fn signature_share_to_sig_share(
    share: &frost::round2::SignatureShare,
) -> Result<FrostSignatureShare, TSSError> {
    // SignatureShare::serialize() returns Vec<u8> directly (scalar wrapper)
    let bytes = share.serialize();

    let byte_array: [u8; SCALAR_SIZE] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| serialization_err(
            "signature_share_to_sig_share",
            &format!(
                "unexpected serialized length: expected {}, got {}",
                SCALAR_SIZE,
                bytes.len()
            ),
        ))?;

    FrostSignatureShare::from_bytes(byte_array)
}

// ════════════════════════════════════════════════════════════════════════════════
// 6) KeyShare <-> frost::keys::KeyPackage
// ════════════════════════════════════════════════════════════════════════════════

/// Mengkonversi internal [`crate::KeyShare`] ke [`frost::keys::KeyPackage`].
///
/// ## Field Mapping
///
/// | KeyShare field | KeyPackage field | Catatan |
/// |----------------|------------------|---------|
/// | `participant_id` | `identifier` | ParticipantId bytes harus valid nonzero scalar |
/// | `secret_share` | `signing_share` | Direct 32-byte scalar mapping |
/// | `participant_pubkey` | `verifying_share` | Direct 32-byte point mapping |
/// | `group_pubkey` | `verifying_key` | Direct 32-byte point mapping |
/// | `threshold` | `min_signers` | u8 → u16 widening |
/// | `total` | *(tidak ada)* | **Field ini hilang!** |
///
/// # Errors
///
/// Mengembalikan [`TSSError::Crypto`] jika:
/// - `participant_id` bytes bukan valid frost Identifier (nonzero scalar)
/// - `secret_share` bytes bukan valid SigningShare
/// - `participant_pubkey` bytes bukan valid VerifyingShare (curve point)
/// - `group_pubkey` bytes bukan valid VerifyingKey (curve point)
pub fn key_share_to_key_package(
    ks: &crate::KeyShare,
) -> Result<frost::keys::KeyPackage, TSSError> {
    // participant_id → frost Identifier
    let identifier = frost::Identifier::deserialize(ks.participant_id().as_bytes())
        .map_err(|e| crypto_err(
            "key_share_to_key_package (identifier)",
            &e.to_string(),
        ))?;

    // secret_share → frost SigningShare
    let signing_share = secret_share_to_signing_share(ks.secret_share())?;

    // participant_pubkey → frost VerifyingShare
    let verifying_share =
        frost::keys::VerifyingShare::deserialize(ks.participant_pubkey().as_bytes())
            .map_err(|e| crypto_err(
                "key_share_to_key_package (verifying_share)",
                &e.to_string(),
            ))?;

    // group_pubkey → frost VerifyingKey
    let verifying_key = group_pubkey_to_verifying_key(ks.group_pubkey())?;

    // threshold (u8) → min_signers (u16)
    let min_signers = u16::from(ks.threshold());

    Ok(frost::keys::KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        verifying_key,
        min_signers,
    ))
}

/// Mengkonversi [`frost::keys::KeyPackage`] ke internal [`crate::KeyShare`].
///
/// Karena `KeyPackage` tidak menyimpan `total` (max_signers),
/// parameter ini **harus disediakan oleh caller**.
///
/// ## Field Mapping
///
/// | KeyPackage field | KeyShare field | Catatan |
/// |------------------|----------------|---------|
/// | `identifier` | `participant_id` | Serialize to 32-byte LE scalar |
/// | `signing_share` | `secret_share` | Direct 32-byte scalar mapping |
/// | `verifying_share` | `participant_pubkey` | Direct 32-byte point mapping |
/// | `verifying_key` | `group_pubkey` | Direct 32-byte point mapping |
/// | `min_signers` | `threshold` | u16 → u8 narrowing (checked) |
/// | *(parameter)* | `total` | Disediakan oleh caller |
///
/// # Arguments
///
/// * `kp` - frost KeyPackage yang akan dikonversi
/// * `total` - Total participants (n in t-of-n), karena KeyPackage tidak menyimpannya
///
/// # Errors
///
/// Mengembalikan [`TSSError`] jika:
/// - `min_signers` > 255 (overflow u8)
/// - Serialization komponen gagal
/// - Bytes hasil serialization tidak valid untuk tipe internal
pub fn key_package_to_key_share(
    kp: &frost::keys::KeyPackage,
    total: u8,
) -> Result<crate::KeyShare, TSSError> {
    // frost Identifier → ParticipantId
    // Identifier::serialize() returns Vec<u8> directly (scalar wrapper)
    let id_bytes = kp.identifier().serialize();
    let id_array: [u8; 32] = id_bytes
        .as_slice()
        .try_into()
        .map_err(|_| serialization_err(
            "key_package_to_key_share (identifier)",
            &format!(
                "unexpected serialized length: expected 32, got {}",
                id_bytes.len()
            ),
        ))?;
    let participant_id = ParticipantId::from_bytes(id_array);

    // frost SigningShare → SecretShare
    let secret_share = signing_share_to_secret_share(kp.signing_share())?;

    // frost VerifyingShare → ParticipantPublicKey
    let vs_bytes = kp.verifying_share().serialize().map_err(map_frost_error)?;
    let vs_array: [u8; PUBLIC_KEY_SIZE] = vs_bytes
        .as_slice()
        .try_into()
        .map_err(|_| serialization_err(
            "key_package_to_key_share (verifying_share)",
            &format!(
                "unexpected serialized length: expected {}, got {}",
                PUBLIC_KEY_SIZE,
                vs_bytes.len()
            ),
        ))?;
    let participant_pubkey = ParticipantPublicKey::from_bytes(vs_array)?;

    // frost VerifyingKey → GroupPublicKey
    let group_pubkey = verifying_key_to_group_pubkey(kp.verifying_key())?;

    // min_signers (u16) → threshold (u8)
    let min_signers = *kp.min_signers();
    let threshold = u8::try_from(min_signers).map_err(|_| crypto_err(
        "key_package_to_key_share",
        &format!("min_signers {} exceeds u8 max (255)", min_signers),
    ))?;

    Ok(crate::KeyShare::new(
        secret_share,
        group_pubkey,
        participant_pubkey,
        participant_id,
        threshold,
        total,
    ))
}

// ════════════════════════════════════════════════════════════════════════════════
// 7) ParticipantId -> frost::Identifier (DKG derivation)
// ════════════════════════════════════════════════════════════════════════════════

/// Derive a `frost::Identifier` from a [`ParticipantId`] using hash-to-field.
///
/// Menggunakan `frost::Identifier::derive()` yang menerapkan hash-to-field
/// pada input bytes, menjamin output berupa nonzero scalar valid pada
/// Ed25519 scalar field.
///
/// Fungsi ini **deterministic**: input `ParticipantId` yang sama selalu
/// menghasilkan `Identifier` yang sama. Semua participants dalam DKG
/// akan secara independen menghitung mapping yang identik.
///
/// ## Penggunaan
///
/// Digunakan oleh `LocalDKGParticipant` saat menjalankan FROST DKG:
/// - `generate_round1()`: derive identifier untuk diri sendiri
/// - `process_round1()`: derive identifier untuk semua peers
/// - `process_round2()`: derive identifier untuk sender verifikasi
///
/// ## Perbedaan dengan `deserialize()`
///
/// | Method | Input | Guarantee |
/// |--------|-------|-----------|
/// | `deserialize()` | Valid LE scalar bytes | Dapat gagal jika bytes invalid |
/// | `derive()` | Arbitrary bytes | Selalu menghasilkan valid nonzero scalar |
///
/// # Errors
///
/// Mengembalikan [`TSSError::Crypto`] jika derivation gagal (secara praktis
/// tidak pernah terjadi untuk hash-to-field).
pub fn participant_id_to_frost_identifier(
    pid: &ParticipantId,
) -> Result<frost::Identifier, TSSError> {
    frost::Identifier::derive(pid.as_bytes())
        .map_err(|e| crypto_err("participant_id_to_frost_identifier", &e.to_string()))
}

// ════════════════════════════════════════════════════════════════════════════════
// 8) SignerId -> frost::Identifier (signing round conversion)
// ════════════════════════════════════════════════════════════════════════════════

/// Mengkonversi [`ParticipantPublicKey`] ke [`frost::keys::VerifyingShare`].
///
/// Digunakan untuk partial signature verification dan building
/// `frost::keys::PublicKeyPackage` untuk aggregate verification.
///
/// `ParticipantPublicKey` menyimpan 32-byte compressed Edwards Y point,
/// identik dengan format `frost::keys::VerifyingShare`.
///
/// # Errors
///
/// Mengembalikan [`TSSError::Crypto`] jika bytes bukan valid Ed25519 curve point.
pub fn participant_pubkey_to_verifying_share(
    pubkey: &ParticipantPublicKey,
) -> Result<frost::keys::VerifyingShare, TSSError> {
    frost::keys::VerifyingShare::deserialize(pubkey.as_bytes())
        .map_err(|e| crypto_err(
            "participant_pubkey_to_verifying_share",
            &e.to_string(),
        ))
}

/// Mengkonversi [`frost::keys::VerifyingShare`] ke [`ParticipantPublicKey`].
///
/// # Errors
///
/// Mengembalikan [`TSSError`] jika serialization gagal atau bytes tidak valid.
pub fn verifying_share_to_participant_pubkey(
    share: &frost::keys::VerifyingShare,
) -> Result<ParticipantPublicKey, TSSError> {
    let bytes = share.serialize().map_err(map_frost_error)?;

    let byte_array: [u8; PUBLIC_KEY_SIZE] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| serialization_err(
            "verifying_share_to_participant_pubkey",
            &format!(
                "unexpected serialized length: expected {}, got {}",
                PUBLIC_KEY_SIZE,
                bytes.len()
            ),
        ))?;

    ParticipantPublicKey::from_bytes(byte_array)
}

// ════════════════════════════════════════════════════════════════════════════════
// 9) SignerId -> frost::Identifier (signing round conversion)
// ════════════════════════════════════════════════════════════════════════════════

/// Mengkonversi [`SignerId`] ke [`frost::Identifier`] via deserialization.
///
/// Berbeda dari [`participant_id_to_frost_identifier`] yang menggunakan `derive()`,
/// fungsi ini menggunakan `deserialize()` karena `SignerId` dalam signing context
/// **sudah berisi** serialized frost Identifier bytes — bukan raw participant ID
/// yang perlu di-hash.
///
/// ## Kapan Gunakan
///
/// Digunakan saat membangun `frost::SigningPackage` dari `(SignerId, SigningCommitment)`
/// pairs selama threshold signing round 2.
///
/// ## Perbedaan dengan `participant_id_to_frost_identifier()`
///
/// | Function | Input | Method | Use case |
/// |----------|-------|--------|----------|
/// | `participant_id_to_frost_identifier` | Raw ParticipantId | `derive()` (hash-to-field) | DKG |
/// | `signer_id_to_frost_identifier` | Serialized frost Identifier | `deserialize()` | Signing |
///
/// # Errors
///
/// Mengembalikan [`TSSError::Crypto`] jika bytes bukan valid nonzero scalar
/// pada Ed25519 scalar field.
pub fn signer_id_to_frost_identifier(
    sid: &SignerId,
) -> Result<frost::Identifier, TSSError> {
    frost::Identifier::deserialize(sid.as_bytes())
        .map_err(|e| crypto_err("signer_id_to_frost_identifier", &e.to_string()))
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use frost_ed25519 as frost;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::BTreeMap;

    /// Helper: generate deterministic frost key material (3-of-5).
    fn generate_test_keys() -> (
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let max_signers: u16 = 5;
        let min_signers: u16 = 3;
        let (shares, pubkey_package) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .expect("dealer keygen must succeed with valid params");

        let mut key_packages = BTreeMap::new();
        for (identifier, secret_share) in shares {
            let key_package = frost::keys::KeyPackage::try_from(secret_share)
                .expect("KeyPackage from SecretShare must succeed");
            key_packages.insert(identifier, key_package);
        }
        (key_packages, pubkey_package)
    }

    /// Helper: run full signing ceremony, return (signature, shares, commitments, pubkey_pkg).
    fn generate_test_signature() -> (
        frost::Signature,
        BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
        BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
        frost::keys::PublicKeyPackage,
    ) {
        let (key_packages, pubkey_package) = generate_test_keys();
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let message = b"test message for frost adapter";

        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();

        // Select first 3 signers (threshold)
        let signers: Vec<frost::Identifier> =
            key_packages.keys().take(3).copied().collect();

        for id in &signers {
            let kp = &key_packages[id];
            let (nonces, commitments) =
                frost::round1::commit(kp.signing_share(), &mut rng);
            nonces_map.insert(*id, nonces);
            commitments_map.insert(*id, commitments);
        }

        let signing_package =
            frost::SigningPackage::new(commitments_map.clone(), message);

        let mut signature_shares = BTreeMap::new();
        for id in &signers {
            let kp = &key_packages[id];
            let nonces = &nonces_map[id];
            let share = frost::round2::sign(&signing_package, nonces, kp)
                .expect("signing must succeed");
            signature_shares.insert(*id, share);
        }

        let group_sig =
            frost::aggregate(&signing_package, &signature_shares, &pubkey_package)
                .expect("aggregation must succeed");

        (group_sig, signature_shares, commitments_map, pubkey_package)
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 1: GroupPublicKey roundtrip
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_group_pubkey_roundtrip() {
        let (_kps, pubkey_package) = generate_test_keys();
        let vk = pubkey_package.verifying_key();

        // frost VerifyingKey → GroupPublicKey → frost VerifyingKey
        let group_pubkey = verifying_key_to_group_pubkey(vk)
            .expect("verifying_key_to_group_pubkey must succeed");

        let vk_back = group_pubkey_to_verifying_key(&group_pubkey)
            .expect("group_pubkey_to_verifying_key must succeed");

        let original_bytes = vk.serialize().expect("serialize must succeed");
        let roundtrip_bytes = vk_back.serialize().expect("serialize must succeed");
        assert_eq!(
            original_bytes, roundtrip_bytes,
            "GroupPublicKey roundtrip must be byte-identical"
        );
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 2: SecretShare roundtrip
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_secret_share_roundtrip() {
        let (key_packages, _) = generate_test_keys();
        let kp = key_packages
            .values()
            .next()
            .expect("must have at least one key package");
        let signing_share = kp.signing_share();

        // frost SigningShare → SecretShare → frost SigningShare
        let secret_share = signing_share_to_secret_share(signing_share)
            .expect("signing_share_to_secret_share must succeed");

        let signing_share_back = secret_share_to_signing_share(&secret_share)
            .expect("secret_share_to_signing_share must succeed");

        let original = signing_share.serialize();
        let roundtrip = signing_share_back.serialize();
        assert_eq!(original, roundtrip, "SecretShare roundtrip must be byte-identical");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 3: FrostSignature roundtrip
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_frost_signature_roundtrip() {
        let (group_sig, _, _, _) = generate_test_signature();

        // frost Signature → FrostSignature → frost Signature
        let our_sig = signature_to_frost_sig(&group_sig)
            .expect("signature_to_frost_sig must succeed");

        let sig_back = frost_sig_to_signature(&our_sig)
            .expect("frost_sig_to_signature must succeed");

        let original = group_sig.serialize().expect("serialize must succeed");
        let roundtrip = sig_back.serialize().expect("serialize must succeed");
        assert_eq!(original, roundtrip, "FrostSignature roundtrip must be byte-identical");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 4: SigningCommitment roundtrip
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_commitment_roundtrip() {
        let (_, _, commitments_map, _) = generate_test_signature();
        let frost_commitments = commitments_map
            .values()
            .next()
            .expect("must have at least one commitment");

        // frost SigningCommitments → SigningCommitment → frost SigningCommitments
        let our_commitment = signing_commitments_to_commitment(frost_commitments)
            .expect("signing_commitments_to_commitment must succeed");

        let commitments_back = commitment_to_signing_commitments(&our_commitment)
            .expect("commitment_to_signing_commitments must succeed");

        // Component-level byte equality: hiding
        let orig_hiding = frost_commitments.hiding().serialize().expect("serialize");
        let rt_hiding = commitments_back.hiding().serialize().expect("serialize");
        assert_eq!(orig_hiding, rt_hiding, "hiding roundtrip must be byte-identical");

        // Component-level byte equality: binding
        let orig_binding = frost_commitments.binding().serialize().expect("serialize");
        let rt_binding = commitments_back.binding().serialize().expect("serialize");
        assert_eq!(orig_binding, rt_binding, "binding roundtrip must be byte-identical");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 5: FrostSignatureShare roundtrip
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_frost_signature_share_roundtrip() {
        let (_, signature_shares, _, _) = generate_test_signature();
        let frost_share = signature_shares
            .values()
            .next()
            .expect("must have at least one signature share");

        // frost SignatureShare → FrostSignatureShare → frost SignatureShare
        let our_share = signature_share_to_sig_share(frost_share)
            .expect("signature_share_to_sig_share must succeed");

        let share_back = sig_share_to_signature_share(&our_share)
            .expect("sig_share_to_signature_share must succeed");

        let original = frost_share.serialize();
        let roundtrip = share_back.serialize();
        assert_eq!(original, roundtrip, "SignatureShare roundtrip must be byte-identical");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 6: KeyShare roundtrip
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_key_share_roundtrip() {
        let (key_packages, _pubkey_package) = generate_test_keys();
        let (id, kp) = key_packages
            .iter()
            .next()
            .expect("must have at least one key package");

        let total: u8 = 5;

        // frost KeyPackage → KeyShare → frost KeyPackage
        let our_key_share = key_package_to_key_share(kp, total)
            .expect("key_package_to_key_share must succeed");

        assert_eq!(our_key_share.threshold(), *kp.min_signers() as u8);
        assert_eq!(our_key_share.total(), total);

        let kp_back = key_share_to_key_package(&our_key_share)
            .expect("key_share_to_key_package must succeed");

        // identifier (scalar wrapper → Vec<u8>)
        let orig_id = id.serialize();
        let rt_id = kp_back.identifier().serialize();
        assert_eq!(orig_id, rt_id, "KeyShare identifier roundtrip must be byte-identical");

        // signing_share (scalar wrapper → Vec<u8>)
        let orig_ss = kp.signing_share().serialize();
        let rt_ss = kp_back.signing_share().serialize();
        assert_eq!(orig_ss, rt_ss, "KeyShare signing_share roundtrip must be byte-identical");

        // verifying_key
        let orig_vk = kp.verifying_key().serialize().expect("serialize");
        let rt_vk = kp_back.verifying_key().serialize().expect("serialize");
        assert_eq!(orig_vk, rt_vk, "KeyShare verifying_key roundtrip must be byte-identical");

        // verifying_share
        let orig_vs = kp.verifying_share().serialize().expect("serialize");
        let rt_vs = kp_back.verifying_share().serialize().expect("serialize");
        assert_eq!(orig_vs, rt_vs, "KeyShare verifying_share roundtrip must be byte-identical");

        // min_signers
        assert_eq!(kp.min_signers(), kp_back.min_signers());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 7: Error mapping
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_error_mapping_invalid_verifying_key() {
        let zero_bytes = [0u8; PUBLIC_KEY_SIZE];
        let result = frost::VerifyingKey::deserialize(&zero_bytes);
        assert!(result.is_err(), "frost should reject identity point");

        let frost_err = result.unwrap_err();
        let tss_err = map_frost_error(frost_err);
        match &tss_err {
            TSSError::Crypto(msg) | TSSError::Serialization(msg) => {
                assert!(!msg.is_empty(), "error message must not be empty");
            }
            _ => {} // Accept any TSSError variant
        }
    }

    #[test]
    fn test_error_mapping_invalid_scalar() {
        // frost accepts any 32-byte value as scalar (reduces mod l).
        // Use wrong length (31 bytes) which frost will reject.
        let short_bytes = [0x42u8; 31];
        let result = frost::keys::SigningShare::deserialize(&short_bytes);
        assert!(result.is_err(), "frost should reject wrong-length scalar");

        let frost_err = result.unwrap_err();
        let tss_err = map_frost_error(frost_err);
        match &tss_err {
            TSSError::Crypto(msg) | TSSError::Serialization(msg) => {
                assert!(!msg.is_empty(), "error message must not be empty");
            }
            _ => {}
        }
    }

    #[test]
    fn test_error_mapping_invalid_signature_length() {
        let short_bytes = [0x42u8; 32]; // Only 32 bytes, need 64
        let result = frost::Signature::deserialize(&short_bytes);
        assert!(result.is_err(), "frost should reject short signature");

        let frost_err = result.unwrap_err();
        let tss_err = map_frost_error(frost_err);
        match &tss_err {
            TSSError::Crypto(msg) | TSSError::Serialization(msg) => {
                assert!(!msg.is_empty(), "error message must not be empty");
            }
            _ => {}
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // BONUS: Determinism verification
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_conversions_are_deterministic() {
        let (key_packages, pubkey_package) = generate_test_keys();
        let vk = pubkey_package.verifying_key();

        // Same input → same output, twice
        let gpk1 = verifying_key_to_group_pubkey(vk).expect("must succeed");
        let gpk2 = verifying_key_to_group_pubkey(vk).expect("must succeed");
        assert_eq!(gpk1.as_bytes(), gpk2.as_bytes(), "must be deterministic");

        let kp = key_packages.values().next().expect("must have key package");
        let ss1 = signing_share_to_secret_share(kp.signing_share()).expect("must succeed");
        let ss2 = signing_share_to_secret_share(kp.signing_share()).expect("must succeed");
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "must be deterministic");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 8: ParticipantId → frost Identifier derivation
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_participant_id_to_frost_identifier_deterministic() {
        let pid = ParticipantId::from_bytes([0x42; 32]);

        let id1 = participant_id_to_frost_identifier(&pid)
            .expect("derivation must succeed");
        let id2 = participant_id_to_frost_identifier(&pid)
            .expect("derivation must succeed");

        assert_eq!(
            id1.serialize(), id2.serialize(),
            "same ParticipantId must produce same frost Identifier"
        );
    }

    #[test]
    fn test_participant_id_to_frost_identifier_unique() {
        let pid1 = ParticipantId::from_bytes([0x01; 32]);
        let pid2 = ParticipantId::from_bytes([0x02; 32]);

        let id1 = participant_id_to_frost_identifier(&pid1)
            .expect("derivation must succeed");
        let id2 = participant_id_to_frost_identifier(&pid2)
            .expect("derivation must succeed");

        assert_ne!(
            id1.serialize(), id2.serialize(),
            "different ParticipantIds must produce different frost Identifiers"
        );
    }

    #[test]
    fn test_participant_id_to_frost_identifier_zero_bytes_succeeds() {
        // Identifier::derive uses hash-to-field, so even zero bytes
        // should produce a valid nonzero identifier
        let pid = ParticipantId::from_bytes([0x00; 32]);
        let result = participant_id_to_frost_identifier(&pid);
        assert!(result.is_ok(), "derive must succeed for any input");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 9: SignerId → frost Identifier roundtrip
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signer_id_to_frost_identifier_roundtrip() {
        // Generate a valid frost Identifier, serialize it, use as SignerId,
        // then convert back — must be identical.
        let (key_packages, _) = generate_test_keys();
        let (frost_id, _) = key_packages
            .iter()
            .next()
            .expect("must have at least one key package");

        let id_bytes = frost_id.serialize();
        let arr: [u8; 32] = id_bytes.as_slice().try_into().expect("32 bytes");
        let sid = crate::types::SignerId::from_bytes(arr);

        let roundtrip_id = signer_id_to_frost_identifier(&sid)
            .expect("signer_id_to_frost_identifier must succeed for valid Identifier bytes");

        assert_eq!(
            frost_id.serialize(),
            roundtrip_id.serialize(),
            "SignerId roundtrip must produce identical frost Identifier"
        );
    }

    #[test]
    fn test_signer_id_to_frost_identifier_deterministic() {
        let (key_packages, _) = generate_test_keys();
        let (frost_id, _) = key_packages
            .iter()
            .next()
            .expect("must have at least one key package");

        let id_bytes = frost_id.serialize();
        let arr: [u8; 32] = id_bytes.as_slice().try_into().expect("32 bytes");
        let sid = crate::types::SignerId::from_bytes(arr);

        let id1 = signer_id_to_frost_identifier(&sid).expect("ok");
        let id2 = signer_id_to_frost_identifier(&sid).expect("ok");

        assert_eq!(
            id1.serialize(),
            id2.serialize(),
            "same SignerId must produce same frost Identifier"
        );
    }

    #[test]
    fn test_signer_id_to_frost_identifier_rejects_zero() {
        // Zero bytes are not a valid nonzero scalar → should fail
        let sid = crate::types::SignerId::from_bytes([0x00; 32]);
        let result = signer_id_to_frost_identifier(&sid);
        // frost Identifier::deserialize rejects the zero scalar
        assert!(result.is_err(), "zero bytes must be rejected as Identifier");
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TEST 10: ParticipantPublicKey ↔ frost VerifyingShare (verification helper)
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_participant_pubkey_to_verifying_share_roundtrip() {
        let (key_packages, _) = generate_test_keys();
        let kp = key_packages.values().next().expect("must have key package");

        let vs = kp.verifying_share();
        let ppk = verifying_share_to_participant_pubkey(vs).expect("conversion must succeed");
        let vs_back = participant_pubkey_to_verifying_share(&ppk).expect("roundtrip must succeed");

        let orig_bytes = vs.serialize().expect("serialize");
        let rt_bytes = vs_back.serialize().expect("serialize");
        assert_eq!(orig_bytes, rt_bytes, "roundtrip must be byte-identical");
    }

    #[test]
    fn test_participant_pubkey_to_verifying_share_rejects_identity() {
        let zero_pubkey = ParticipantPublicKey::from_bytes([0x00; 32]);
        // Zero bytes = identity point → should be rejected by frost
        if let Ok(ppk) = zero_pubkey {
            let result = participant_pubkey_to_verifying_share(&ppk);
            assert!(result.is_err(), "identity point must be rejected");
        }
        // If from_bytes itself rejects zero bytes, that's also correct
    }

    #[test]
    fn test_participant_pubkey_to_verifying_share_deterministic() {
        let (key_packages, _) = generate_test_keys();
        let kp = key_packages.values().next().expect("must have key package");

        let vs = kp.verifying_share();
        let ppk = verifying_share_to_participant_pubkey(vs).expect("ok");

        let vs1 = participant_pubkey_to_verifying_share(&ppk).expect("ok");
        let vs2 = participant_pubkey_to_verifying_share(&ppk).expect("ok");

        assert_eq!(
            vs1.serialize().expect("ok"),
            vs2.serialize().expect("ok"),
            "conversion must be deterministic"
        );
    }
}
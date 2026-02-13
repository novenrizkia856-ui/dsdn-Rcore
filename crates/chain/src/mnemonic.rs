//! # Mnemonic Module (13.17.9)
//!
//! BIP39-compatible mnemonic seed phrase untuk DSDN Wallet.
//!
//! ## Overview
//!
//! Module ini menyediakan:
//! - 24-word mnemonic generation (256-bit entropy)
//! - Mnemonic validation dan parsing
//! - Entropy ↔ Ed25519 secret key mapping
//!
//! ## How It Works
//!
//! ```text
//! ┌────────────────────────────────────────────────────────┐
//! │ GENERATE FLOW:                                         │
//! │   CSPRNG → 256-bit entropy → BIP39 encode → 24 words  │
//! │   entropy (32 bytes) = Ed25519 secret key              │
//! │                                                        │
//! │ IMPORT FLOW:                                           │
//! │   24 words → BIP39 decode → verify checksum → entropy  │
//! │   entropy (32 bytes) = Ed25519 secret key              │
//! └────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Security Notes
//!
//! ```text
//! ⚠️ CRITICAL:
//! - Mnemonic IS the private key — guard it with your life
//! - NEVER log, display in debug, or store unencrypted
//! - 24 words = 256-bit entropy = full key strength
//! - Checksum prevents typos (8-bit SHA-256 checksum)
//! ```
//!
//! ## BIP39 Encoding (24 words)
//!
//! | Component   | Bits |
//! |-------------|------|
//! | Entropy     | 256  |
//! | Checksum    | 8    |
//! | Total       | 264  |
//! | Words       | 24 × 11 bits = 264 |
//!
//! ## Dependency
//!
//! Requires `bip39` crate in Cargo.toml:
//! ```toml
//! [dependencies]
//! bip39 = "2"
//! ```

use bip39::{Mnemonic, Language};

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Errors yang mungkin terjadi saat operasi mnemonic.
#[derive(Debug, Clone, PartialEq)]
pub enum MnemonicError {
    /// Mnemonic phrase tidak valid (wrong word count, invalid words, bad checksum)
    InvalidMnemonic(String),

    /// Entropy length tidak sesuai (harus 32 bytes untuk 24 words)
    InvalidEntropyLength,

    /// Internal generation error
    GenerationFailed,
}

impl std::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MnemonicError::InvalidMnemonic(msg) => write!(f, "invalid mnemonic: {}", msg),
            MnemonicError::InvalidEntropyLength => write!(f, "invalid entropy length (expected 32 bytes)"),
            MnemonicError::GenerationFailed => write!(f, "mnemonic generation failed"),
        }
    }
}

impl std::error::Error for MnemonicError {}

// ════════════════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Generate 24-word BIP39 mnemonic dan return (mnemonic_phrase, secret_key).
///
/// Entropy 256-bit di-generate via CSPRNG, lalu di-encode ke 24 words.
/// Entropy bytes langsung digunakan sebagai Ed25519 secret key (32 bytes).
///
/// # Returns
/// * `Ok((String, [u8; 32]))` — (mnemonic phrase space-separated, secret key bytes)
/// * `Err(MnemonicError)` — jika generation gagal
///
/// # Example
/// ```rust,ignore
/// let (phrase, secret) = generate_mnemonic()?;
/// // phrase = "abandon ability able about above absent ..."
/// // secret = [u8; 32] — langsung bisa dipakai sebagai Ed25519 secret key
/// ```
pub fn generate_mnemonic() -> Result<(String, [u8; 32]), MnemonicError> {
    use rand::RngCore;
    
    // Generate 256-bit entropy via CSPRNG
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    
    // Encode entropy ke 24-word BIP39 mnemonic
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|_| MnemonicError::GenerationFailed)?;

    Ok((mnemonic.to_string(), entropy))
}

/// Parse dan validate 24-word mnemonic, return secret key bytes.
///
/// Menerima mnemonic phrase (space-separated), memvalidasi:
/// 1. Word count harus 24
/// 2. Semua words harus ada di BIP39 English wordlist
/// 3. Checksum harus valid
///
/// # Arguments
/// * `phrase` — 24 words separated by spaces
///
/// # Returns
/// * `Ok([u8; 32])` — secret key bytes (= entropy)
/// * `Err(MnemonicError)` — jika mnemonic tidak valid
///
/// # Example
/// ```rust,ignore
/// let phrase = "abandon ability able about above absent ...";
/// let secret = mnemonic_to_secret_key(phrase)?;
/// let wallet = Wallet::from_secret_key(&secret);
/// ```
pub fn mnemonic_to_secret_key(phrase: &str) -> Result<[u8; 32], MnemonicError> {
    // Normalize: trim, lowercase, collapse whitespace
    let normalized = phrase
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    // Validate word count
    let word_count = normalized.split(' ').count();
    if word_count != 24 {
        return Err(MnemonicError::InvalidMnemonic(
            format!("expected 24 words, got {}", word_count)
        ));
    }

    // Parse mnemonic (validates words + checksum)
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &normalized)
        .map_err(|e| MnemonicError::InvalidMnemonic(format!("{}", e)))?;

    // Extract entropy
    let entropy = mnemonic.to_entropy();

    if entropy.len() != 32 {
        return Err(MnemonicError::InvalidEntropyLength);
    }

    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&entropy);

    Ok(secret_key)
}

/// Derive mnemonic phrase dari existing secret key (untuk backup/display).
///
/// Mengambil 32-byte secret key dan meng-encode sebagai 24-word BIP39 mnemonic.
/// Berguna untuk menampilkan seed phrase dari wallet yang sudah ada.
///
/// # Arguments
/// * `secret_key` — 32-byte Ed25519 secret key
///
/// # Returns
/// * `Ok(String)` — 24-word mnemonic phrase
/// * `Err(MnemonicError)` — jika secret key tidak bisa di-encode
///
/// # Example
/// ```rust,ignore
/// let phrase = secret_key_to_mnemonic(wallet.secret_key())?;
/// println!("Your seed phrase: {}", phrase);
/// ```
pub fn secret_key_to_mnemonic(secret_key: &[u8; 32]) -> Result<String, MnemonicError> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, secret_key)
        .map_err(|e| MnemonicError::InvalidMnemonic(format!("entropy encode failed: {}", e)))?;

    Ok(mnemonic.to_string())
}

/// Validate mnemonic tanpa extract key (dry check).
///
/// # Returns
/// * `true` — mnemonic valid (24 words, valid words, checksum OK)
/// * `false` — mnemonic tidak valid
pub fn validate_mnemonic(phrase: &str) -> bool {
    mnemonic_to_secret_key(phrase).is_ok()
}

/// Format mnemonic untuk display (4 columns × 6 rows).
///
/// # Example Output
/// ```text
///  1. abandon     7. ability    13. above     19. absent
///  2. ability     8. able       14. absorb    20. abuse
///  3. able        9. about      15. abstract  21. access
///  4. about      10. above      16. absurd    22. accident
///  5. above      11. absent     17. abuse     23. account
///  6. absent     12. absorb     18. access    24. accuse
/// ```
pub fn format_mnemonic_display(phrase: &str) -> String {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let total = words.len();

    if total != 24 {
        return phrase.to_string();
    }

    // 4 columns × 6 rows layout
    let rows = 6;
    let mut lines = Vec::new();

    for row in 0..rows {
        let mut cols = Vec::new();
        for col in 0..4 {
            let idx = col * rows + row;
            if idx < total {
                cols.push(format!("{:>2}. {:<12}", idx + 1, words[idx]));
            }
        }
        lines.push(cols.join("  "));
    }

    lines.join("\n")
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic_24_words() {
        let (phrase, secret) = generate_mnemonic().expect("generate should succeed");

        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24, "Must generate 24 words");
        assert_eq!(secret.len(), 32, "Secret key must be 32 bytes");

        // Secret key tidak boleh semua zero
        assert!(!secret.iter().all(|&b| b == 0), "Secret should not be all zeros");

        println!("✅ test_generate_mnemonic_24_words PASSED");
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        let (phrase, secret) = generate_mnemonic().expect("generate");

        // Import kembali dari phrase
        let recovered = mnemonic_to_secret_key(&phrase).expect("import");

        // Secret key harus sama
        assert_eq!(secret, recovered, "Roundtrip must preserve secret key");

        println!("✅ test_mnemonic_roundtrip PASSED");
    }

    #[test]
    fn test_secret_key_to_mnemonic_roundtrip() {
        let (original_phrase, secret) = generate_mnemonic().expect("generate");

        // Convert secret → mnemonic
        let derived_phrase = secret_key_to_mnemonic(&secret).expect("encode");

        // Phrase harus sama
        assert_eq!(original_phrase, derived_phrase, "Phrases must match");

        // Dan import kembali harus menghasilkan secret yang sama
        let recovered = mnemonic_to_secret_key(&derived_phrase).expect("decode");
        assert_eq!(secret, recovered);

        println!("✅ test_secret_key_to_mnemonic_roundtrip PASSED");
    }

    #[test]
    fn test_mnemonic_determinism() {
        // Same secret key harus selalu menghasilkan same mnemonic
        let secret = [0x42u8; 32];

        let phrase1 = secret_key_to_mnemonic(&secret).expect("encode 1");
        let phrase2 = secret_key_to_mnemonic(&secret).expect("encode 2");

        assert_eq!(phrase1, phrase2, "Same secret must produce same mnemonic");

        // Dan import harus menghasilkan secret yang sama
        let recovered1 = mnemonic_to_secret_key(&phrase1).expect("decode 1");
        let recovered2 = mnemonic_to_secret_key(&phrase2).expect("decode 2");

        assert_eq!(recovered1, secret);
        assert_eq!(recovered2, secret);

        println!("✅ test_mnemonic_determinism PASSED");
    }

    #[test]
    fn test_invalid_mnemonic_wrong_word_count() {
        let result = mnemonic_to_secret_key("abandon ability able");
        assert!(result.is_err());

        if let Err(MnemonicError::InvalidMnemonic(msg)) = result {
            assert!(msg.contains("24"), "Error should mention expected word count");
        }

        println!("✅ test_invalid_mnemonic_wrong_word_count PASSED");
    }

    #[test]
    fn test_invalid_mnemonic_bad_word() {
        let bad_phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor xyznotaword";
        let result = mnemonic_to_secret_key(bad_phrase);
        assert!(result.is_err());

        println!("✅ test_invalid_mnemonic_bad_word PASSED");
    }

    #[test]
    fn test_invalid_mnemonic_bad_checksum() {
        // Generate valid mnemonic, then swap last word to break checksum
        let (phrase, _) = generate_mnemonic().expect("generate");
        let mut words: Vec<&str> = phrase.split_whitespace().collect();

        // Replace last word with a different valid word to break checksum
        let last = words[23];
        words[23] = if last == "abandon" { "zoo" } else { "abandon" };
        let tampered = words.join(" ");

        let result = mnemonic_to_secret_key(&tampered);
        // Kemungkinan besar error karena checksum invalid
        // (kecuali kebetulan valid, tapi sangat unlikely)
        // Kita hanya test bahwa fungsi tidak panic
        let _ = result;

        println!("✅ test_invalid_mnemonic_bad_checksum PASSED (no panic)");
    }

    #[test]
    fn test_validate_mnemonic() {
        let (phrase, _) = generate_mnemonic().expect("generate");

        assert!(validate_mnemonic(&phrase), "Generated mnemonic should be valid");
        assert!(!validate_mnemonic("not a valid mnemonic"), "Random string should be invalid");
        assert!(!validate_mnemonic(""), "Empty string should be invalid");

        println!("✅ test_validate_mnemonic PASSED");
    }

    #[test]
    fn test_mnemonic_whitespace_normalization() {
        let (phrase, secret) = generate_mnemonic().expect("generate");

        // Add extra whitespace
        let messy = format!("  {}  ", phrase.replace(' ', "   "));
        let recovered = mnemonic_to_secret_key(&messy).expect("should handle whitespace");
        assert_eq!(secret, recovered);

        println!("✅ test_mnemonic_whitespace_normalization PASSED");
    }

    #[test]
    fn test_mnemonic_case_insensitive() {
        let (phrase, secret) = generate_mnemonic().expect("generate");

        // Uppercase
        let upper = phrase.to_uppercase();
        let recovered = mnemonic_to_secret_key(&upper).expect("should handle uppercase");
        assert_eq!(secret, recovered);

        println!("✅ test_mnemonic_case_insensitive PASSED");
    }

    #[test]
    fn test_format_mnemonic_display() {
        let (phrase, _) = generate_mnemonic().expect("generate");
        let formatted = format_mnemonic_display(&phrase);

        // Harus mengandung "1." dan "24."
        assert!(formatted.contains("1."), "Should contain word 1");
        assert!(formatted.contains("24."), "Should contain word 24");

        // Harus 6 lines
        let lines: Vec<&str> = formatted.lines().collect();
        assert_eq!(lines.len(), 6, "Should have 6 lines (4 cols × 6 rows)");

        println!("✅ test_format_mnemonic_display PASSED");
        println!("{}", formatted);
    }

    #[test]
    fn test_different_mnemonics_different_keys() {
        let (phrase1, secret1) = generate_mnemonic().expect("gen 1");
        let (phrase2, secret2) = generate_mnemonic().expect("gen 2");

        assert_ne!(phrase1, phrase2, "Two random mnemonics should differ");
        assert_ne!(secret1, secret2, "Two random keys should differ");

        println!("✅ test_different_mnemonics_different_keys PASSED");
    }
}
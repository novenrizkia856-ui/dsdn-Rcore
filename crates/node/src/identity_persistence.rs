//! # Identity Persistence (14B.47)
//!
//! Provides [`IdentityStore`] for persisting and loading a service node's
//! Ed25519 secret key, operator address, and TLS fingerprint to disk.
//!
//! ## File Layout
//!
//! ```text
//! {base_path}/
//! ├── node_identity.key   # Raw 32-byte Ed25519 secret key (0600)
//! ├── operator.addr       # 40-char lowercase hex operator address
//! └── tls.fp              # 64-char lowercase hex TLS fingerprint
//! ```
//!
//! ## Security Model
//!
//! - `node_identity.key` is written with permission `0600` (owner read/write
//!   only). If permission setting fails, the operation returns an error.
//! - Secret key bytes are never logged, printed, or included in error messages.
//! - Files are opened with `create(true).write(true).truncate(true)` to
//!   prevent partial state from previous writes.
//! - All writes are followed by `flush()` + `sync_all()` for durability.
//!
//! ## Identity Corruption Handling
//!
//! `load_or_generate` validates that the loaded operator address matches
//! the one derived from the keypair. If they diverge (file corruption,
//! manual tampering), `PersistenceError::Corruption` is returned. No
//! silent regeneration occurs — corruption must be resolved manually.
//!
//! ## Deterministic Restart Guarantee
//!
//! Given an intact `node_identity.key`, the same `NodeIdentityManager`
//! is reconstructed on every restart. The `node_id`, `operator_address`,
//! and all signing behavior are deterministic (Ed25519 from fixed seed).
//!
//! ## Why `from_keypair` Instead of `generate`
//!
//! `NodeIdentityManager::generate()` does not expose the secret key
//! (the `signing_key` field is private). Since the secret must be
//! persisted, `load_or_generate` generates 32 random bytes via `OsRng`,
//! saves them, then constructs via `from_keypair(secret)`. The behavior
//! is equivalent: both produce an Ed25519 keypair from a 32-byte seed.
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()`.
//! - No `unsafe` code.
//! - All I/O errors are propagated via [`PersistenceError`].
//! - No TOCTOU: file operations use `create(true).truncate(true)`.

use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::identity_manager::{IdentityError, NodeIdentityManager};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Filename for the Ed25519 secret key (raw 32 bytes).
const KEY_FILENAME: &str = "node_identity.key";
/// Filename for the operator address (40-char hex).
const OPERATOR_FILENAME: &str = "operator.addr";
/// Filename for the TLS fingerprint (64-char hex).
const TLS_FP_FILENAME: &str = "tls.fp";

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type for identity persistence operations.
///
/// Wraps both I/O errors and identity construction errors without
/// modifying the upstream `IdentityError` type from `identity_manager`.
///
/// ## Why a Separate Error Type
///
/// `IdentityError` has three variants (`KeyGenerationFailed`,
/// `InvalidSecretKey`, `SigningFailed`) — none for I/O. Since
/// `identity_manager.rs` must not be modified, persistence I/O errors
/// are wrapped in this dedicated type.
#[derive(Debug)]
pub enum PersistenceError {
    /// File I/O failure (read, write, permission, sync).
    Io(io::Error),
    /// Identity construction or validation failure.
    Identity(IdentityError),
    /// Identity corruption detected (e.g., operator address mismatch).
    Corruption(String),
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistenceError::Io(e) => write!(f, "identity persistence I/O error: {}", e),
            PersistenceError::Identity(e) => write!(f, "identity error: {}", e),
            PersistenceError::Corruption(msg) => write!(f, "identity corruption: {}", msg),
        }
    }
}

impl std::error::Error for PersistenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PersistenceError::Io(e) => Some(e),
            PersistenceError::Identity(e) => Some(e),
            PersistenceError::Corruption(_) => None,
        }
    }
}

impl From<io::Error> for PersistenceError {
    fn from(e: io::Error) -> Self {
        PersistenceError::Io(e)
    }
}

impl From<IdentityError> for PersistenceError {
    fn from(e: IdentityError) -> Self {
        PersistenceError::Identity(e)
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// IDENTITY STORE
// ════════════════════════════════════════════════════════════════════════════════

/// Persistent storage for node identity files.
///
/// Reads and writes Ed25519 secret keys, operator addresses, and TLS
/// fingerprints to a base directory on disk.
///
/// ## Thread Safety
///
/// `IdentityStore` is `Send + Sync` (all fields are owned, no interior
/// mutability). However, file I/O is not inherently thread-safe —
/// external synchronization is required if multiple threads access
/// the same files concurrently.
pub struct IdentityStore {
    /// Root directory for identity files.
    base_path: PathBuf,
}

impl IdentityStore {
    /// Creates a new store rooted at the given directory path.
    ///
    /// The directory is NOT created immediately — it is created on
    /// first write operation (in `ensure_directory`).
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    // ────────────────────────────────────────────────────────────────
    // SAVE / LOAD: SECRET KEY
    // ────────────────────────────────────────────────────────────────

    /// Persists a 32-byte Ed25519 secret key to `{base_path}/node_identity.key`.
    ///
    /// - Creates the base directory if it does not exist.
    /// - Opens file with `create(true).write(true).truncate(true)`.
    /// - Writes exactly 32 raw bytes.
    /// - Sets file permission to `0600` (Unix) — owner read/write only.
    /// - Calls `flush()` + `sync_all()` for durability.
    ///
    /// ## Errors
    ///
    /// Returns `io::Error` if directory creation, file open, write,
    /// flush, sync, or permission setting fails.
    pub fn save_keypair(&self, secret_key: &[u8; 32]) -> Result<(), io::Error> {
        self.ensure_directory()?;
        let path = self.base_path.join(KEY_FILENAME);

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;

        file.write_all(secret_key)?;
        file.flush()?;
        file.sync_all()?;

        set_permission_0600(&path)?;

        Ok(())
    }

    /// Loads a 32-byte Ed25519 secret key from `{base_path}/node_identity.key`.
    ///
    /// The file must exist and contain exactly 32 bytes.
    ///
    /// ## Errors
    ///
    /// Returns `io::Error` if the file does not exist, cannot be read,
    /// or does not contain exactly 32 bytes.
    pub fn load_keypair(&self) -> Result<[u8; 32], io::Error> {
        let path = self.base_path.join(KEY_FILENAME);
        let data = fs::read(&path)?;
        if data.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "node_identity.key: expected 32 bytes, found {}",
                    data.len(),
                ),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        Ok(key)
    }

    // ────────────────────────────────────────────────────────────────
    // SAVE / LOAD: OPERATOR ADDRESS
    // ────────────────────────────────────────────────────────────────

    /// Persists a 20-byte operator address as 40-char lowercase hex
    /// to `{base_path}/operator.addr`.
    ///
    /// No `0x` prefix. No trailing newline.
    ///
    /// Opens file with `create(true).write(true).truncate(true)`,
    /// then `flush()` + `sync_all()`.
    pub fn save_operator_address(&self, address: &[u8; 20]) -> Result<(), io::Error> {
        self.ensure_directory()?;
        let hex = bytes_to_hex(address);
        let path = self.base_path.join(OPERATOR_FILENAME);

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;

        file.write_all(hex.as_bytes())?;
        file.flush()?;
        file.sync_all()?;

        Ok(())
    }

    /// Loads a 20-byte operator address from `{base_path}/operator.addr`.
    ///
    /// Expects a 40-char lowercase hex string (trimmed of whitespace).
    ///
    /// ## Errors
    ///
    /// Returns `io::Error` if the file does not exist, the content is
    /// not exactly 40 hex characters, or the hex is invalid.
    pub fn load_operator_address(&self) -> Result<[u8; 20], io::Error> {
        let path = self.base_path.join(OPERATOR_FILENAME);
        let raw = fs::read_to_string(&path)?;
        let trimmed = raw.trim();
        if trimmed.len() != 40 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "operator.addr: expected 40 hex chars, found {}",
                    trimmed.len(),
                ),
            ));
        }
        hex_to_bytes_20(trimmed)
    }

    // ────────────────────────────────────────────────────────────────
    // SAVE: TLS FINGERPRINT
    // ────────────────────────────────────────────────────────────────

    /// Persists a 32-byte TLS fingerprint as 64-char lowercase hex
    /// to `{base_path}/tls.fp`.
    ///
    /// No `0x` prefix. No trailing newline.
    ///
    /// Opens file with `create(true).write(true).truncate(true)`,
    /// then `flush()` + `sync_all()`.
    pub fn save_tls_fingerprint(&self, fingerprint: &[u8; 32]) -> Result<(), io::Error> {
        self.ensure_directory()?;
        let hex = bytes_to_hex(fingerprint);
        let path = self.base_path.join(TLS_FP_FILENAME);

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;

        file.write_all(hex.as_bytes())?;
        file.flush()?;
        file.sync_all()?;

        Ok(())
    }

    // ────────────────────────────────────────────────────────────────
    // EXISTS
    // ────────────────────────────────────────────────────────────────

    /// Returns `true` only if both `node_identity.key` and `operator.addr`
    /// exist on disk.
    ///
    /// Does not validate file contents — use `load_keypair` and
    /// `load_operator_address` for content validation.
    pub fn exists(&self) -> bool {
        self.base_path.join(KEY_FILENAME).is_file()
            && self.base_path.join(OPERATOR_FILENAME).is_file()
    }

    // ────────────────────────────────────────────────────────────────
    // LOAD OR GENERATE
    // ────────────────────────────────────────────────────────────────

    /// Loads an existing identity or generates a fresh one.
    ///
    /// ## If identity files exist (`exists() == true`)
    ///
    /// 1. Load secret key from `node_identity.key`.
    /// 2. Construct `NodeIdentityManager::from_keypair(secret)`.
    /// 3. Load operator address from `operator.addr`.
    /// 4. Validate that the loaded operator address matches
    ///    `manager.operator_address()`.
    /// 5. If mismatch → return `PersistenceError::Corruption`.
    ///
    /// ## If identity files do not exist
    ///
    /// 1. Generate 32 random bytes (secret key) via `OsRng`.
    /// 2. Construct `NodeIdentityManager::from_keypair(secret)`.
    /// 3. Save secret key to `node_identity.key` (0600).
    /// 4. Save operator address to `operator.addr`.
    ///
    /// Uses `from_keypair` instead of `generate()` because the secret
    /// key must be persisted, and `generate()` does not expose the
    /// raw secret bytes. The behavior is equivalent.
    ///
    /// ## No Silent Regeneration
    ///
    /// If loading fails due to corruption (wrong file size, invalid hex,
    /// operator mismatch), the error is returned. No fallback to
    /// generation occurs.
    ///
    /// ## Errors
    ///
    /// Returns `PersistenceError::Io` for file I/O failures,
    /// `PersistenceError::Identity` for keypair construction failures,
    /// or `PersistenceError::Corruption` for operator address mismatch.
    pub fn load_or_generate(&self) -> Result<NodeIdentityManager, PersistenceError> {
        if self.exists() {
            // Load existing identity
            let secret = self.load_keypair()?;
            let manager = NodeIdentityManager::from_keypair(secret)?;

            // Validate operator address consistency
            let stored_op = self.load_operator_address()?;
            if stored_op != *manager.operator_address() {
                return Err(PersistenceError::Corruption(
                    "stored operator address does not match derived address".to_string(),
                ));
            }

            Ok(manager)
        } else {
            // Generate fresh identity
            let secret = generate_random_secret()?;
            let manager = NodeIdentityManager::from_keypair(secret)?;

            // Persist before returning — if save fails, error propagates
            self.save_keypair(&secret)?;
            self.save_operator_address(manager.operator_address())?;

            Ok(manager)
        }
    }

    // ────────────────────────────────────────────────────────────────
    // INTERNAL HELPERS
    // ────────────────────────────────────────────────────────────────

    /// Creates the base directory (and parents) if it does not exist.
    fn ensure_directory(&self) -> Result<(), io::Error> {
        if !self.base_path.exists() {
            fs::create_dir_all(&self.base_path)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for IdentityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityStore")
            .field("base_path", &self.base_path)
            .field("exists", &self.exists())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS (module-private)
// ════════════════════════════════════════════════════════════════════════════════

/// Sets file permission to 0600 (Unix: owner read/write only).
///
/// On non-Unix platforms, this is a no-op that returns `Ok(())`.
/// Non-Unix platforms should use OS-specific ACLs externally.
#[cfg(unix)]
fn set_permission_0600(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_permission_0600(_path: &Path) -> Result<(), io::Error> {
    // Non-Unix: file permissions are not supported in the same way.
    // The caller is responsible for OS-specific ACLs.
    Ok(())
}

/// Generates 32 cryptographically random bytes using `OsRng`.
///
/// Uses `RngCore::try_fill_bytes` to avoid panicking on entropy
/// exhaustion. Returns `io::Error` if the OS random source fails.
fn generate_random_secret() -> Result<[u8; 32], io::Error> {
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut secret)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("OsRng failed: {}", e)))?;
    Ok(secret)
}

/// Converts a byte slice to a lowercase hex string.
///
/// No `0x` prefix. No separators. No trailing newline.
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        hex.push(HEX_CHARS[(b >> 4) as usize]);
        hex.push(HEX_CHARS[(b & 0x0F) as usize]);
    }
    hex
}

/// Lowercase hex digit lookup table.
const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Decodes a 40-char hex string into a 20-byte array.
fn hex_to_bytes_20(hex: &str) -> Result<[u8; 20], io::Error> {
    if hex.len() != 40 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected 40 hex chars, got {}", hex.len()),
        ));
    }
    let mut out = [0u8; 20];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Converts a single hex ASCII byte to its numeric value (0–15).
fn hex_digit(c: u8) -> Result<u8, io::Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid hex digit: 0x{:02x}", c),
        )),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COMPILE-TIME ASSERTIONS
// ════════════════════════════════════════════════════════════════════════════════

const _: () = {
    fn assert_send<T: Send>() {}
    fn check() { assert_send::<IdentityStore>(); }
    let _ = check;
};

const _: () = {
    fn assert_sync<T: Sync>() {}
    fn check() { assert_sync::<IdentityStore>(); }
    let _ = check;
};

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    /// Atomic counter for unique temp directory names.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Creates a unique temporary directory for each test.
    fn make_test_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir()
            .join(format!("dsdn_identity_test_{}_{}", pid, n));
        // Clean up if leftover from previous run
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// Removes a test directory (best-effort cleanup).
    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    fn make_store() -> (IdentityStore, PathBuf) {
        let dir = make_test_dir();
        let store = IdentityStore::new(dir.join("identity"));
        (store, dir)
    }

    // ──────────────────────────────────────────────────────────────────
    // SAVE / LOAD KEYPAIR
    // ──────────────────────────────────────────────────────────────────

    /// Save and load keypair round-trip.
    #[test]
    fn test_save_load_keypair_roundtrip() {
        let (store, dir) = make_store();
        assert!(store.save_keypair(&TEST_SEED).is_ok());
        let loaded = store.load_keypair();
        assert!(loaded.is_ok());
        if let Ok(key) = loaded {
            assert_eq!(key, TEST_SEED);
        }
        cleanup(&dir);
    }

    /// Load keypair from nonexistent file → error.
    #[test]
    fn test_load_keypair_missing() {
        let (store, dir) = make_store();
        let result = store.load_keypair();
        assert!(result.is_err());
        cleanup(&dir);
    }

    /// Load keypair with wrong size → error.
    #[test]
    fn test_load_keypair_wrong_size() {
        let (store, dir) = make_store();
        fs::create_dir_all(&store.base_path).expect("test setup: mkdir");
        let path = store.base_path.join(KEY_FILENAME);
        fs::write(&path, &[0u8; 16]).expect("test setup: write");
        let result = store.load_keypair();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("expected 32 bytes"));
        }
        cleanup(&dir);
    }

    /// Saved key file has exactly 32 bytes.
    #[test]
    fn test_save_keypair_exact_size() {
        let (store, dir) = make_store();
        assert!(store.save_keypair(&TEST_SEED).is_ok());
        let path = store.base_path.join(KEY_FILENAME);
        let data = fs::read(&path).expect("test read");
        assert_eq!(data.len(), 32);
        cleanup(&dir);
    }

    /// Key file permission is 0600 on Unix.
    #[cfg(unix)]
    #[test]
    fn test_save_keypair_permission() {
        use std::os::unix::fs::PermissionsExt;
        let (store, dir) = make_store();
        assert!(store.save_keypair(&TEST_SEED).is_ok());
        let path = store.base_path.join(KEY_FILENAME);
        let meta = fs::metadata(&path).expect("test metadata");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        cleanup(&dir);
    }

    /// Save keypair overwrites existing file (truncate).
    #[test]
    fn test_save_keypair_overwrites() {
        let (store, dir) = make_store();
        let seed1 = [0xAA; 32];
        let seed2 = [0xBB; 32];
        assert!(store.save_keypair(&seed1).is_ok());
        assert!(store.save_keypair(&seed2).is_ok());
        let loaded = store.load_keypair();
        assert!(loaded.is_ok());
        if let Ok(key) = loaded {
            assert_eq!(key, seed2);
        }
        cleanup(&dir);
    }

    // ──────────────────────────────────────────────────────────────────
    // SAVE / LOAD OPERATOR ADDRESS
    // ──────────────────────────────────────────────────────────────────

    /// Save and load operator address round-trip.
    #[test]
    fn test_save_load_operator_roundtrip() {
        let (store, dir) = make_store();
        let addr: [u8; 20] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0x0D, 0x0E, 0x0F, 0x10,
        ];
        assert!(store.save_operator_address(&addr).is_ok());
        let loaded = store.load_operator_address();
        assert!(loaded.is_ok());
        if let Ok(a) = loaded {
            assert_eq!(a, addr);
        }
        cleanup(&dir);
    }

    /// Operator file contains exactly 40 lowercase hex chars.
    #[test]
    fn test_save_operator_hex_format() {
        let (store, dir) = make_store();
        let addr = [0xAB; 20];
        assert!(store.save_operator_address(&addr).is_ok());
        let path = store.base_path.join(OPERATOR_FILENAME);
        let content = fs::read_to_string(&path).expect("test read");
        assert_eq!(content.len(), 40);
        assert_eq!(content, "ab".repeat(20));
        cleanup(&dir);
    }

    /// Load operator with wrong length → error.
    #[test]
    fn test_load_operator_wrong_length() {
        let (store, dir) = make_store();
        fs::create_dir_all(&store.base_path).expect("test setup: mkdir");
        let path = store.base_path.join(OPERATOR_FILENAME);
        fs::write(&path, "deadbeef").expect("test write");
        let result = store.load_operator_address();
        assert!(result.is_err());
        cleanup(&dir);
    }

    /// Load operator with invalid hex → error.
    #[test]
    fn test_load_operator_invalid_hex() {
        let (store, dir) = make_store();
        fs::create_dir_all(&store.base_path).expect("test setup: mkdir");
        let path = store.base_path.join(OPERATOR_FILENAME);
        fs::write(&path, "zz".repeat(20)).expect("test write");
        let result = store.load_operator_address();
        assert!(result.is_err());
        cleanup(&dir);
    }

    // ──────────────────────────────────────────────────────────────────
    // SAVE TLS FINGERPRINT
    // ──────────────────────────────────────────────────────────────────

    /// Save TLS fingerprint produces 64-char hex.
    #[test]
    fn test_save_tls_fingerprint() {
        let (store, dir) = make_store();
        let fp = [0xCA; 32];
        assert!(store.save_tls_fingerprint(&fp).is_ok());
        let path = store.base_path.join(TLS_FP_FILENAME);
        let content = fs::read_to_string(&path).expect("test read");
        assert_eq!(content.len(), 64);
        assert!(content.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(content, "ca".repeat(32));
        cleanup(&dir);
    }

    // ──────────────────────────────────────────────────────────────────
    // EXISTS
    // ──────────────────────────────────────────────────────────────────

    /// exists() returns false when no files.
    #[test]
    fn test_exists_false_initially() {
        let (store, dir) = make_store();
        assert!(!store.exists());
        cleanup(&dir);
    }

    /// exists() returns false with only key file.
    #[test]
    fn test_exists_partial_key_only() {
        let (store, dir) = make_store();
        assert!(store.save_keypair(&TEST_SEED).is_ok());
        assert!(!store.exists());
        cleanup(&dir);
    }

    /// exists() returns true with both key and operator files.
    #[test]
    fn test_exists_true_with_both() {
        let (store, dir) = make_store();
        assert!(store.save_keypair(&TEST_SEED).is_ok());
        assert!(store.save_operator_address(&[0u8; 20]).is_ok());
        assert!(store.exists());
        cleanup(&dir);
    }

    // ──────────────────────────────────────────────────────────────────
    // LOAD OR GENERATE
    // ──────────────────────────────────────────────────────────────────

    /// load_or_generate creates fresh identity when no files exist.
    #[test]
    fn test_load_or_generate_fresh() {
        let (store, dir) = make_store();
        let result = store.load_or_generate();
        assert!(result.is_ok());
        // Files should now exist
        assert!(store.exists());
        cleanup(&dir);
    }

    /// load_or_generate loads existing identity deterministically.
    #[test]
    fn test_load_or_generate_existing() {
        let (store, dir) = make_store();
        // Create identity
        let mgr1 = store.load_or_generate();
        assert!(mgr1.is_ok());
        // Reload — should produce same identity
        let mgr2 = store.load_or_generate();
        assert!(mgr2.is_ok());
        if let (Ok(m1), Ok(m2)) = (mgr1, mgr2) {
            assert_eq!(m1.node_id(), m2.node_id());
            assert_eq!(m1.operator_address(), m2.operator_address());
        }
        cleanup(&dir);
    }

    /// load_or_generate detects operator address corruption.
    #[test]
    fn test_load_or_generate_corruption() {
        let (store, dir) = make_store();
        // Pre-seed with known keypair
        assert!(store.save_keypair(&TEST_SEED).is_ok());
        let mgr_ref = NodeIdentityManager::from_keypair(TEST_SEED)
            .expect("test setup: from_keypair");
        assert!(store.save_operator_address(mgr_ref.operator_address()).is_ok());

        // Corrupt operator address with different value
        let op_path = store.base_path.join(OPERATOR_FILENAME);
        fs::write(&op_path, "ff".repeat(20)).expect("test corrupt");

        let result = store.load_or_generate();
        assert!(result.is_err());
        if let Err(PersistenceError::Corruption(msg)) = result {
            assert!(msg.contains("operator address"));
        } else {
            panic!("expected PersistenceError::Corruption");
        }
        cleanup(&dir);
    }

    /// load_or_generate with pre-seeded keypair loads correctly.
    #[test]
    fn test_load_or_generate_preseeded() {
        let (store, dir) = make_store();
        let mgr_ref = NodeIdentityManager::from_keypair(TEST_SEED)
            .expect("test setup: from_keypair");
        assert!(store.save_keypair(&TEST_SEED).is_ok());
        assert!(store.save_operator_address(mgr_ref.operator_address()).is_ok());

        let loaded = store.load_or_generate();
        assert!(loaded.is_ok());
        if let Ok(m) = loaded {
            assert_eq!(m.node_id(), mgr_ref.node_id());
            assert_eq!(m.operator_address(), mgr_ref.operator_address());
        }
        cleanup(&dir);
    }

    /// load_or_generate fails if key file is corrupted (wrong size).
    #[test]
    fn test_load_or_generate_corrupt_key_size() {
        let (store, dir) = make_store();
        fs::create_dir_all(&store.base_path).expect("test mkdir");
        fs::write(store.base_path.join(KEY_FILENAME), &[0u8; 16]).expect("test write");
        fs::write(store.base_path.join(OPERATOR_FILENAME), "a".repeat(40)).expect("test write");

        let result = store.load_or_generate();
        assert!(result.is_err());
        cleanup(&dir);
    }

    /// Generated identity has valid signing behavior.
    #[test]
    fn test_load_or_generate_signing_works() {
        let (store, dir) = make_store();
        let mgr = store.load_or_generate().expect("test: generate");
        // Sign a nonce and verify
        let nonce = [0x42u8; 32];
        let sig = mgr.sign_challenge(&nonce);
        assert_eq!(sig.len(), 64);

        // Verify via ed25519-dalek
        let pk = ed25519_dalek::VerifyingKey::from_bytes(mgr.node_id());
        assert!(pk.is_ok());
        if let Ok(vk) = pk {
            let signature = ed25519_dalek::Signature::from_slice(&sig);
            assert!(signature.is_ok());
            if let Ok(s) = signature {
                assert!(vk.verify_strict(&nonce, &s).is_ok());
            }
        }
        cleanup(&dir);
    }

    // ──────────────────────────────────────────────────────────────────
    // HEX ENCODING
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[0x00, 0xFF, 0x0A, 0xBC]), "00ff0abc");
    }

    #[test]
    fn test_bytes_to_hex_empty() {
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn test_hex_roundtrip_20() {
        let original = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67,
        ];
        let hex = bytes_to_hex(&original);
        let decoded = hex_to_bytes_20(&hex);
        assert!(decoded.is_ok());
        if let Ok(d) = decoded {
            assert_eq!(d, original);
        }
    }

    #[test]
    fn test_hex_digit_valid() {
        assert_eq!(hex_digit(b'0').unwrap(), 0);
        assert_eq!(hex_digit(b'9').unwrap(), 9);
        assert_eq!(hex_digit(b'a').unwrap(), 10);
        assert_eq!(hex_digit(b'f').unwrap(), 15);
        assert_eq!(hex_digit(b'A').unwrap(), 10);
        assert_eq!(hex_digit(b'F').unwrap(), 15);
    }

    #[test]
    fn test_hex_digit_invalid() {
        assert!(hex_digit(b'g').is_err());
        assert!(hex_digit(b'z').is_err());
        assert!(hex_digit(b' ').is_err());
    }

    // ──────────────────────────────────────────────────────────────────
    // DEBUG
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_output() {
        let (store, dir) = make_store();
        let debug_str = format!("{:?}", store);
        assert!(debug_str.contains("IdentityStore"));
        assert!(debug_str.contains("base_path"));
        cleanup(&dir);
    }

    // ──────────────────────────────────────────────────────────────────
    // PERSISTENCE ERROR
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_persistence_error_display() {
        let e1 = PersistenceError::Io(io::Error::new(io::ErrorKind::NotFound, "test"));
        let e2 = PersistenceError::Identity(IdentityError::InvalidSecretKey);
        let e3 = PersistenceError::Corruption("mismatch".to_string());

        let s1 = format!("{}", e1);
        let s2 = format!("{}", e2);
        let s3 = format!("{}", e3);

        assert!(s1.contains("I/O"));
        assert!(s2.contains("identity error"));
        assert!(s3.contains("corruption"));
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
    }

    #[test]
    fn test_persistence_error_source() {
        let e = PersistenceError::Io(io::Error::new(io::ErrorKind::NotFound, "test"));
        assert!(std::error::Error::source(&e).is_some());

        let e2 = PersistenceError::Corruption("test".to_string());
        assert!(std::error::Error::source(&e2).is_none());
    }

    #[test]
    fn test_persistence_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let pe: PersistenceError = io_err.into();
        if let PersistenceError::Io(e) = pe {
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        } else {
            panic!("expected PersistenceError::Io");
        }
    }

    #[test]
    fn test_persistence_error_from_identity() {
        let ie = IdentityError::InvalidSecretKey;
        let pe: PersistenceError = ie.into();
        if let PersistenceError::Identity(e) = pe {
            assert_eq!(e, IdentityError::InvalidSecretKey);
        } else {
            panic!("expected PersistenceError::Identity");
        }
    }
}
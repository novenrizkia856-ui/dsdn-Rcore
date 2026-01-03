//! Content ID helpers based on SHA-256.
//! Exposes deterministic hex string representation.

use sha2::{Digest, Sha256};

/// Compute SHA-256 and return lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sum = hasher.finalize();
    hex::encode(sum)
}

/// Short prefix form useful for logging (e.g., first 12 hex chars).
pub fn short_cid(data: &[u8]) -> String {
    let h = sha256_hex(data);
    h.get(0..12).unwrap_or(&h).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let a = b"some payload bytes";
        let h1 = sha256_hex(a);
        let h2 = sha256_hex(a);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // sha256 hex length
    }

    #[test]
    fn test_short_cid() {
        let a = b"x";
        let s = short_cid(a);
        assert!(s.len() <= 12);
    }
}

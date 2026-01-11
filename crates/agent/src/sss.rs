//! Shamir's Secret Sharing (SSS) Implementation
//!
//! This module implements (k, n) threshold secret sharing over GF(257).
//! A secret is split into n shares such that any k shares can reconstruct
//! the original secret, but fewer than k shares reveal nothing.
//!
//! # Field Choice
//!
//! We use GF(257) because 257 is the smallest prime > 256, allowing us to
//! represent all byte values (0-255) as field elements. Field elements
//! range from 0 to 256 inclusive.
//!
//! # Share Format
//!
//! Each share byte position stores a value in 0..256, which requires
//! more than 8 bits. We encode each field element as 2 bytes (little-endian)
//! in the share data.

use rand::RngCore;
use rand::rngs::OsRng;

/// Field prime - 257 (smallest prime > 256)
/// Field elements are in range 0..=256
const P: u16 = 257;

/// Compute a * b mod P
fn mul(a: u16, b: u16) -> u16 {
    (((a as u32) * (b as u32)) % (P as u32)) as u16
}

/// Compute a + b mod P
fn add(a: u16, b: u16) -> u16 {
    let sum = (a as u32) + (b as u32);
    if sum >= P as u32 {
        (sum - P as u32) as u16
    } else {
        sum as u16
    }
}

/// Extended Euclidean algorithm for modular inverse
fn egcd(a: i64, b: i64) -> (i64, i64, i64) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (g, x, y) = egcd(b, a % b);
        (g, y, x - (a / b) * y)
    }
}

/// Modular inverse mod P
/// Returns a^(-1) mod P
fn modinv(a: u16) -> u16 {
    if a == 0 {
        // This should never happen in valid SSS usage
        // Return 0 to avoid panic in production
        return 0;
    }
    let a_i = a as i64;
    let p_i = P as i64;
    let (g, x, _) = egcd(a_i, p_i);
    if g != 1 {
        // Should not happen for prime P and 0 < a < P
        return 0;
    }
    let mut inv = x % p_i;
    if inv < 0 {
        inv += p_i;
    }
    inv as u16
}

/// Encode a u16 field element (0..256) as 2 bytes (little-endian)
fn encode_field_element(val: u16) -> [u8; 2] {
    [val as u8, (val >> 8) as u8]
}

/// Decode a u16 field element from 2 bytes (little-endian)
fn decode_field_element(bytes: &[u8]) -> u16 {
    if bytes.len() < 2 {
        return 0;
    }
    (bytes[0] as u16) | ((bytes[1] as u16) << 8)
}

/// Split secret bytes into n shares with threshold k
///
/// # Arguments
/// * `secret` - The secret bytes to split
/// * `n` - Number of shares to generate (1..=255)
/// * `k` - Threshold for reconstruction (2..=n)
///
/// # Returns
/// Vec of (share_index, share_bytes) where share_index is 1..=n
/// Each share_bytes has length = 2 * secret.len() (2 bytes per field element)
///
/// # Errors
/// Returns error if k < 2, k > n, or n == 0
pub fn split_secret(secret: &[u8], n: u8, k: u8) -> anyhow::Result<Vec<(u8, Vec<u8>)>> {
    if k < 2 {
        anyhow::bail!("threshold k must be at least 2");
    }
    if k > n {
        anyhow::bail!("threshold k cannot exceed n");
    }
    if n == 0 {
        anyhow::bail!("n must be greater than 0");
    }

    let mut rng = OsRng;
    // Each share stores 2 bytes per secret byte (to hold field elements 0..256)
    let mut shares: Vec<Vec<u8>> = vec![Vec::with_capacity(secret.len() * 2); n as usize];

    // For each byte of secret, create polynomial of degree k-1
    // with constant term = secret_byte
    for &byte in secret.iter() {
        // coefficients: a0 = byte, a1..a_{k-1} = random in 0..P-1
        let mut coeffs: Vec<u16> = Vec::with_capacity(k as usize);
        coeffs.push(byte as u16); // constant term is the secret byte

        for _ in 1..k {
            // Random coefficient in 0..256 (full field range)
            coeffs.push((rng.next_u32() % (P as u32)) as u16);
        }

        // Evaluate polynomial at x = 1, 2, ..., n
        for xi in 1..=n {
            let x = xi as u16;
            // Horner's method: y = a_{k-1}*x^{k-1} + ... + a_1*x + a_0
            let mut y: u16 = 0;
            for c in coeffs.iter().rev() {
                y = mul(y, x);
                y = add(y, *c);
            }
            // y is in range 0..256, encode as 2 bytes
            let encoded = encode_field_element(y);
            shares[(xi - 1) as usize].push(encoded[0]);
            shares[(xi - 1) as usize].push(encoded[1]);
        }
    }

    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        out.push((i + 1, shares[i as usize].clone()));
    }
    Ok(out)
}

/// Recover secret from k shares using Lagrange interpolation
///
/// # Arguments
/// * `shares` - Slice of (share_index, share_bytes) tuples
///
/// # Returns
/// The reconstructed secret bytes
///
/// # Errors
/// Returns error if shares is empty or shares have inconsistent lengths
pub fn recover_secret(shares: &[(u8, Vec<u8>)]) -> anyhow::Result<Vec<u8>> {
    let k = shares.len();
    if k == 0 {
        anyhow::bail!("no shares provided");
    }

    let share_len = shares[0].1.len();
    
    // Verify all shares have same length
    for (idx, s) in shares.iter().enumerate() {
        if s.1.len() != share_len {
            anyhow::bail!(
                "share {} has length {}, expected {}",
                idx,
                s.1.len(),
                share_len
            );
        }
    }

    // Share length must be even (2 bytes per field element)
    if share_len % 2 != 0 {
        anyhow::bail!("invalid share length: must be even");
    }

    let secret_len = share_len / 2;
    let mut secret = Vec::with_capacity(secret_len);

    // For each byte position, do Lagrange interpolation at x=0
    for idx in 0..secret_len {
        let byte_offset = idx * 2;

        // Compute secret[idx] = sum_j y_j * L_j(0)
        // where L_j(0) = product_{m != j} (0 - x_m) / (x_j - x_m)
        //             = product_{m != j} (-x_m) / (x_j - x_m)
        let mut accum: u16 = 0;

        for j in 0..k {
            let xj = shares[j].0 as u16;
            let yj = decode_field_element(&shares[j].1[byte_offset..byte_offset + 2]);

            // Compute L_j(0) = product_{m != j} (-x_m) / (x_j - x_m)
            let mut num: u16 = 1;
            let mut den: u16 = 1;

            for m in 0..k {
                if m == j {
                    continue;
                }
                let xm = shares[m].0 as u16;

                // num *= -x_m mod P = (P - x_m) mod P
                num = mul(num, (P - xm) % P);

                // den *= (x_j - x_m) mod P
                let diff = if xj >= xm {
                    xj - xm
                } else {
                    P - (xm - xj)
                };
                den = mul(den, diff);
            }

            let den_inv = modinv(den);
            let lj = mul(num, den_inv);
            accum = add(accum, mul(yj, lj));
        }

        // accum is the recovered byte value (should be 0..255)
        if accum > 255 {
            anyhow::bail!(
                "recovered value {} at index {} exceeds byte range",
                accum,
                idx
            );
        }
        secret.push(accum as u8);
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: BASIC ROUNDTRIP
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_roundtrip() {
        let secret = b"this is a secret key";
        let shares = split_secret(secret, 5, 3).expect("split should succeed");

        // Verify share count
        assert_eq!(shares.len(), 5);

        // Verify share indices
        for (i, (idx, _)) in shares.iter().enumerate() {
            assert_eq!(*idx, (i + 1) as u8);
        }

        // Verify share lengths (2 bytes per secret byte)
        for (_, data) in &shares {
            assert_eq!(data.len(), secret.len() * 2);
        }

        // Pick any 3 shares and recover
        let picked = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = recover_secret(&picked).expect("recover should succeed");
        assert_eq!(recovered, secret);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: DIFFERENT SHARE COMBINATIONS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_different_combinations() {
        let secret = b"test secret 123";
        let shares = split_secret(secret, 5, 3).expect("split");

        // Test various 3-share combinations
        let combos = vec![
            vec![0, 1, 2],
            vec![0, 1, 4],
            vec![1, 2, 3],
            vec![2, 3, 4],
            vec![0, 2, 4],
        ];

        for combo in combos {
            let picked: Vec<_> = combo.iter().map(|&i| shares[i].clone()).collect();
            let recovered = recover_secret(&picked).expect("recover");
            assert_eq!(recovered, secret, "failed for combo {:?}", combo);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: MINIMUM THRESHOLD (k=2)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_threshold_2() {
        let secret = b"minimal threshold";
        let shares = split_secret(secret, 3, 2).expect("split");

        let picked = vec![shares[0].clone(), shares[2].clone()];
        let recovered = recover_secret(&picked).expect("recover");
        assert_eq!(recovered, secret);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: ALL BYTE VALUES
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_all_byte_values() {
        // Test with all possible byte values 0-255
        let secret: Vec<u8> = (0u8..=255u8).collect();
        let shares = split_secret(&secret, 5, 3).expect("split");

        let picked = vec![shares[1].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = recover_secret(&picked).expect("recover");
        assert_eq!(recovered, secret);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: EMPTY SECRET
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_empty_secret() {
        let secret: Vec<u8> = vec![];
        let shares = split_secret(&secret, 3, 2).expect("split");

        assert_eq!(shares.len(), 3);
        for (_, data) in &shares {
            assert_eq!(data.len(), 0);
        }

        let picked = vec![shares[0].clone(), shares[1].clone()];
        let recovered = recover_secret(&picked).expect("recover");
        assert!(recovered.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: SINGLE BYTE SECRET
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_single_byte() {
        for byte_val in [0u8, 1, 127, 128, 255] {
            let secret = vec![byte_val];
            let shares = split_secret(&secret, 4, 3).expect("split");

            let picked = vec![shares[0].clone(), shares[1].clone(), shares[3].clone()];
            let recovered = recover_secret(&picked).expect("recover");
            assert_eq!(recovered, secret, "failed for byte value {}", byte_val);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: MAXIMUM SHARES (n=255)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_many_shares() {
        let secret = b"many shares test";
        let shares = split_secret(secret, 10, 5).expect("split");

        assert_eq!(shares.len(), 10);

        // Pick 5 random shares
        let picked = vec![
            shares[0].clone(),
            shares[3].clone(),
            shares[5].clone(),
            shares[7].clone(),
            shares[9].clone(),
        ];
        let recovered = recover_secret(&picked).expect("recover");
        assert_eq!(recovered, secret);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: INVALID PARAMETERS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_invalid_params() {
        let secret = b"test";

        // k < 2
        assert!(split_secret(secret, 5, 1).is_err());

        // k > n
        assert!(split_secret(secret, 3, 5).is_err());

        // n = 0
        assert!(split_secret(secret, 0, 2).is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: EMPTY SHARES RECOVERY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_empty_shares() {
        let shares: Vec<(u8, Vec<u8>)> = vec![];
        assert!(recover_secret(&shares).is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: INCONSISTENT SHARE LENGTHS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_inconsistent_lengths() {
        let shares = vec![
            (1u8, vec![1, 0, 2, 0]),
            (2u8, vec![3, 0]), // different length
        ];
        assert!(recover_secret(&shares).is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: FIELD ELEMENT ENCODING
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_field_element_encoding() {
        // Test encoding/decoding of field elements
        for val in [0u16, 1, 127, 128, 255, 256] {
            let encoded = encode_field_element(val);
            let decoded = decode_field_element(&encoded);
            assert_eq!(decoded, val, "encoding roundtrip failed for {}", val);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: MODULAR ARITHMETIC
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_modular_arithmetic() {
        // Test mul
        assert_eq!(mul(100, 100), (10000 % 257) as u16);
        assert_eq!(mul(256, 2), (512 % 257) as u16);
        assert_eq!(mul(0, 100), 0);

        // Test add
        assert_eq!(add(200, 100), (300 % 257) as u16);
        assert_eq!(add(256, 1), 0);
        assert_eq!(add(0, 0), 0);

        // Test modinv
        for a in 1u16..=10 {
            let inv = modinv(a);
            assert_eq!(mul(a, inv), 1, "modinv failed for {}", a);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: EXACT THRESHOLD
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_exact_threshold() {
        let secret = b"exact threshold test";
        let shares = split_secret(secret, 5, 5).expect("split");

        // Need exactly 5 shares
        let recovered = recover_secret(&shares).expect("recover");
        assert_eq!(recovered, secret);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: LARGE SECRET
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sss_large_secret() {
        // 1KB secret
        let secret: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let shares = split_secret(&secret, 5, 3).expect("split");

        let picked = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = recover_secret(&picked).expect("recover");
        assert_eq!(recovered, secret);
    }
}
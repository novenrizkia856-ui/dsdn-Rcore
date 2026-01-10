use rand::RngCore;
use rand::rngs::OsRng;

/// Field prime - 257 (fits u16). We represent field elements as u16 in 0..=256
const P: u16 = 257;

/// Compute a * b mod P
fn mul(a: u16, b: u16) -> u16 {
    (((a as u32) * (b as u32)) % (P as u32)) as u16
}

/// Compute a + b mod P
fn add(a: u16, b: u16) -> u16 {
    let mut v = a as u32 + b as u32;
    if v >= P as u32 { v -= P as u32; }
    v as u16
}

/// Compute a - b mod P
#[allow(dead_code)]
fn sub(a: u16, b: u16) -> u16 {
    let v = (P as i32 + a as i32 - b as i32) % (P as i32);
    v as u16
}

/// Extended gcd for modular inverse
fn egcd(a: i64, b: i64) -> (i64, i64, i64) {
    if b == 0 { (a, 1, 0) } else {
        let (g, x, y) = egcd(b, a % b);
        (g, y, x - (a / b) * y)
    }
}

/// Modular inverse mod P
fn modinv(a: u16) -> u16 {
    let a_i = a as i64;
    let p_i = P as i64;
    let (g, x, _) = egcd(a_i, p_i);
    if g != 1 { panic!("no inverse for {}", a); }
    let mut inv = (x % p_i) as i64;
    if inv < 0 { inv += p_i; }
    inv as u16
}

/// Split secret bytes into n shares with threshold k
/// returns Vec<(x, share_bytes)>, where x in 1..255
pub fn split_secret(secret: &[u8], n: u8, k: u8) -> anyhow::Result<Vec<(u8, Vec<u8>)>> {
    if k < 2 || k > n { anyhow::bail!("invalid threshold"); }
    if n == 0 { anyhow::bail!("n must > 0"); }

    let mut rng = OsRng;
    let mut shares: Vec<Vec<u8>> = vec![Vec::with_capacity(secret.len()); n as usize];

    // For each byte of secret, create polynomial degree k-1 with constant term = secret_byte
    for &b in secret.iter() {
        // coefficients: a0 = b, a1..a_{k-1} random in 0..P-1
        let mut coeffs: Vec<u16> = Vec::with_capacity(k as usize);
        coeffs.push(b as u16); // constant term
        for _ in 1..k {
            coeffs.push((rng.next_u32() % (P as u32)) as u16);
        }

        // evaluate at x = 1..n
        for xi in 1..=n {
            let x = xi as u16;
            // Horner evaluation
            let mut y = 0u16;
            for c in coeffs.iter().rev() {
                y = mul(y, x);
                y = add(y, *c);
            }
            shares[(xi - 1) as usize].push((y % P) as u8); // safe: y < P
        }
    }

    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        out.push(((i + 1), shares[i as usize].clone()));
    }
    Ok(out)
}

/// Recover secret from k shares. Each share is (x, bytes)
pub fn recover_secret(shares: &[(u8, Vec<u8>)]) -> anyhow::Result<Vec<u8>> {
    let k = shares.len();
    if k == 0 { anyhow::bail!("no shares"); }
    let len = shares[0].1.len();
    // verify all same length
    for s in shares.iter() {
        if s.1.len() != len { anyhow::bail!("inconsistent share lengths"); }
    }

    let mut secret = vec![0u8; len];

    // for each byte position, do Lagrange interpolation over field P
    for idx in 0..len {
        // compute secret = sum_j y_j * l_j(0)
        let mut accum: u16 = 0;
        for j in 0..k {
            let _xj = shares[j].0 as i64;
            let yj = shares[j].1[idx] as u16;

            // compute L_j(0) = product_{m != j} (0 - x_m) / (x_j - x_m)
            // which equals product_{m != j} (-x_m) * inv(x_j - x_m)
            let mut num: u16 = 1;
            let mut den: u16 = 1;
            for m in 0..k {
                if m == j { continue; }
                let xm = shares[m].0 as u16;
                // num *= (P - xm) mod P  -> which is -xm
                num = mul(num, (P - xm) % P);
                // den *= (xj - xm) mod P
                let mut diff = ( (shares[j].0 as i32) - (shares[m].0 as i32) ) % (P as i32);
                if diff < 0 { diff += P as i32; }
                den = mul(den, diff as u16);
            }
            let den_inv = modinv(den);
            let lj = mul(num, den_inv);
            accum = add(accum, mul(yj, lj));
        }
        secret[idx] = (accum % P) as u8;
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sss_roundtrip() {
        let secret = b"this is a secret key";
        let shares = split_secret(secret, 5, 3).expect("split");
        // pick any 3 shares
        let picked = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = recover_secret(&picked).expect("recover");
        assert_eq!(recovered, secret);
    }
}
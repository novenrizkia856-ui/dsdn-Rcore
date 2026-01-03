use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use hex::{encode as hex_encode, decode as hex_decode};
use std::ops::{Add, Sub};
use anyhow::Result;

/// Address is 20 bytes (first 20 bytes of SHA3-512(pubkey))
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn from_bytes(b: [u8; 20]) -> Self { Address(b) }
    pub fn as_bytes(&self) -> &[u8;20] { &self.0 }
    pub fn to_hex(&self) -> String { hex_encode(self.0) }
    pub fn from_hex(s: &str) -> Result<Self, anyhow::Error> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex_decode(s)?;
        if bytes.len() != 20 { anyhow::bail!("invalid address length: {}", bytes.len()); }
        let mut arr = [0u8;20];
        arr.copy_from_slice(&bytes);
        Ok(Address(arr))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}
impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Address").field(&self.to_hex()).finish()
    }
}
impl FromStr for Address {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_hex(s).map_err(|e| e.into())
    }
}

/* --- serde serialize/deserialize for Address as hex string --- */
impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&self.to_hex())
    }
}
impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Address, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        Address::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Hash type: sha3-512 digest wrapper (64 bytes)
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 64]);

impl Hash {
    pub fn from_bytes(b: [u8;64]) -> Self { Hash(b) }
    pub fn as_bytes(&self) -> &[u8;64] { &self.0 }
    pub fn to_hex(&self) -> String { hex_encode(self.0) }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}
impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hash").field(&self.to_hex()).finish()
    }
}

impl FromStr for Hash {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let v = hex_decode(s)?;
        if v.len() != 64 { anyhow::bail!("invalid sha3-512 length"); }
        let mut arr = [0u8;64];
        arr.copy_from_slice(&v);
        Ok(Hash(arr))
    }
}

/* serde impls for Hash as hex string */
impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&self.to_hex())
    }
}
impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Hash, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        Hash::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Amount newtype (smallest units). 8 decimals scale factor defined in LIB constants.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Amount(pub u128);

impl Amount {
    pub fn new_raw(v: u128) -> Self { Amount(v) }
    pub fn zero() -> Self { Amount(0u128) }
    pub fn as_u128(&self) -> u128 { self.0 }
    pub fn checked_add(self, rhs: Amount) -> Option<Amount> { self.0.checked_add(rhs.0).map(Amount) }
    pub fn checked_sub(self, rhs: Amount) -> Option<Amount> { self.0.checked_sub(rhs.0).map(Amount) }
}

impl Add for Amount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output { Amount(self.0 + rhs.0) }
}
impl Sub for Amount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output { Amount(self.0 - rhs.0) }
}

/* Implement serde for Amount simply */
impl Serialize for Amount {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_u128(self.0)
    }
}
impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Amount, D::Error>
    where D: Deserializer<'de> {
        let v = u128::deserialize(deserializer)?;
        Ok(Amount(v))
    }
}

/// exposed constants for tokenomics
pub const DECIMALS: u32 = 8;
pub const SCALE: u128 = 10u128.pow(DECIMALS);
pub const MAX_SUPPLY: u128 = 300_000_000u128 * SCALE;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn amount_checked_ops() {
        let a = Amount::new_raw(100);
        let b = Amount::new_raw(50);
        assert_eq!(a.checked_add(b).unwrap().as_u128(), 150u128);
        assert_eq!(a.checked_sub(b).unwrap().as_u128(), 50u128);
    }

    #[test]
    fn address_from_pubkey_deterministic() {
        let (pk, _sk) = crypto::generate_ed25519_keypair_bytes();
        let addr1 = crypto::address_from_pubkey_bytes(&pk).expect("address");
        let addr2 = crypto::address_from_pubkey_bytes(&pk).expect("address2");
        assert_eq!(addr1, addr2);
        assert_eq!(addr1.to_hex().len(), 40);
    }
}

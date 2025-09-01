//! Minimal BIP-32 helper functions:
//! - point(p):    scalar -> EC point (public key) on secp256k1
//! - serP(P):     compressed SEC1 (33 bytes)
//! - ser32(i):    big-endian u32 (4 bytes)
//! - ser256(p):   big-endian 256-bit integer (32 bytes)

use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::bip32::error::Bip32Error;

/// point(p): compute P = p * G as a secp256k1 public key.
///
/// `p` must be a 32-byte big-endian scalar in [1, n-1].
pub fn point(p: &[u8; 32]) -> Result<PublicKey, Bip32Error> {
  let sk = SecretKey::from_byte_array(*p).map_err(|_| Bip32Error::InvalidSecretKey)?;
  // Only a verification context is needed to derive a public key.
  let secp = Secp256k1::new();
  Ok(PublicKey::from_secret_key(&secp, &sk))
}

/// serP(P): compressed SEC1 encoding of a public key (33 bytes, 0x02/0x03 + X)
pub fn ser_p(pk: &PublicKey) -> [u8; 33] {
  pk.serialize() // `serialize()` returns compressed by default
}

/// ser32(i): 4-byte big-endian serialization of a 32-bit integer
pub fn ser32(i: u32) -> [u8; 4] {
  i.to_be_bytes()
}

/// ser256(p): 32-byte big-endian serialization of a nonnegative integer `p`.
///
/// Accepts any-length big-endian byte string up to 32 bytes and left-pads with zeros to 32.
/// Returns an error if `p` would not fit in 32 bytes.
pub fn ser256(p_be: &[u8]) -> Result<[u8; 32], Bip32Error> {
  if p_be.len() > 32 {
    return Err(Bip32Error::IntegerTooLarge);
  }
  let mut out = [0u8; 32];
  let start = 32 - p_be.len();
  out[start..].copy_from_slice(p_be);
  Ok(out)
}

fn hash160(data: &[u8]) -> [u8; 20] {
  let mut sha = Sha256::new();
  sha.update(data);
  let mid = sha.finalize();

  let mut rip = Ripemd160::new();
  rip.update(mid);
  let out = rip.finalize();
  let mut r = [0u8; 20];
  r.copy_from_slice(&out);
  r
}

pub fn fingerprint_from_pub(pk: &PublicKey) -> [u8; 4] {
  let h160 = hash160(&ser_p(pk));
  [h160[0], h160[1], h160[2], h160[3]]
}

#[cfg(test)]
mod tests {
  use super::*;
  use hex::ToHex;

  #[test]
  fn test_ser32() {
    assert_eq!(ser32(0xDEAD_BEEF), [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(ser32(0), [0, 0, 0, 0]);
    assert_eq!(ser32(1), [0, 0, 0, 1]);
  }

  #[test]
  fn test_ser256() {
    // 0x01 -> 31 zeros + 01
    let s = ser256(&[0x01]).unwrap();
    assert_eq!(s[0..31], [0u8; 31]);
    assert_eq!(s[31], 1);

    // already 32 bytes
    let thirty_two = [0x11u8; 32];
    assert_eq!(ser256(&thirty_two).unwrap(), thirty_two);

    // too large
    assert!(matches!(ser256(&[0; 33]), Err(Bip32Error::IntegerTooLarge)));
  }

  #[test]
  fn test_point_and_ser_p() {
    // Private key = 1 (valid). Resulting public key is generator G.
    let mut sk = [0u8; 32];
    sk[31] = 1;
    let pk = point(&sk).unwrap();

    let enc = ser_p(&pk);
    assert_eq!(enc.len(), 33);
    // Compressed point starts with 0x02 or 0x03 depending on Y parity.
    assert!(enc[0] == 0x02 || enc[0] == 0x03);

    // X coordinate is nonzero; just sanity-check not all zeroes
    assert!(enc[1..].iter().any(|&b| b != 0));

    // Optional: print for visual inspection
    eprintln!("G (compressed) = {}", enc.encode_hex::<String>());
  }
}

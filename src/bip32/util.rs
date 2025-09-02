use ripemd::Ripemd160;
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

/// serP(P): compressed SEC1 encoding of a public key (33 bytes, 0x02/0x03 + X)
pub fn ser_p(pk: &PublicKey) -> [u8; 33] {
  pk.serialize() // `serialize()` returns compressed by default
}

/// ser32(i): 4-byte big-endian serialization of a 32-bit integer
pub fn ser32(i: u32) -> [u8; 4] {
  i.to_be_bytes()
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

/// first four bytes of Ripemd160(Sha256(serP(pk)))
pub fn fingerprint_from_pub(pk: &PublicKey) -> [u8; 4] {
  let h160 = hash160(&ser_p(pk));
  [h160[0], h160[1], h160[2], h160[3]]
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_ser32() {
    assert_eq!(ser32(0xDEAD_BEEF), [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(ser32(0), [0, 0, 0, 0]);
    assert_eq!(ser32(1), [0, 0, 0, 1]);
  }
}

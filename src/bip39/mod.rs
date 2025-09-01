//! BIP-39: Seed derivation from a mnemonic sentence.
//!
//! Seed = PBKDF2-HMAC-SHA512(password=mnemonic_nfkd, salt="mnemonic" + passphrase_nfkd, c=2048, dkLen=64)
//!
//! Notes:
//! - We apply NFKD to both mnemonic and passphrase.
//! - We also normalize whitespace in the mnemonic to single ASCII spaces,
//!   which handles arbitrary Unicode whitespace safely.

use sha2::Sha512;
use unicode_normalization::UnicodeNormalization;

/// Normalize the mnemonic per BIP-39:
/// - NFKD normalization
/// - collapse all Unicode whitespace to single ASCII spaces
fn normalize_mnemonic(mnemonic: &str) -> String {
  mnemonic
    .nfkd()
    .collect::<String>()
    .split_whitespace()
    .collect::<Vec<_>>()
    .join(" ")
}

/// NFKD for the passphrase (no whitespace collapsing)
fn normalize_passphrase(passphrase: &str) -> String {
  passphrase.nfkd().collect::<String>()
}

/// Derive the 64-byte seed from a BIP-39 mnemonic and optional passphrase.
///
/// `passphrase` may be empty ("").
///
/// This function does **not** validate that the mnemonic is in a wordlist or that
/// its checksum/entropy length is valid; it only implements the seed derivation step.
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
  let m_norm = normalize_mnemonic(mnemonic);
  let p_norm = normalize_passphrase(passphrase);
  let mut seed = [0u8; 64];
  let salt = String::from("mnemonic") + &p_norm;
  pbkdf2::pbkdf2_hmac::<Sha512>(m_norm.as_bytes(), salt.as_bytes(), 2048, &mut seed);
  seed
}

/* ----------------------------- Tests ----------------------------- */
#[cfg(test)]
mod tests {
  use super::*;
  use hex::ToHex;

  // Helper to get lowercase hex string for asserts
  fn hex_seed(m: &str, p: &str) -> String {
    mnemonic_to_seed(m, p).encode_hex::<String>()
  }

  // Vector 1 (BIP-39): "abandon ... about", passphrase TREZOR
  // Expected seed:
  // c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553
  // 1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
  #[test]
  fn bip39_vector1_trezor() {
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let s = hex_seed(m, "TREZOR");
    assert_eq!(
            s,
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
  }

  // Vector 2 (BIP-39): "legal winner thank year wave sausage worth useful legal winner thank yellow", passphrase TREZOR
  // Expected seed:
  // 2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f
  // a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607
  #[test]
  fn bip39_vector2_trezor() {
    let m = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let s = hex_seed(m, "TREZOR");
    assert_eq!(
            s,
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
        );
  }

  // Vector 3 (BIP-39): "letter advice cage absurd amount doctor acoustic avoid letter advice cage above", passphrase TREZOR
  // Expected seed:
  // d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30
  // fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8
  #[test]
  fn bip39_vector3_trezor() {
    let m = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    let s = hex_seed(m, "TREZOR");
    assert_eq!(
            s,
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"
        );
  }

  // Whitespace robustness: leading/trailing/multiple spaces must not change the seed.
  #[test]
  fn whitespace_collapses() {
    let m1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let m2 = "  abandon   abandon abandon\tabandon\nabandon abandon abandon abandon abandon abandon abandon about  ";
    assert_eq!(hex_seed(m1, ""), hex_seed(m2, ""));
  }

  // Empty passphrase is valid; salt is just "mnemonic".
  #[test]
  fn empty_passphrase() {
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let _seed = mnemonic_to_seed(m, "");
    // Smoke test: consistent length and deterministic
    assert_eq!(_seed.len(), 64);
    assert_eq!(_seed, mnemonic_to_seed(m, ""));
  }
}

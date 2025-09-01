//! BIP-39: Seed derivation from a mnemonic sentence.
//!
//! Seed = PBKDF2-HMAC-SHA512(password=mnemonic_nfkd, salt="mnemonic" + passphrase_nfkd, c=2048, dkLen=64)
//!
//! Notes:
//! - We apply NFKD to both mnemonic and passphrase.
//! - We also normalize whitespace in the mnemonic to single ASCII spaces,
//!   which handles arbitrary Unicode whitespace safely.

use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;

const WORDLIST: &str = include_str!("../bip39wordlist.txt");

fn checksum_bits(ms_length: usize) -> usize {
  // CS in bits
  ms_length / 3
}

fn entropy_bits(ms_length: usize) -> usize {
  // ENT in bits
  32 * ms_length / 3
}

fn entropy_bytes(ms_length: usize) -> usize {
  // ENT in bytes (always byte-aligned)
  entropy_bits(ms_length) / 8
}

/// Split a big-endian bitstream into 11-bit indices (0..=2047), MSB-first,
/// consuming exactly `total_bits` from `bytes`.
fn bitstream_to_11_bit_indices(stream: &[u8], total_bits: usize) -> Vec<usize> {
  debug_assert!(total_bits % 11 == 0);
  debug_assert!(total_bits <= stream.len() * 8);

  let n = total_bits / 11;
  let mut out = Vec::with_capacity(n);
  let mut buf: u32 = 0;
  let mut buf_bits: usize = 0;
  let mut remaining_bits = total_bits;

  for &b in stream {
    if remaining_bits == 0 {
      break;
    }
    let take = remaining_bits.min(8);
    let top = (b >> (8 - take)) as u32;
    buf = (buf << take) | top;
    buf_bits += take;
    remaining_bits -= take;

    while buf_bits >= 11 {
      let shift = buf_bits - 11;
      let idx = ((buf >> shift) & 0x7FF) as usize;
      out.push(idx);
      buf &= if shift == 0 { 0 } else { (1u32 << shift) - 1 };
      buf_bits -= 11;
    }
  }
  debug_assert_eq!(remaining_bits, 0);
  debug_assert_eq!(buf_bits, 0);

  out
}

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

fn random_mnemonic_sentence_from_entropy(ms_length: usize, entropy: Option<Vec<u8>>) -> String {
  let entropy_len = entropy_bytes(ms_length);
  let entropy = entropy.unwrap_or_else(|| {
    let mut v = vec![0u8; entropy_len];
    getrandom::fill(&mut v).expect("failed to generate entropy");
    v
  });
  debug_assert!((12..=24).contains(&ms_length) && ms_length % 3 == 0);
  debug_assert_eq!(entropy.len(), entropy_len);

  let mut stream = Vec::with_capacity(entropy_len + 1); // Entropy + single checksum byte
  let hash = Sha256::digest(&entropy);
  stream.extend_from_slice(&entropy);
  stream.push(*hash.first().expect("sha256 returns at least one byte"));

  let total_bits = entropy_bits(ms_length) + checksum_bits(ms_length);
  let word_idxs = bitstream_to_11_bit_indices(&stream, total_bits);

  let word_list: Vec<_> = WORDLIST.split('\n').collect();
  word_idxs
    .into_iter()
    .map(|idx| *word_list.get(idx).expect("word list long enough"))
    .collect::<Vec<_>>()
    .join(" ")
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

/// Generate a random BIP-39 mnemonic sentence with a given length.
/// The length must be 12, 15, 18, 21, or 24 words.
pub fn random_mnemonic_sentence(ms_length: usize) -> String {
  random_mnemonic_sentence_from_entropy(ms_length, None)
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

  #[test]
  fn entropy_to_mnemonic_12_1() {
    let ms_length = 12;
    let entropy = vec![0x00u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
  }

  #[test]
  fn entropy_to_mnemonic_12_2() {
    let ms_length = 12;
    let entropy = vec![0x7fu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "legal winner thank year wave sausage worth useful legal winner thank yellow"
    );
  }

  #[test]
  fn entropy_to_mnemonic_12_3() {
    let ms_length = 12;
    let entropy = vec![0x80u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
    );
  }

  #[test]
  fn entropy_to_mnemonic_12_4() {
    let ms_length = 12;
    let entropy = vec![0xffu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
  }

  #[test]
  fn entropy_to_mnemonic_12_5() {
    let ms_length = 12;
    let entropy = vec![
      0x9e, 0x88, 0x5d, 0x95, 0x2a, 0xd3, 0x62, 0xca, 0xeb, 0x4e, 0xfe, 0x34, 0xa8, 0xe9, 0x1b,
      0xd2,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
    );
  }

  #[test]
  fn entropy_to_mnemonic_12_6() {
    let ms_length = 12;
    let entropy = vec![
      0xc0, 0xba, 0x5a, 0x8e, 0x91, 0x41, 0x11, 0x21, 0x0f, 0x2b, 0xd1, 0x31, 0xf3, 0xd5, 0xe0,
      0x8d,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "scheme spot photo card baby mountain device kick cradle pact join borrow"
    );
  }

  #[test]
  fn entropy_to_mnemonic_12_7() {
    let ms_length = 12;
    let entropy = vec![
      0x23, 0xdb, 0x81, 0x60, 0xa3, 0x1d, 0x3e, 0x0d, 0xca, 0x36, 0x88, 0xed, 0x94, 0x1a, 0xdb,
      0xf3,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "cat swing flag economy stadium alone churn speed unique patch report train"
    );
  }

  #[test]
  fn entropy_to_mnemonic_12_8() {
    let ms_length = 12;
    let entropy = vec![
      0xf3, 0x0f, 0x8c, 0x1d, 0xa6, 0x65, 0x47, 0x8f, 0x49, 0xb0, 0x01, 0xd9, 0x4c, 0x5f, 0xc4,
      0x52,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "vessel ladder alter error federal sibling chat ability sun glass valve picture"
    );
  }

  #[test]
  fn entropy_to_mnemonic_18_1() {
    let ms_length = 18;
    let entropy = vec![0x00u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent");
  }

  #[test]
  fn entropy_to_mnemonic_18_2() {
    let ms_length = 18;
    let entropy = vec![0x7fu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will");
  }

  #[test]
  fn entropy_to_mnemonic_18_3() {
    let ms_length = 18;
    let entropy = vec![0x80u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always");
  }

  #[test]
  fn entropy_to_mnemonic_18_4() {
    let ms_length = 18;
    let entropy = vec![0xffu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when"
    );
  }

  #[test]
  fn entropy_to_mnemonic_18_5() {
    let ms_length = 18;
    let entropy = vec![
      0x66, 0x10, 0xb2, 0x59, 0x67, 0xcd, 0xcc, 0xa9, 0xd5, 0x98, 0x75, 0xf5, 0xcb, 0x50, 0xb0,
      0xea, 0x75, 0x43, 0x33, 0x11, 0x86, 0x9e, 0x93, 0x0b,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(
      ms,
      "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog"
    );
  }

  #[test]
  fn entropy_to_mnemonic_18_6() {
    let ms_length = 18;
    let entropy = vec![
      0x6d, 0x9b, 0xe1, 0xee, 0x6e, 0xbd, 0x27, 0xa2, 0x58, 0x11, 0x5a, 0xad, 0x99, 0xb7, 0x31,
      0x7b, 0x9c, 0x8d, 0x28, 0xb6, 0xd7, 0x64, 0x31, 0xc3,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave");
  }

  #[test]
  fn entropy_to_mnemonic_18_7() {
    let ms_length = 18;
    let entropy = vec![
      0x81, 0x97, 0xa4, 0xa4, 0x7f, 0x04, 0x25, 0xfa, 0xea, 0xa6, 0x9d, 0xee, 0xbc, 0x05, 0xca,
      0x29, 0xc0, 0xa5, 0xb5, 0xcc, 0x76, 0xce, 0xac, 0xc0,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access");
  }

  #[test]
  fn entropy_to_mnemonic_18_8() {
    let ms_length = 18;
    let entropy = vec![
      0xc1, 0x0e, 0xc2, 0x0d, 0xc3, 0xcd, 0x9f, 0x65, 0x2c, 0x7f, 0xac, 0x2f, 0x12, 0x30, 0xf7,
      0xa3, 0xc8, 0x28, 0x38, 0x9a, 0x14, 0x39, 0x2f, 0x05,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump");
  }

  #[test]
  fn entropy_to_mnemonic_24_1() {
    let ms_length = 24;
    let entropy = vec![0x00u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art");
  }

  #[test]
  fn entropy_to_mnemonic_24_2() {
    let ms_length = 24;
    let entropy = vec![0x7fu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title");
  }

  #[test]
  fn entropy_to_mnemonic_24_3() {
    let ms_length = 24;
    let entropy = vec![0x80u8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless");
  }

  #[test]
  fn entropy_to_mnemonic_24_4() {
    let ms_length = 24;
    let entropy = vec![0xffu8; entropy_bytes(ms_length)];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote");
  }

  #[test]
  fn entropy_to_mnemonic_24_5() {
    let ms_length = 24;
    let entropy = vec![
      0x68, 0xa7, 0x9e, 0xac, 0xa2, 0x32, 0x48, 0x73, 0xea, 0xcc, 0x50, 0xcb, 0x9c, 0x6e, 0xca,
      0x8c, 0xc6, 0x8e, 0xa5, 0xd9, 0x36, 0xf9, 0x87, 0x87, 0xc6, 0x0c, 0x7e, 0xbc, 0x74, 0xe6,
      0xce, 0x7c,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length");
  }

  #[test]
  fn entropy_to_mnemonic_24_6() {
    let ms_length = 24;
    let entropy = vec![
      0x9f, 0x6a, 0x28, 0x78, 0xb2, 0x52, 0x07, 0x99, 0xa4, 0x4e, 0xf1, 0x8b, 0xc7, 0xdf, 0x39,
      0x4e, 0x70, 0x61, 0xa2, 0x24, 0xd2, 0xc3, 0x3c, 0xd0, 0x15, 0xb1, 0x57, 0xd7, 0x46, 0x86,
      0x98, 0x63,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside");
  }

  #[test]
  fn entropy_to_mnemonic_24_7() {
    let ms_length = 24;
    let entropy = vec![
      0x06, 0x6d, 0xca, 0x1a, 0x2b, 0xb7, 0xe8, 0xa1, 0xdb, 0x28, 0x32, 0x14, 0x8c, 0xe9, 0x93,
      0x3e, 0xea, 0x0f, 0x3a, 0xc9, 0x54, 0x8d, 0x79, 0x31, 0x12, 0xd9, 0xa9, 0x5c, 0x94, 0x07,
      0xef, 0xad,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform");
  }

  #[test]
  fn entropy_to_mnemonic_24_8() {
    let ms_length = 24;
    let entropy = vec![
      0xf5, 0x85, 0xc1, 0x1a, 0xec, 0x52, 0x0d, 0xb5, 0x7d, 0xd3, 0x53, 0xc6, 0x95, 0x54, 0xb2,
      0x1a, 0x89, 0xb2, 0x0f, 0xb0, 0x65, 0x09, 0x66, 0xfa, 0x0a, 0x9d, 0x6f, 0x74, 0xfd, 0x98,
      0x9d, 0x8f,
    ];
    let ms = random_mnemonic_sentence_from_entropy(ms_length, Some(entropy));
    assert_eq!(ms, "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold");
  }
}

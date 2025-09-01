//! BIP-32 (HD keys) for secp256k1.
//!
//! Features:
//! - Master key from seed
//! - CKDpriv (hardened & normal) and CKDpub (normal only)
//! - xprv/xpub Base58Check serialization (mainnet & testnet)
//! - Small path parser: e.g. "m/0h/1/2'/2"
//!
//! This aims to be concise and readable while following BIP-32.
//! For production, add more tests (BIP-32 vectors), decoding, and robust error handling.

mod error;
mod util;

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

use sha2::Sha512;

use crate::bip32::error::Bip32Error;

type HmacSha512 = Hmac<Sha512>;

pub const HARDENED_OFFSET: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug)]
pub enum Network {
  Mainnet,
  Testnet,
}

impl Network {
  fn versions(self) -> (u32, u32) {
    match self {
      // xpub/xprv
      Network::Mainnet => (0x0488_B21E, 0x0488_ADE4),
      // tpub/tprv
      Network::Testnet => (0x0435_87CF, 0x0435_8394),
    }
  }
}

fn decode_versions(v: u32) -> Result<(Network, bool /*is_pub*/), Bip32Error> {
  match v {
    0x0488_B21E => Ok((Network::Mainnet, true)),  // xpub
    0x0488_ADE4 => Ok((Network::Mainnet, false)), // xprv
    0x0435_87CF => Ok((Network::Testnet, true)),  // tpub
    0x0435_8394 => Ok((Network::Testnet, false)), // tprv
    _ => Err(Bip32Error::BadVersion),
  }
}

#[derive(Clone)]
pub struct ExtendedPrivKey {
  pub depth: u8,
  pub parent_fingerprint: [u8; 4],
  pub child_number: u32,
  pub chain_code: [u8; 32],
  pub secret_key: SecretKey,
}

#[derive(Clone)]
pub struct ExtendedPubKey {
  pub depth: u8,
  pub parent_fingerprint: [u8; 4],
  pub child_number: u32,
  pub chain_code: [u8; 32],
  pub public_key: PublicKey, // compressed
}

/* --------------------- Master key from seed ---------------------- */

impl ExtendedPrivKey {
  /// Create master extended private key from seed (BIP-32).
  /// I = HMAC-SHA512(key="Bitcoin seed", data=seed)
  /// master secret = I_L, master chain code = I_R
  pub fn master(seed: &[u8]) -> Result<Self, Bip32Error> {
    let mut mac =
      HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC can take key of any size");
    mac.update(seed);
    let i = mac.finalize().into_bytes(); // 64 bytes

    let mut il = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    let mut ir = [0u8; 32];
    ir.copy_from_slice(&i[32..]);

    let sk = SecretKey::from_byte_array(il).map_err(|_| Bip32Error::InvalidSeed)?;
    Ok(ExtendedPrivKey {
      depth: 0,
      parent_fingerprint: [0u8; 4],
      child_number: 0,
      chain_code: ir,
      secret_key: sk,
    })
  }

  /// Derive a child private key (CKDpriv) at index `i`.
  /// Hardened if i >= HARDENED_OFFSET.
  pub fn ckd_priv(&self, i: u32) -> Result<Self, Bip32Error> {
    // Data = (0x00 || ser256(k_par) || ser32(i)) for hardened
    //      = (serP(K_par)     || ser32(i))       for normal
    let secp = Secp256k1::new();

    let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("HMAC key");
    if i >= HARDENED_OFFSET {
      let mut data = [0u8; 1 + 32 + 4];
      data[0] = 0x00;
      data[1..33].copy_from_slice(&self.secret_key.secret_bytes());
      data[33..].copy_from_slice(&util::ser32(i));
      mac.update(&data);
    } else {
      let parent_pub = PublicKey::from_secret_key(&secp, &self.secret_key);
      let mut data = [0u8; 33 + 4];
      data[..33].copy_from_slice(&util::ser_p(&parent_pub));
      data[33..].copy_from_slice(&util::ser32(i));
      mac.update(&data);
    }
    let i64 = mac.finalize().into_bytes();

    let mut il = [0u8; 32];
    il.copy_from_slice(&i64[..32]);
    let mut ir = [0u8; 32];
    ir.copy_from_slice(&i64[32..]);

    // If parse(I_L) ∉ [1, n-1] or (I_L + k_par) == 0 mod n -> invalid child
    // Use add_assign which checks range and zero result.
    // First ensure I_L is a valid scalar; this also rejects zero/≥n.
    let tweak = Scalar::from_be_bytes(il).map_err(|_| Bip32Error::InvalidChildKey)?;
    let sk = self
      .secret_key
      .add_tweak(&tweak)
      .map_err(|_| Bip32Error::InvalidChildKey)?;

    // Build child
    let parent_pub = PublicKey::from_secret_key(&secp, &self.secret_key);
    Ok(ExtendedPrivKey {
      depth: self.depth + 1,
      parent_fingerprint: util::fingerprint_from_pub(&parent_pub),
      child_number: i,
      chain_code: ir,
      secret_key: sk,
    })
  }

  /// Get the corresponding extended public key.
  pub fn to_xpub(&self) -> ExtendedPubKey {
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, &self.secret_key);
    ExtendedPubKey {
      depth: self.depth,
      parent_fingerprint: self.parent_fingerprint,
      child_number: self.child_number,
      chain_code: self.chain_code,
      public_key: pubkey,
    }
  }

  /// Serialize to Base58 (xprv/tprv) for `network`.
  pub fn to_base58(&self, network: Network) -> String {
    let (_xpub, xprv) = network.versions();
    let mut payload = [0u8; 78];
    payload[..4].copy_from_slice(&xprv.to_be_bytes());
    payload[4] = self.depth;
    payload[5..9].copy_from_slice(&self.parent_fingerprint);
    payload[9..13].copy_from_slice(&util::ser32(self.child_number));
    payload[13..45].copy_from_slice(&self.chain_code);
    // key data: 0x00 + ser256(k)
    payload[45] = 0;
    payload[46..78].copy_from_slice(&self.secret_key.secret_bytes());

    bs58::encode(payload).with_check().into_string()
  }
}

impl ExtendedPubKey {
  /// CKDpub for non-hardened indices.
  pub fn ckd_pub(&self, i: u32) -> Result<Self, Bip32Error> {
    if i >= HARDENED_OFFSET {
      return Err(Bip32Error::HardenedFromPublic);
    }
    // Data = serP(K_par) || ser32(i)
    let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("HMAC key");
    let mut data = [0u8; 33 + 4];
    data[..33].copy_from_slice(&util::ser_p(&self.public_key));
    data[33..].copy_from_slice(&util::ser32(i));
    mac.update(&data);
    let i64 = mac.finalize().into_bytes();

    let mut il = [0u8; 32];
    il.copy_from_slice(&i64[..32]);
    let mut ir = [0u8; 32];
    ir.copy_from_slice(&i64[32..]);

    // Tweak-add: K_child = K_par + I_L*G
    let secp = Secp256k1::new();
    let tweak = Scalar::from_be_bytes(il).map_err(|_| Bip32Error::InvalidChildKey)?;
    let child_pk = self
      .public_key
      .add_exp_tweak(&secp, &tweak)
      .map_err(|_| Bip32Error::InvalidChildKey)?;

    Ok(ExtendedPubKey {
      depth: self.depth + 1,
      parent_fingerprint: util::fingerprint_from_pub(&self.public_key),
      child_number: i,
      chain_code: ir,
      public_key: child_pk,
    })
  }

  /// Serialize to Base58 (xpub/tpub) for `network`.
  pub fn to_base58(&self, network: Network) -> String {
    let (xpub, _xprv) = network.versions();
    let mut payload = [0u8; 78];
    payload[..4].copy_from_slice(&xpub.to_be_bytes());
    payload[4] = self.depth;
    payload[5..9].copy_from_slice(&self.parent_fingerprint);
    payload[9..13].copy_from_slice(&util::ser32(self.child_number));
    payload[13..45].copy_from_slice(&self.chain_code);
    payload[45..78].copy_from_slice(&util::ser_p(&self.public_key));

    bs58::encode(payload).with_check().into_string()
  }
}

/* --------------------- Convenience: path derivation --------------------- */

/// A single path element (index + hardened bit)
#[derive(Clone, Copy, Debug)]
pub struct ChildNumber {
  pub index: u32, // full value, including hardened bit if set
}
impl ChildNumber {
  pub fn new(index: u32, hardened: bool) -> Self {
    let v = if hardened {
      index | HARDENED_OFFSET
    } else {
      index
    };
    ChildNumber { index: v }
  }
  pub fn is_hardened(&self) -> bool {
    self.index >= HARDENED_OFFSET
  }
  pub fn number(&self) -> u32 {
    self.index
  }
}

fn append_child_number(elem: &str, out: &mut Vec<ChildNumber>) -> Result<(), Bip32Error> {
  if elem.is_empty() {
    return Err(Bip32Error::BadPath);
  }
  let hardened = elem.ends_with('\'') || elem.ends_with('h') || elem.ends_with('H');
  let num_str = if hardened {
    &elem[..elem.len() - 1]
  } else {
    elem
  };
  let n: u32 = num_str.parse().map_err(|_| Bip32Error::BadPath)?;
  if n >= HARDENED_OFFSET {
    return Err(Bip32Error::BadPath);
  }
  out.push(ChildNumber::new(n, hardened));
  Ok(())
}

/// Parse "m/0h/1/2'/2" -> Vec<ChildNumber>
pub fn parse_path(s: &str) -> Result<Vec<ChildNumber>, Bip32Error> {
  let s = s.trim();
  if s.is_empty() {
    return Err(Bip32Error::BadPath);
  }
  let mut path_comps = s.split('/');
  let first = path_comps.next().ok_or(Bip32Error::BadPath)?;
  let mut out = Vec::new();
  if first != "m" && first != "M" {
    append_child_number(first, &mut out)?;
  }
  for elem in path_comps {
    append_child_number(elem, &mut out)?;
  }
  Ok(out)
}

/// Derive an extended private key along a path from a master key.
pub fn derive_priv_from_path(
  xprv: &ExtendedPrivKey,
  path: &[ChildNumber],
) -> Result<ExtendedPrivKey, Bip32Error> {
  let mut xprv = xprv.clone();
  for cn in path {
    xprv = xprv.ckd_priv(cn.number())?;
  }
  Ok(xprv)
}

/// Derive an extended public key along a (non-hardened) path from an xpub.
pub fn derive_pub_from_path(
  xpub: &ExtendedPubKey,
  path: &[ChildNumber],
) -> Result<ExtendedPubKey, Bip32Error> {
  let mut xpub = xpub.clone();
  for cn in path {
    if cn.is_hardened() {
      return Err(Bip32Error::HardenedFromPublic);
    }
    xpub = xpub.ckd_pub(cn.number())?;
  }
  Ok(xpub)
}

// Parse any extended key; dispatch to xpub/xprv.
pub fn parse_xkey(
  s: &str,
) -> Result<(Option<ExtendedPrivKey>, Option<ExtendedPubKey>, Network), Bip32Error> {
  // 78-byte payload expected after Base58Check
  let data = bs58::decode(s)
    .with_check(None)
    .into_vec()
    .map_err(|_| Bip32Error::InvalidBase58)?;
  if data.len() != 78 {
    return Err(Bip32Error::InvalidBase58);
  }

  let ver = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
  let (network, is_pub) = decode_versions(ver)?;

  let depth = data[4];
  let mut parent_fingerprint = [0u8; 4];
  parent_fingerprint.copy_from_slice(&data[5..9]);
  let child_number = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
  let mut chain_code = [0u8; 32];
  chain_code.copy_from_slice(&data[13..45]);

  // Reject invalid "root" headers per BIP-32
  if depth == 0 && (parent_fingerprint != [0, 0, 0, 0] || child_number != 0) {
    return Err(Bip32Error::InvalidRootFields);
  }

  if is_pub {
    // key data: 33 bytes compressed SEC1
    let pk_bytes: [u8; 33] = data[45..78].try_into().unwrap();
    let public_key = PublicKey::from_slice(&pk_bytes).map_err(|_| Bip32Error::BadKeyData)?;
    let xpub = ExtendedPubKey {
      depth,
      parent_fingerprint,
      child_number,
      chain_code,
      public_key,
    };
    Ok((None, Some(xpub), network))
  } else {
    // key data: 0x00 + 32-byte secret
    if data[45] != 0x00 {
      return Err(Bip32Error::BadKeyData);
    }
    let sk_bytes: [u8; 32] = data[46..78].try_into().unwrap();
    let secret_key = SecretKey::from_byte_array(sk_bytes).map_err(|_| Bip32Error::BadKeyData)?;
    let xprv = ExtendedPrivKey {
      depth,
      parent_fingerprint,
      child_number,
      chain_code,
      secret_key,
    };
    Ok((Some(xprv), None, network))
  }
}

// Convenience wrappers
pub fn parse_xprv(s: &str) -> Result<(ExtendedPrivKey, Network), Bip32Error> {
  match parse_xkey(s)? {
    (Some(xprv), None, net) => Ok((xprv, net)),
    _ => Err(Bip32Error::BadVersion),
  }
}

pub fn parse_xpub(s: &str) -> Result<(ExtendedPubKey, Network), Bip32Error> {
  match parse_xkey(s)? {
    (None, Some(xpub), net) => Ok((xpub, net)),
    _ => Err(Bip32Error::BadVersion),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use hex::FromHex;

  fn derive_to_strings(seed_hex: &str, path: &str) -> (String, String) {
    let seed = Vec::from_hex(seed_hex).expect("seed hex");
    let master = ExtendedPrivKey::master(&seed).expect("master");
    let path_nodes = parse_path(path).expect("path");
    let xprv = derive_priv_from_path(&master, &path_nodes).expect("derive");
    let xpub = xprv.to_xpub();
    (
      xprv.to_base58(Network::Mainnet),
      xpub.to_base58(Network::Mainnet),
    )
  }

  fn assert_pair(seed_hex: &str, path: &str, want_xprv: &str, want_xpub: &str) {
    let (got_xprv, got_xpub) = derive_to_strings(seed_hex, path);
    assert_eq!(got_xprv, want_xprv, "xprv mismatch at {path}");
    assert_eq!(got_xpub, want_xpub, "xpub mismatch at {path}");
    // Also ensure decode->encode round-trip
    let (px, net1) = parse_xprv(&got_xprv).expect("parse xprv");
    let (pu, net2) = parse_xpub(&got_xpub).expect("parse xpub");
    assert!(matches!(net1, Network::Mainnet));
    assert!(matches!(net2, Network::Mainnet));
    assert_eq!(px.to_base58(Network::Mainnet), got_xprv, "xprv re-encode");
    assert_eq!(pu.to_base58(Network::Mainnet), got_xpub, "xpub re-encode");
  }

  #[test]
  fn round_trip_master_and_ckdpriv() {
    // Seed: 16 bytes (demo)
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let m = ExtendedPrivKey::master(&seed).unwrap();
    // Serialize base58 for both networks (not checked against vectors here)
    let _main_xprv = m.to_base58(Network::Mainnet);
    let _test_xprv = m.to_base58(Network::Testnet);

    // Derive m/0h/1/2h/2
    let path = parse_path("m/0h/1/2h/2").unwrap();
    let child = derive_priv_from_path(&m, &path).unwrap();

    // to xpub
    let xpub = child.to_xpub();
    let s = xpub.to_base58(Network::Mainnet);
    assert!(s.starts_with("xpub") || s.starts_with("tpub"));
  }

  #[test]
  fn ckdpub_matches_priv_for_non_hardened() {
    // m -> m/1/2
    let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2").unwrap();
    let m = ExtendedPrivKey::master(&seed).unwrap();
    let m_pub = m.to_xpub();

    let path = parse_path("m/1/2").unwrap();
    let child_priv = derive_priv_from_path(&m, &path).unwrap().to_xpub();
    let child_pub = derive_pub_from_path(&m_pub, &path).unwrap();

    assert_eq!(
      util::ser_p(&child_priv.public_key),
      util::ser_p(&child_pub.public_key)
    );
    assert_eq!(child_priv.chain_code, child_pub.chain_code);
    assert_eq!(child_priv.depth, child_pub.depth);
    assert_eq!(child_priv.child_number, child_pub.child_number);
  }

  #[test]
  fn to_string_examples() {
    let seed = b"any deterministc seed works here";
    let m = ExtendedPrivKey::master(seed).unwrap();
    let xprv = m.to_base58(Network::Mainnet);
    let xpub = m.to_xpub().to_base58(Network::Mainnet);
    // Just smoke-test that the prefixes look right.
    assert!(xprv.starts_with("xprv") && xpub.starts_with("xpub"));
  }

  #[test]
  fn show_derived_strings() {
    // Handy test to print something deterministic when you run `cargo test -- --nocapture`
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let m = ExtendedPrivKey::master(&seed).unwrap();
    let path = parse_path("m/0h/1/2h/2/1000000000").unwrap();
    let child = derive_priv_from_path(&m, &path).unwrap();
    eprintln!("xprv: {}", child.to_base58(Network::Mainnet));
    eprintln!("xpub: {}", child.to_xpub().to_base58(Network::Mainnet));
    // Compare manually with BIP-32 vectors if desired.
  }

  #[test]
  fn roundtrip_xprv_xpub_mainnet() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let m = ExtendedPrivKey::master(&seed).unwrap();
    let xprv_s = m.to_base58(Network::Mainnet);
    let xpub_s = m.to_xpub().to_base58(Network::Mainnet);

    let (xprv2, net1) = parse_xprv(&xprv_s).unwrap();
    let (xpub2, net2) = parse_xpub(&xpub_s).unwrap();

    assert!(matches!(net1, Network::Mainnet));
    assert!(matches!(net2, Network::Mainnet));

    assert_eq!(xprv2.depth, m.depth);
    assert_eq!(xprv2.parent_fingerprint, m.parent_fingerprint);
    assert_eq!(xprv2.child_number, m.child_number);
    assert_eq!(xprv2.chain_code, m.chain_code);
    assert_eq!(xprv2.secret_key.secret_bytes(), m.secret_key.secret_bytes());

    assert_eq!(
      util::ser_p(&xpub2.public_key),
      util::ser_p(&m.to_xpub().public_key)
    );
    assert_eq!(xpub2.depth, m.depth);
    assert_eq!(xpub2.parent_fingerprint, m.parent_fingerprint);
    assert_eq!(xpub2.child_number, m.child_number);
    assert_eq!(xpub2.chain_code, m.chain_code);
  }

  #[test]
  fn rejects_wrong_version() {
    // Corrupt the first byte of an otherwise valid xpub
    let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2").unwrap();
    let m = ExtendedPrivKey::master(&seed).unwrap().to_xpub();
    let mut s = m.to_base58(Network::Mainnet);
    // flip first char; almost certainly breaks version/checksum
    let mut chars: Vec<char> = s.chars().collect();
    chars[0] = if chars[0] == 'x' { 'y' } else { 'x' };
    s = chars.into_iter().collect();
    assert!(parse_xpub(&s).is_err());
  }

  #[test]
  fn testnet_roundtrip_from_vector1_root() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let m = ExtendedPrivKey::master(&seed).unwrap();

    // Encode as testnet
    let tprv = m.to_base58(Network::Testnet);
    let tpub = m.to_xpub().to_base58(Network::Testnet);
    assert!(tprv.starts_with("tprv"));
    assert!(tpub.starts_with("tpub"));

    // Parse back and ensure network + fields round-trip
    let (px, n1) = parse_xprv(&tprv).unwrap();
    let (pu, n2) = parse_xpub(&tpub).unwrap();
    assert!(matches!(n1, Network::Testnet));
    assert!(matches!(n2, Network::Testnet));

    assert_eq!(px.depth, m.depth);
    assert_eq!(px.parent_fingerprint, m.parent_fingerprint);
    assert_eq!(px.child_number, m.child_number);
    assert_eq!(px.chain_code, m.chain_code);
    assert_eq!(px.secret_key.secret_bytes(), m.secret_key.secret_bytes());

    assert_eq!(
      util::ser_p(&pu.public_key),
      util::ser_p(&m.to_xpub().public_key)
    );
    assert_eq!(pu.depth, m.depth);
    assert_eq!(pu.parent_fingerprint, m.parent_fingerprint);
    assert_eq!(pu.child_number, m.child_number);
    assert_eq!(pu.chain_code, m.chain_code);
  }

  #[test]
  fn reject_invalid_root_fields_by_dropping_depth() {
    // Non-root xpub: Vector 1, path m/0'
    let non_root = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";

    // Decode payload (78 bytes), change depth to 0, keep everything else
    let mut bytes = bs58::decode(non_root).with_check(None).into_vec().unwrap();
    assert_eq!(bytes.len(), 78);
    bytes[4] = 0; // depth

    // Re-encode with fresh checksum and ensure parser rejects invalid root header
    let bad = bs58::encode(bytes).with_check().into_string();
    match parse_xpub(&bad) {
      Ok((xpub, network)) => panic!("expected error, got valid xpub {}", xpub.to_base58(network)),
      Err(Bip32Error::InvalidRootFields) => {}
      Err(other) => panic!("expected InvalidRootFields, got {:?}", other),
    }
  }

  // Official test vectors

  /* --------------------- Test Vector 1 --------------------- */
  // Source: BIP-32 spec / bitcoin wiki
  // Seed: 000102030405060708090a0b0c0d0e0f
  #[test]
  fn bip32_vector1() {
    let seed = "000102030405060708090a0b0c0d0e0f";

    // m (root)
    let (m_xprv, m_xpub) = (
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        );
    assert_pair(seed, "m", m_xprv, m_xpub);

    // m/0'
    assert_pair(
            seed, "m/0'",
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        );

    // m/0'/1
    assert_pair(
            seed, "m/0'/1",
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        );

    // m/0'/1/2'/2/1000000000
    assert_pair(
            seed, "m/0'/1/2'/2/1000000000",
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        );
  }

  /* --------------------- Test Vector 2 --------------------- */
  #[test]
  fn bip32_vector2() {
    let seed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    // m
    assert_pair(
            seed, "m",
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        );

    // m/0
    assert_pair(
            seed, "m/0",
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        );

    // m/0/2147483647'
    assert_pair(
            seed, "m/0/2147483647'",
            "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
            "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
        );

    // m/0/2147483647'/1
    assert_pair(
            seed, "m/0/2147483647'/1",
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
            "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
        );

    // m/0/2147483647'/1/2147483646'
    assert_pair(
            seed, "m/0/2147483647'/1/2147483646'",
            "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        );

    // m/0/2147483647'/1/2147483646'/2
    assert_pair(
            seed, "m/0/2147483647'/1/2147483646'/2",
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
        );
  }

  /* --------------------- Test Vector 3 (leading zeros) --------------------- */
  #[test]
  fn bip32_vector3_leading_zeros() {
    let seed = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be";

    // m
    assert_pair(
            seed, "m",
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
            "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
        );

    // m/0'
    assert_pair(
            seed, "m/0'",
            "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
            "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
        );
  }

  /* --------------------- Test Vector 4 (leading zeros) --------------------- */
  #[test]
  fn bip32_vector4_leading_zeros() {
    let seed = "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678";

    // m
    assert_pair(
            seed, "m",
            "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
            "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
        );

    // m/0'
    assert_pair(
            seed, "m/0'",
            "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
            "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
        );

    // m/0'/1'
    assert_pair(
            seed, "m/0'/1'",
            "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
            "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
        );
  }

  /* --------------------- Negative cases from Test Vector 5 --------------------- */
  // These two should be rejected by the current parser (bad key prefixes).
  #[test]
  fn bip32_vector5_invalid_prefixes() {
    // invalid pubkey prefix 04
    let bad_pub = "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn";
    assert!(parse_xpub(bad_pub).is_err());

    // invalid prvkey prefix 04 (first payload byte not 0x00)
    let bad_prv = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ";
    assert!(parse_xprv(bad_prv).is_err());
  }
}

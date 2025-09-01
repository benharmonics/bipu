use std::fmt;

#[derive(Debug)]
pub enum Bip32Error {
  InvalidSecretKey,
  IntegerTooLarge,
  /// I_L out of range for master
  InvalidSeed,
  /// I_L out of range or key addition produced zero
  InvalidChildKey,
  /// tried hardened CKD from public
  HardenedFromPublic,
  /// parse failure
  BadPath,
  /// Base58Check decode failed or payload malformed
  InvalidBase58,
  /// Version prefix not recognized as xpub/xprv/tpub/tprv
  BadVersion,
  /// Key data field malformed (wrong length or invaliid pub/priv key bytes)
  BadKeyData,
  /// BIP-32 requires that depth = 0 (master) implies parent fingerprint = 0 and child number = 0
  InvalidRootFields,
}

impl fmt::Display for Bip32Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    use Bip32Error::*;
    match self {
      InvalidSecretKey => write!(f, "point(P) failed: invalid secret key"),
      IntegerTooLarge => write!(f, "ser256 failed: integer too large"),
      InvalidSeed => write!(f, "invalid seed produced an invalid master key"),
      InvalidChildKey => write!(f, "invalid child key (I_L out of range or zero)"),
      HardenedFromPublic => write!(f, "cannot derive a hardened child from a public key"),
      BadPath => write!(f, "invalid derivation path"),
      InvalidBase58 => write!(f, "base58check decode failed or payload malformed"),
      BadVersion => write!(f, "bad version prefix - must be xpub/xprv/tpub/tprv"),
      BadKeyData => write!(
        f,
        "key data field malformed - wrong length or invalid pub/priv key bytes"
      ),
      InvalidRootFields => write!(f, "bip-32 requires that depth = 0 (master) implies parent fingerprint = 0 and child number = 0")
    }
  }
}


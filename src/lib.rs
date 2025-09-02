mod bip32;
mod bip39;

use anyhow::{anyhow, Context};
use clap::{arg, builder::ValueParser, ArgMatches, Command};

fn run_cmd_bip39_seed_derivation(matches: &ArgMatches) {
  let passphrase: &String = matches
    .get_one("passphrase")
    .expect("valid empty default passphrase");
  let mnemonic: &String = matches
    .get_one("mnemonic")
    .expect("mnemonic should be a required argument");
  let seed = bip39::mnemonic_to_seed(mnemonic, passphrase);
  println!("{}", hex::encode(seed));
}

fn run_cmd_bip32_key_derivation_from_xkey(
  xkey: &str,
  path: &[bip32::ChildNumber],
  showpub: bool,
) -> anyhow::Result<()> {
  match bip32::parse_xkey(xkey).expect("xkey must be validated") {
    (Some(xprv), None, network) => {
      let xprv = bip32::derive_priv_from_path(&xprv, path)
        .map_err(|e| anyhow!("failed to derive from xprv: {e}"))?;
      println!("{}", xprv.to_base58(network));
      if showpub {
        println!("{}", xprv.to_xpub().to_base58(network));
      }
    }
    (None, Some(xpub), network) => {
      let xpub = bip32::derive_pub_from_path(&xpub, path)
        .map_err(|e| anyhow!("failed to derive from xpub: {e}"))?;
      println!("{}", xpub.to_base58(network));
    }
    _ => unreachable!("failed to parse xkey as either xprv or xpub without error"),
  }
  Ok(())
}

fn run_cmd_bip32_key_derivation(matches: &ArgMatches) -> anyhow::Result<()> {
  let path: &String = matches.get_one("path").expect("path should be required");
  let cks = bip32::parse_path(path).map_err(|e| anyhow!("failed to parse path: {e}"))?;
  let showpub = matches.get_flag("showpub");

  // Derive from extended keys starting at any level
  if let Some(xkey) = matches.get_one::<String>("xprv") {
    return run_cmd_bip32_key_derivation_from_xkey(xkey, &cks, showpub);
  }

  let ms_match = matches.get_one::<String>("mnemonic");
  let seed_match = matches.get_one::<String>("seed");
  let seed = match (ms_match, seed_match) {
    (Some(mnemonic), None) => bip39::mnemonic_to_seed(mnemonic, "").to_vec(),
    (None, Some(seed)) => hex::decode(seed.strip_prefix("0x").unwrap_or(seed))
      .context("seed should be hexadecimal string")?,
    _ => unreachable!("mnemonic/seed must be mutually-exclusive and at least one must exist"),
  };
  let network_match: &String = matches
    .get_one("network")
    .expect("default network should be enforced");
  let network = match network_match.as_str() {
    "mainnet" => bip32::Network::Mainnet,
    "testnet" => bip32::Network::Testnet,
    _ => unreachable!("network must be either mainnet or testnet"),
  };

  let master = bip32::ExtendedPrivKey::master(&seed)
    .map_err(|_| anyhow!("invalid seed length {}", seed.len()))?;
  let xprv = bip32::derive_priv_from_path(&master, &cks).unwrap();
  println!("{}", xprv.to_base58(network));
  if showpub {
    println!("{}", xprv.to_xpub().to_base58(network));
  }
  Ok(())
}

fn run_cmd_bip39_mnemonic_generation(matches: &ArgMatches) {
  let ms_length: usize = *matches
    .get_one("wordcount")
    .expect("default wordcount of 12 is expected");
  println!("{}", bip39::random_mnemonic_sentence(ms_length));
}

pub fn run() {
  let matches = Command::new(env!("CARGO_CRATE_NAME"))
    .version("v2025.0.1")
    .author("benharmonics")
    .about("BIP utilities for digital wallet management")
    .arg_required_else_help(true)
    .subcommand(
      Command::new("32")
        .about("Derive child keys using the BIP-32 protocol")
        .visible_alias("derive")
        .arg(arg!(<PATH> "BIP-32 derivation path e.g. m/5'/0 or m/5h/0").id("path"))
        .arg(
          arg!(-m --mnemonic <MNEMONIC> "Random BIP-39 mnemonic sentence")
            .id("mnemonic")
            .required_unless_present_any(["seed", "xprv"])
            .conflicts_with_all(["seed", "xprv"])
            .value_parser(ValueParser::new(|s: &str| {
              if !s.chars().into_iter().all(|c| c.is_ascii()) {
                return Err("invalid characters (non-ascii)");
              }
              let nwords = s.split_whitespace().count();
              if !(12..=24).contains(&nwords) || nwords % 3 != 0 {
                return Err("invalid mnemonic sentence - must be 12, 15, 18, 21, or 24 words");
              }
              Ok(s.to_string())
            })),
        )
        .arg(
          arg!(-s --seed <SEED> "64-byte seed, given as a hexadecimal string")
            .id("seed")
            .required_unless_present_any(["mnemonic", "xprv"])
            .conflicts_with_all(["mnemonic", "xprv"]),
        )
        // TODO: allow xpub by converting this to xkey
        .arg(
          arg!(-x --xprv <XPRV> "BIP-32 extended private key (any depth)")
            .id("xprv")
            .required_unless_present_any(["mnemonic", "seed"])
            .conflicts_with_all(["mnemonic", "seed"])
            .value_parser(ValueParser::new(|s: &str| match bip32::parse_xkey(s) {
              Ok(_) => Ok(s.to_string()),
              Err(e) => Err(e.to_string()),
            }
            )),
        )
        .arg(
          arg!(-n --network <NETWORK>)
            .id("network")
            .default_value("mainnet")
            .value_parser(["mainnet", "testnet"]),
        )
        .arg(arg!(--showpub "If set, show extended public key as well as extended private key").action(clap::ArgAction::SetTrue)),
    )
    .subcommand(
      Command::new("39")
        .about("Generate random mnemonic sentences per BIP-39, or derive a 64-byte seed from an existing mnemonic")
        .arg_required_else_help(true)
        .visible_alias("mnemonic")
        .subcommand(
          Command::new("new")
            .about("Create new random BIP-39 mnemonic")
            .arg(
              arg!([WORD_COUNT] "Number of words in the mnemonic - must be 12, 15, 18, 21, or 24")
                .id("wordcount")
                .value_parser(ValueParser::new(|s: &str| {
                  match s.parse::<usize>() {
                    Ok(ms_length) => {
                      if !(12..=24).contains(&ms_length) || ms_length % 3 != 0 {
                        Err("expected 12, 15, 18, 21, or 24")
                      } else {
                        Ok(ms_length)
                      }
                    }
                    Err(_) => Err("expected integer (one of 12, 15, 18, 21, or 24)"),
                  }
                }))
                .default_value("12"),
            ),
        )
        .subcommand(
          Command::new("seed")
            .about("Generate a 32-byte seed value from a mnemonic")
            .arg(
              arg!(<MNEMONIC> "Valid BIP-39 mnemonic - must be 12, 15, 18, 21, or 24 words"),
            )
            .arg(
              arg!(-p --passphrase [PHRASE] "Optional passphrase for additional security")
                .default_value(""),
            ),
        ),
    )
    .get_matches();

  match matches.subcommand() {
    None => unreachable!("top-level subcommand should be required"),
    Some((cmdname, matches)) => match cmdname {
      "39" => match matches.subcommand() {
        None => unreachable!("BIP39 subcommand should be required"),
        Some((cmdname, matches)) => match cmdname {
          "new" => run_cmd_bip39_mnemonic_generation(matches),
          "seed" => run_cmd_bip39_seed_derivation(matches),
          _ => unreachable!("unknown command in BIP39 utilities"),
        },
      },
      "32" => run_cmd_bip32_key_derivation(matches)
        .unwrap_or_else(|e| println!("failed to derive key: {e}")),
      _ => unreachable!("unknown top-level subcommand"),
    },
  }
}

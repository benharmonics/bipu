mod bip32;
mod bip39;

use clap::{arg, ArgMatches, Command};

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

fn run_cmd_bip32_key_derivation(matches: &ArgMatches) {
  let ms_match = matches.get_one::<String>("mnemonic");
  let seed_match = matches.get_one::<String>("seed");
  let xprv_match = matches.get_one::<String>("xprv");
  let network_match: &String = matches
    .get_one("network")
    .expect("default network should be enforced");
  let seed = match (ms_match, seed_match, xprv_match) {
    (Some(mnemonic), None, None) => bip39::mnemonic_to_seed(mnemonic, "").to_vec(),
    (None, Some(seed), None) => hex::decode(seed).expect("seed should be hex string"),
    (None, None, Some(xprv)) => unimplemented!("TODO: derive keys from xkeys"),
    _ => unreachable!("matches must be mutually-exclusive"),
  };
  let path: &String = matches.get_one("path").expect("path should be required");
  let network = match network_match.as_str() {
    "mainnet" => bip32::Network::Mainnet,
    "testnet" => bip32::Network::Testnet,
    _ => unreachable!("network must be either mainnet or testnet"),
  };

  let master = bip32::ExtendedPrivKey::master(&seed).expect("mnemonic should have been validated");
  let cks = bip32::parse_path(path).unwrap();
  let xprv = bip32::derive_priv_from_path(&master, &cks).expect("derive_priv_from_path works with given child key");
  println!("{}", xprv.to_base58(network));
}

pub fn run() {
  let matches = Command::new(env!("CARGO_CRATE_NAME"))
    .version("v2025.0.1")
    .author("benharmonics")
    .about("BIP utilities - BIP-39 mnemonic generation/seed derivation, BIP-32 key derivation, etc")
    .arg_required_else_help(true)
    .subcommand(
      Command::new("32")
        .about("Derive child keys using the BIP-32 protocol")
        .visible_alias("derive")
        .arg(arg!(<PATH> "BIP-32 derivation path e.g. m/5'/0").id("path"))
        .arg(
          arg!(-m --mnemonic <MNEMONIC> "Random BIP-39 mnemonic sentence")
            .id("mnemonic")
            .required_unless_present_any(["seed", "xprv"])
            .conflicts_with_all(["seed", "xprv"])
            .value_parser(clap::builder::ValueParser::new(|s: &str| {
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
        .arg(
          arg!(-x --xprv <XPRV> "BIP-32 extended private key (any depth)")
            .id("xprv")
            .required_unless_present_any(["mnemonic", "seed"])
            .conflicts_with_all(["mnemonic", "seed"]),
        )
        .arg(
          arg!(-n --network <NETWORK> "network (either mainnet or testnet)")
            .id("network")
            .default_value("mainnet")
            .value_parser(["mainnet", "testnet"]),
        ),
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
                .value_parser(clap::builder::ValueParser::new(|s: &str| {
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
          "new" => unimplemented!("TODO: BIP-39 mnemonic generation"),
          "seed" => run_cmd_bip39_seed_derivation(&matches),
          _ => unreachable!("unknown command in BIP39 utilities"),
        },
      },
      "32" => run_cmd_bip32_key_derivation(&matches),
      _ => unreachable!("unknown top-level subcommand"),
    },
  }
}

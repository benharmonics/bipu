# bipu

A CLI implementing various BIP utilities for managing digital wallets, including mnemonic sentence generation and conversion to 64-byte seeds (BIP-39) and derivation of private/public keys using BIP-32.

## Installation and Usage

You will need to have the `cargo` toolchain (i.e. Rust) installed to build and install this tool. Installation should be relatively easy, though:

```bash
cargo install /path/to/bipu
```

For usage, run the program with the subcommand `help`:

```bash
bipu help
```

## BIP-32

BIP-32 allows you to derive many private keys from a parent seed (or, equivalently, a parent mnemonic sentence - see [BIP-39](#BIP-39)). This specification thus describes hierarchical deterministic (HD) wallets, which can be shared entirely or partially with different systems, with or without the ability to spend coins.

[Reference](https://en.bitcoin.it/wiki/BIP_0032)

## BIP-39

BIP-39 describes the implementation of a mnemonic phrase - a group of easy-to-remember words - for the generation of deterministic wallets.

There are two parts to BIP-39: generating the mnemonic and converting it to a 64-byte binary seed. The seed can then be used to generate deterministic wallets using BIP-32, or something similar.

[Reference](https://bips.dev/39/)


*Note*: In fact, there are no checks that your mnemonic is valid when converting to a binary seed. You could generate the binary seed of any text, but I wouldn't recommend using just any old text as a secure mnemonic. It's also possible to "manually" generate a mnemonic by just picking a few of your favorite words; I wouldn't recommend this either. You're not as unpredictable as you might think you are - it's best to just have a computer generate a mnemonic instead.

### Note on the wordlist

The wordlist included in this package was suggested by my resource, although in general, you could swap out this word list with one of your own. There are a couple of considerations you might want to satisfy:

- The wordlist should be created in such a way that typing in the first four letters of a word disambiguates it from any other word in the list.
- Word pairs which are too similar (e.g. "through" and "thorough") should be avoided because they tend to cause human error.

It doesn't even really matter what language you use: theoretically there are [non-English wordlists](https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md) out there which you could use instead. However, there are many English-only implementations of BIP-39, so it's discouraged to use non-English wordlists.

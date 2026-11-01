// Ed25519 identity derived from the 32-byte seed. With @noble/ed25519 the
// private key IS the seed; there is no separate secret key object.
import { getPublicKey, hashes } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { entropyToMnemonic, mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
hashes.sha512 = sha512;

/** Derive the Ed25519 public key for a 32-byte seed. */
export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  return getPublicKey(seed);
}

/** Encode a 32-byte seed as a 24-word BIP39 mnemonic. */
export function seedToMnemonic(seed: Uint8Array): string {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  return entropyToMnemonic(seed, wordlist);
}

/** Decode a 24-word BIP39 mnemonic back to the 32-byte seed. Throws on invalid checksum. */
export function mnemonicToSeed(mnemonic: string): Uint8Array {
  const seed = mnemonicToEntropy(mnemonic, wordlist);
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  return seed;
}

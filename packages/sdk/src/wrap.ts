// Seed wrapping. Section 4 of the spec.
//   KEK          = HKDF-SHA256(ikm = ek_pw ‖ ek_pin, salt = "", info = "sahichap/seed-wrap/v1", L = 32)
//   wrapped_seed = nonce(24) ‖ XChaCha20-Poly1305.seal(KEK, nonce, seed, ad = "sahichap/seed/v1" ‖ user_id)
// These strings are part of the storage format. Changing them invalidates every stored wrapped seed.

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { concatBytes, managedNonce } from "@noble/ciphers/utils.js";

export const KEK_INFO = "sahichap/seed-wrap/v1";
export const WRAP_AD_PREFIX = "sahichap/seed/v1";

const utf8 = (s: string) => new TextEncoder().encode(s);

// managedNonce draws a random 24-byte nonce on encrypt, prepends it to the
// ciphertext, and strips it again on decrypt. That is exactly nonce ‖ ciphertext.
const cipher = (kek: Uint8Array, userId: string) =>
  managedNonce(xchacha20poly1305)(kek, concatBytes(utf8(WRAP_AD_PREFIX), utf8(userId)));

/** Derive the 32-byte key-encryption key from the two OPAQUE export keys. */
export function deriveKek(ekPw: Uint8Array, ekPin: Uint8Array): Uint8Array {
  return hkdf(sha256, concatBytes(ekPw, ekPin), new Uint8Array(0), utf8(KEK_INFO), 32);
}

/** Encrypt the seed under the KEK, bound to userId. Returns nonce ‖ ciphertext. */
export function wrapSeed(kek: Uint8Array, seed: Uint8Array, userId: string): Uint8Array {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  return cipher(kek, userId).encrypt(seed);
}

/** Reverse of wrapSeed. Throws if the KEK, userId, or blob is wrong. */
export function unwrapSeed(kek: Uint8Array, wrapped: Uint8Array, userId: string): Uint8Array {
  return cipher(kek, userId).decrypt(wrapped);
}

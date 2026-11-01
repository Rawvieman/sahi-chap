// Manifest signing. Section 6.3 of the spec.
//   signature = Ed25519.sign(sk, canonical(manifest))

import { sign, verify } from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { canonicalBytes, type Manifest } from "./canonical.js";
import "./keypair.js"; // installs sha512 into @noble/ed25519

// Rust verifies with ed25519-dalek's verify_strict (RFC 8032). noble defaults
// to the looser ZIP215 rules, so turn those off to keep both verifiers in
// agreement on malformed signatures.
const STRICT = { zip215: false };

const strip = (prefix: string, value: string): Uint8Array => {
  if (!value.startsWith(prefix)) throw new Error(`expected ${prefix} prefix`);
  return hexToBytes(value.slice(prefix.length));
};

/** Sign a manifest with the seed. Returns "ed25519:<hex>". */
export function signManifest(seed: Uint8Array, manifest: Manifest): string {
  return "ed25519:" + bytesToHex(sign(canonicalBytes(manifest), seed));
}

/** Verify a manifest signature against manifest.signer_pk. Never throws. */
export function verifyManifest(manifest: Manifest, signature: string): boolean {
  try {
    const sig = strip("ed25519:", signature);
    const pk = strip("ed25519:", manifest.signer_pk);
    return verify(sig, canonicalBytes(manifest), pk, STRICT);
  } catch {
    return false;
  }
}

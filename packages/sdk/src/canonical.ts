// RFC 8785 canonical JSON. Section 6.3 of the spec.
// Every signature and hash in the system is over these bytes, so the TS and
// Rust implementations must agree byte for byte (checked by vectors/).

import canonicalize from "canonicalize";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export interface Manifest {
  type: "sahichap/manifest/v1";
  request_id: string;
  doc_id: string;
  doc_hash: string; // "sha256:<hex>"
  doc_size: number;
  signer_id: string;
  signer_pk: string; // "ed25519:<hex>"
  role: string;
  intent: string;
  stage_index: number;
  prev_stage_hash: string | null;
  sign_nonce: string;
  client_time: string; // RFC 3339 UTC, informational only
}

// JCS serialises floats, but Rust and JS can format them differently, and
// `canonicalize` silently drops undefined properties. Neither may reach a
// signature, so refuse both before serialising.
function assertSignable(value: unknown, path = "$"): void {
  if (typeof value === "number" && !Number.isInteger(value)) {
    throw new Error(`non-integer number at ${path}`);
  }
  if (value === undefined) throw new Error(`undefined at ${path}`);
  if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) assertSignable(v, `${path}.${k}`);
  }
}

/** Canonical UTF-8 bytes of any JSON value. Rejects floats and undefined. */
export function canonicalBytes(value: unknown): Uint8Array {
  assertSignable(value);
  const text = canonicalize(value);
  if (text === undefined) throw new Error("value has no JSON representation");
  return new TextEncoder().encode(text);
}

/** "sha256:<hex>" of the canonical bytes of value. */
export function canonicalHash(value: unknown): string {
  return "sha256:" + bytesToHex(sha256(canonicalBytes(value)));
}

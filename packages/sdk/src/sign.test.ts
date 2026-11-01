import { test } from "node:test";
import assert from "node:assert/strict";
import { bytesToHex } from "@noble/hashes/utils.js";
import { publicKeyFromSeed } from "./keypair.js";
import { signManifest, verifyManifest } from "./sign.js";
import type { Manifest } from "./canonical.js";

const seed = new Uint8Array(32).fill(7);
const manifest: Manifest = {
  type: "sahichap/manifest/v1",
  request_id: "req-1",
  doc_id: "doc-1",
  doc_hash: "sha256:" + "00".repeat(32),
  doc_size: 12345,
  signer_id: "alice",
  signer_pk: "ed25519:" + bytesToHex(publicKeyFromSeed(seed)),
  role: "approver",
  intent: "approve",
  stage_index: 0,
  prev_stage_hash: null,
  sign_nonce: "nonce-1",
  client_time: "2026-11-01T10:00:00Z",
};

test("signs deterministically and verifies", () => {
  const sig = signManifest(seed, manifest);
  assert.match(sig, /^ed25519:[0-9a-f]{128}$/);
  assert.equal(signManifest(seed, manifest), sig);
  assert.equal(verifyManifest(manifest, sig), true);
  assert.equal(verifyManifest({ ...manifest }, sig), true); // key order irrelevant
});

test("rejects a changed field, a wrong key, and garbage", () => {
  const sig = signManifest(seed, manifest);
  assert.equal(verifyManifest({ ...manifest, intent: "reject" }, sig), false);
  const other = "ed25519:" + bytesToHex(publicKeyFromSeed(new Uint8Array(32).fill(8)));
  assert.equal(verifyManifest({ ...manifest, signer_pk: other }, sig), false);
  assert.equal(verifyManifest(manifest, "ed25519:zz"), false);
  assert.equal(verifyManifest(manifest, "sha256:" + "00".repeat(64)), false);
  assert.equal(verifyManifest({ ...manifest, doc_size: 1.5 }, sig), false);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { deriveKek, wrapSeed, unwrapSeed } from "./wrap.js";

const ekPw = new Uint8Array(64).fill(1);
const ekPin = new Uint8Array(64).fill(2);
const seed = new Uint8Array(32).fill(7);
const kek = deriveKek(ekPw, ekPin);

test("kek is 32 bytes, deterministic, and depends on both export keys", () => {
  assert.equal(kek.length, 32);
  assert.deepEqual(deriveKek(ekPw, ekPin), kek);
  assert.notDeepEqual(deriveKek(ekPw, new Uint8Array(64).fill(3)), kek);
  assert.notDeepEqual(deriveKek(ekPin, ekPw), kek);
});

test("wrap round-trips and is nonce ‖ ciphertext ‖ tag", () => {
  const wrapped = wrapSeed(kek, seed, "user-1");
  assert.equal(wrapped.length, 24 + 32 + 16);
  assert.deepEqual(unwrapSeed(kek, wrapped, "user-1"), seed);
  assert.notDeepEqual(wrapSeed(kek, seed, "user-1"), wrapped); // fresh nonce each time
});

test("rejects wrong kek, wrong user, and a flipped byte", () => {
  const wrapped = wrapSeed(kek, seed, "user-1");
  assert.throws(() => unwrapSeed(deriveKek(ekPin, ekPw), wrapped, "user-1"));
  assert.throws(() => unwrapSeed(kek, wrapped, "user-2"));
  const tampered = wrapped.slice();
  tampered[30] ^= 1;
  assert.throws(() => unwrapSeed(kek, tampered, "user-1"));
});

test("rejects a seed that is not 32 bytes", () => {
  assert.throws(() => wrapSeed(kek, new Uint8Array(16), "user-1"));
});

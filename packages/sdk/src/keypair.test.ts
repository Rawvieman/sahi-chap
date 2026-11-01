import { test } from "node:test";
import assert from "node:assert/strict";
import { publicKeyFromSeed, seedToMnemonic, mnemonicToSeed } from "./keypair.js";

const seed = new Uint8Array(32).fill(7);

test("public key is 32 bytes and deterministic", () => {
  const pk = publicKeyFromSeed(seed);
  assert.equal(pk.length, 32);
  assert.deepEqual(publicKeyFromSeed(seed), pk);
});

test("mnemonic round-trips the seed", () => {
  const words = seedToMnemonic(seed);
  assert.equal(words.split(" ").length, 24);
  assert.deepEqual(mnemonicToSeed(words), seed);
});

test("rejects seeds that are not 32 bytes", () => {
  assert.throws(() => seedToMnemonic(new Uint8Array(16)));
});

test("rejects a mnemonic with a bad checksum", () => {
  const words = seedToMnemonic(seed).split(" ");
  words[23] = words[23] === "abandon" ? "ability" : "abandon";
  assert.throws(() => mnemonicToSeed(words.join(" ")));
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalBytes, canonicalHash } from "./canonical.js";

const text = (v: unknown) => new TextDecoder().decode(canonicalBytes(v));

test("sorts keys, strips whitespace, keeps null and nested order", () => {
  assert.equal(
    text({ b: 1, a: { d: null, c: [3, "x", { z: true, y: false }] } }),
    '{"a":{"c":[3,"x",{"y":false,"z":true}],"d":null},"b":1}',
  );
});

test("escapes strings the RFC 8785 way", () => {
  assert.equal(text({ s: "é\n\"\\\u0001" }), '{"s":"é\\n\\"\\\\\\u0001"}');
});

test("rejects floats and undefined anywhere in the tree", () => {
  assert.throws(() => canonicalBytes({ n: 1.5 }), /non-integer/);
  assert.throws(() => canonicalBytes({ a: { n: undefined } }), /undefined/);
  assert.throws(() => canonicalBytes([1, 2.5]), /non-integer/);
});

test("hash is sha256 of the canonical bytes and independent of key order", () => {
  const h = canonicalHash({ a: 1, b: 2 });
  assert.match(h, /^sha256:[0-9a-f]{64}$/);
  assert.equal(canonicalHash({ b: 2, a: 1 }), h);
  // sha256('{"a":1,"b":2}')
  assert.equal(h, "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777");
});

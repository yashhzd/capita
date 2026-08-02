import { afterAll, expect, test } from "vitest";
import { MerkleTree } from "../src/merkle.js";
import { closePoseidon, p2 } from "../src/poseidon.js";
import { MERKLE_DEPTH } from "../src/constants.js";

afterAll(async () => {
  await closePoseidon();
});

test("insert changes root; path verifies; wrong leaf fails", async () => {
  const t = new MerkleTree();
  const r0 = t.root();
  const i = await t.insert(42n);
  expect(t.root()).not.toBe(r0);
  const path = t.path(i);
  expect(await MerkleTree.verify(t.root(), 42n, path)).toBe(true);
  expect(await MerkleTree.verify(t.root(), 43n, path)).toBe(false);
});

test("two inserts, both paths verify against same root", async () => {
  const t = new MerkleTree();
  const i1 = await t.insert(7n), i2 = await t.insert(9n);
  expect(await MerkleTree.verify(t.root(), 7n, t.path(i1))).toBe(true);
  expect(await MerkleTree.verify(t.root(), 9n, t.path(i2))).toBe(true);
});

// Beyond the brief's two required tests: an empty tree's root must be the
// precomputed all-zeros root (not some arbitrary sentinel), and it must be
// identical across separate instances. A bug in the zero-subtree table
// would pass the two tests above (they only ever check roots against
// themselves) yet silently disagree with what the Noir circuits compute for
// an empty tree in Task 5 -- this test catches that class of bug locally
// instead of leaving it to surface deep inside a circuit later.
test("empty tree root is the precomputed all-zeros root, and stable across instances", async () => {
  const a = new MerkleTree();
  const b = new MerkleTree();
  expect(a.root()).toBe(b.root());

  // Independently re-derive the all-zeros root via p2() directly (not by
  // reaching into MerkleTree internals), so this checks against the
  // definition rather than against the implementation.
  let expected = 0n;
  for (let level = 0; level < MERKLE_DEPTH; level++) {
    expected = await p2([expected, expected]);
  }
  expect(a.root()).toBe(expected);
});

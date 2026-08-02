import { afterAll, expect, test } from "vitest";
import {
  enrollNullifier,
  noteNullifier,
  ownerPk,
  paymentCommit,
  personId,
  tallyCommit,
} from "../src/notes.js";
import { closePoseidon, p2 } from "../src/poseidon.js";
import {
  APP_SCOPE,
  DOMAIN_ENROLL,
  DOMAIN_NULLIFIER,
  DOMAIN_PAYMENT,
  DOMAIN_TALLY,
} from "../src/constants.js";

afterAll(async () => {
  await closePoseidon();
});

// Each function is pinned to its spec formula by re-deriving the expected
// value via p2() directly (same convention as merkle.test.ts: check against
// the definition, not the implementation). These literal input arrays are
// the contract the Noir circuits must reproduce exactly -- a reordered,
// dropped, or re-tagged argument fails here instead of surfacing as a
// cross-language mismatch inside a circuit.
test("each function matches its spec formula computed via raw p2", async () => {
  expect(await personId(11n)).toBe(await p2([11n, APP_SCOPE]));
  expect(await ownerPk(21n)).toBe(await p2([21n]));
  expect(await paymentCommit(1n, 2n, 3n)).toBe(await p2([DOMAIN_PAYMENT, 1n, 2n, 3n]));
  expect(await tallyCommit(1n, 2n, 3n, 4n)).toBe(await p2([DOMAIN_TALLY, 1n, 2n, 3n, 4n]));
  expect(await enrollNullifier(31n)).toBe(await p2([DOMAIN_ENROLL, 31n]));
  expect(await noteNullifier(41n, 42n)).toBe(await p2([DOMAIN_NULLIFIER, 41n, 42n]));
});

test("determinism: same inputs give same outputs across repeated calls", async () => {
  expect(await personId(11n)).toBe(await personId(11n));
  expect(await ownerPk(21n)).toBe(await ownerPk(21n));
  expect(await paymentCommit(1n, 2n, 3n)).toBe(await paymentCommit(1n, 2n, 3n));
  expect(await tallyCommit(1n, 2n, 3n, 4n)).toBe(await tallyCommit(1n, 2n, 3n, 4n));
  expect(await enrollNullifier(31n)).toBe(await enrollNullifier(31n));
  expect(await noteNullifier(41n, 42n)).toBe(await noteNullifier(41n, 42n));
});

// Change one argument at a time and require the output to move. This is the
// test that catches a dropped or duplicated argument in a p2() call, which
// per-function determinism and the formula pins above cannot catch if the
// same mistake were copied into both places.
test("sensitivity: changing any single argument changes the output", async () => {
  expect(await personId(11n)).not.toBe(await personId(12n));
  expect(await ownerPk(21n)).not.toBe(await ownerPk(22n));
  expect(await enrollNullifier(31n)).not.toBe(await enrollNullifier(32n));

  const payment = await paymentCommit(1n, 2n, 3n);
  expect(await paymentCommit(9n, 2n, 3n)).not.toBe(payment);
  expect(await paymentCommit(1n, 9n, 3n)).not.toBe(payment);
  expect(await paymentCommit(1n, 2n, 9n)).not.toBe(payment);

  const tally = await tallyCommit(1n, 2n, 3n, 4n);
  expect(await tallyCommit(9n, 2n, 3n, 4n)).not.toBe(tally);
  expect(await tallyCommit(1n, 9n, 3n, 4n)).not.toBe(tally);
  expect(await tallyCommit(1n, 2n, 9n, 4n)).not.toBe(tally);
  expect(await tallyCommit(1n, 2n, 3n, 9n)).not.toBe(tally);

  const nullifier = await noteNullifier(41n, 42n);
  expect(await noteNullifier(9n, 42n)).not.toBe(nullifier);
  expect(await noteNullifier(41n, 9n)).not.toBe(nullifier);
});

// Domain separation: feed every function the same small raw inputs and
// require all outputs to be pairwise distinct. The domain tags (and, for
// personId, the APP_SCOPE suffix) are what keep a payment commitment from
// ever colliding with a tally commitment or a nullifier built over the
// same raw values.
test("domain separation: same raw inputs across note types give distinct outputs", async () => {
  const outputs: [string, bigint][] = [
    ["personId", await personId(5n)],
    ["ownerPk", await ownerPk(5n)],
    ["enrollNullifier", await enrollNullifier(5n)],
    ["noteNullifier", await noteNullifier(5n, 6n)],
    ["paymentCommit", await paymentCommit(5n, 6n, 7n)],
    ["tallyCommit", await tallyCommit(5n, 6n, 7n, 8n)],
  ];
  for (let i = 0; i < outputs.length; i++) {
    for (let j = i + 1; j < outputs.length; j++) {
      const [nameA, a] = outputs[i];
      const [nameB, b] = outputs[j];
      expect(a, `${nameA} vs ${nameB}`).not.toBe(b);
    }
  }
});

// The same commitment nullified under two different secrets must give two
// different nullifiers (a payment note spent by owner_sk vs a tally note
// spent by person_secret), and the same secret over two different
// commitments must too (spending two notes never links them).
test("noteNullifier separates by secret and by commitment", async () => {
  const alicePk = await ownerPk(101n);
  const c1 = await paymentCommit(500n, alicePk, 71n);
  const c2 = await paymentCommit(500n, alicePk, 72n);

  expect(await noteNullifier(101n, c1)).not.toBe(await noteNullifier(102n, c1));
  expect(await noteNullifier(101n, c1)).not.toBe(await noteNullifier(101n, c2));
});

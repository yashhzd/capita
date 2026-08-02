import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, expect, test } from "vitest";
import { compile, execute } from "../src/prove.js";
import { closePoseidon } from "../src/poseidon.js";
import { MerkleTree } from "../src/merkle.js";
import { G, GRUMPKIN_ORDER, mul } from "../src/grumpkin.js";
import { encrypt, keygen, type Limbs } from "../src/elgamal.js";
import {
  enrollNullifier,
  noteNullifier,
  ownerPk,
  paymentCommit,
  personId,
  tallyCommit,
} from "../src/notes.js";
import { P } from "../src/constants.js";

// TypeScript <-> Noir consistency gate. Executes the `consistency` probe
// circuit (which evaluates every primitive in circuits/common) and asserts
// the outputs equal the TypeScript reference implementation from Tasks 2-4,
// on three fixed input sets. Every later circuit builds on the common lib,
// so a silent divergence here would surface much later as an unprovable
// statement -- this test is the tripwire.
//
// Probe output layout (see circuits/consistency/src/main.nr):
//   0 person_id         1 owner_pk          2 payment_commit
//   3 tally_commit      4 enroll_nullifier  5 note_nullifier
//   6 merkle_root       7 G.x               8 G.y
//   9 c1.x             10 c1.y             11..14 ct[0..3]

const CONSISTENCY_DIR = fileURLToPath(
  new URL("../../circuits/consistency/", import.meta.url),
);
const MASK_128 = (1n << 128n) - 1n;
const toHex = (v: bigint) => "0x" + v.toString(16);

interface InputSet {
  name: string;
  personSecret: bigint;
  ownerSk: bigint;
  v: bigint;
  r: bigint;
  s: bigint;
  d: bigint;
  r2: bigint;
  treeLeaves: bigint[];
  leafIndex: number;
  msg: Limbs;
  apkSk: bigint;
  rEnc: bigint;
}

// Three fixed sets, chosen to vary every dimension that could hide a
// divergence: tree position (all-left path, then mixed index bits), field
// values at both ends of the range (small and P - 1), and the encryption
// scalar across all three regimes of Grumpkin's scalar field -- below
// 2^128 (hi limb 0), above 2^128 (hi limb nonzero), and in [P, order)
// where the scalar exceeds the native field modulus and only the two-limb
// encoding can carry it.
const SETS: InputSet[] = [
  {
    name: "small values, single-leaf tree, rEnc below 2^128",
    personSecret: 11n,
    ownerSk: 12n,
    v: 5000n,
    r: 13n,
    s: 900n,
    d: 20260801n,
    r2: 14n,
    treeLeaves: [4242n],
    leafIndex: 0,
    msg: [1n, 2n, 3n, 4n],
    apkSk: 99n,
    rEnc: 77n,
  },
  {
    name: "values at the field edge, mixed path bits, rEnc above 2^128",
    personSecret: P - 1n,
    ownerSk: P - 2n,
    v: 123456789n,
    r: P - 3n,
    s: 10000n,
    d: 20260802n,
    r2: P - 4n,
    treeLeaves: [101n, 102n, 103n],
    leafIndex: 1,
    msg: [P - 1n, 0n, 7n, P - 5n],
    apkSk: 123456789123456789n,
    rEnc: (1n << 128n) + 3n,
  },
  {
    name: "rEnc in [P, GRUMPKIN_ORDER), deeper tree position",
    personSecret: 0xdeadbeefn,
    ownerSk: 0xcafef00dn,
    v: 9999n,
    r: 424242n,
    s: 12345n,
    d: 20260803n,
    r2: 515151n,
    treeLeaves: [1001n, 1002n, 1003n, 1004n, 1005n, 1006n],
    leafIndex: 5,
    msg: [0n, P - 1n, 1n, 0xffffffffffffffffn],
    apkSk: 31337n,
    rEnc: GRUMPKIN_ORDER - 5n,
  },
];

beforeAll(() => {
  // Always recompile so the gate never compares against stale bytecode.
  compile(CONSISTENCY_DIR);
}, 120_000);

afterAll(async () => {
  await closePoseidon();
});

for (const set of SETS) {
  test(`circuit matches TypeScript: ${set.name}`, { timeout: 60_000 }, async () => {
    // The scalar must exceed the native field modulus in at least one set,
    // or the [P, order) regime would silently go untested.
    if (set.name.startsWith("rEnc in [P")) {
      expect(set.rEnc > P).toBe(true);
      expect(set.rEnc < GRUMPKIN_ORDER).toBe(true);
    }

    // TypeScript side, mirroring the probe's composition exactly:
    // payment_commit over the derived owner_pk, tally_commit and
    // enroll_nullifier over the derived person_id, note_nullifier over the
    // derived payment_commit with owner_sk as the secret.
    const pid = await personId(set.personSecret);
    const opk = await ownerPk(set.ownerSk);
    const pc = await paymentCommit(set.v, opk, set.r);
    const tc = await tallyCommit(pid, set.s, set.d, set.r2);
    const en = await enrollNullifier(pid);
    const nn = await noteNullifier(set.ownerSk, pc);

    const tree = new MerkleTree();
    for (const leaf of set.treeLeaves) {
      await tree.insert(leaf);
    }
    const root = tree.root();
    const path = tree.path(set.leafIndex);
    const leaf = set.treeLeaves[set.leafIndex];

    const apk = keygen(set.apkSk);
    const memo = await encrypt(set.msg, apk, set.rEnc);

    // Scalar handoff convention (Task 8 must do the same): reduce to the
    // canonical Grumpkin scalar, then split into 128-bit limbs
    // (value = lo + 2^128 * hi), matching Noir's EmbeddedCurveScalar.
    const rEncCanonical =
      ((set.rEnc % GRUMPKIN_ORDER) + GRUMPKIN_ORDER) % GRUMPKIN_ORDER;

    const { returnValue } = await execute(CONSISTENCY_DIR, {
      person_secret: toHex(set.personSecret),
      owner_sk: toHex(set.ownerSk),
      v: toHex(set.v),
      r: toHex(set.r),
      s: toHex(set.s),
      d: toHex(set.d),
      r2: toHex(set.r2),
      leaf: toHex(leaf),
      siblings: path.siblings.map(toHex),
      indices: path.indices.map((bit) => bit === 1),
      msg: set.msg.map(toHex),
      apk_x: toHex(apk.x),
      apk_y: toHex(apk.y),
      r_enc_lo: toHex(rEncCanonical & MASK_128),
      r_enc_hi: toHex(rEncCanonical >> 128n),
    });

    const out = (returnValue as string[]).map(BigInt);
    expect(out, "probe returns 15 field elements").toHaveLength(15);
    expect(out[0], "person_id").toBe(pid);
    expect(out[1], "owner_pk").toBe(opk);
    expect(out[2], "payment_commit").toBe(pc);
    expect(out[3], "tally_commit").toBe(tc);
    expect(out[4], "enroll_nullifier").toBe(en);
    expect(out[5], "note_nullifier").toBe(nn);
    expect(out[6], "merkle fold reproduces the tree root").toBe(root);
    expect(out[7], "TS generator x reproduces the circuit's").toBe(G.x);
    expect(out[8], "TS generator y reproduces the circuit's").toBe(G.y);
    // memo.c1 is mul(rEnc, G) on the TS side, so these two assertions are
    // the "TS mul reproduces the circuit's fixed-base c1" check.
    expect(out[9], "elgamal c1.x").toBe(memo.c1.x);
    expect(out[10], "elgamal c1.y").toBe(memo.c1.y);
    expect(out.slice(11), "elgamal ciphertext limbs").toEqual([...memo.ct]);
  });
}

test("TS mul agrees with the circuit generator on a direct check", () => {
  // Belt and braces alongside the c1 comparison: multiplying the TS
  // generator by 1 must land exactly on the circuit's embedded-curve
  // generator coordinates returned by the probe (checked per-set above);
  // here we pin the TS constants themselves so a drive-by edit to
  // grumpkin.ts G cannot slip past between probe runs.
  expect(G.x).toBe(1n);
  expect(G.y).toBe(17631683881184975370165255887551781615748388533673675138860n);
  const one = mul(1n, G);
  expect(one.x).toBe(G.x);
  expect(one.y).toBe(G.y);
});

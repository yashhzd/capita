import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, expect, test } from "vitest";
import { compile, execute } from "../src/prove.js";
import { closePoseidon, p2 } from "../src/poseidon.js";
import { MerkleTree, type Path } from "../src/merkle.js";
import {
  noteNullifier,
  ownerPk,
  paymentCommit,
  personId,
  tallyCommit,
} from "../src/notes.js";
import { Pool, type EnrollOutput } from "../src/pool.js";
import { MERKLE_DEPTH } from "../src/constants.js";

// Spend circuit core against live pool state: enroll a person, deposit a
// transparent payment note, then execute the spend circuit over the real
// tree's root and paths and check its public outputs against the
// TypeScript formulas. Per the plan, the executed witness's return value
// stands in for a verified proof until Task 11; spend ACCEPTANCE (root and
// nullifier bookkeeping on the pool) is Task 9.

const SPEND_DIR = fileURLToPath(new URL("../../circuits/spend/", import.meta.url));
const ENROLLMENT_DIR = fileURLToPath(
  new URL("../../circuits/enrollment/", import.meta.url),
);
const toHex = (v: bigint) => "0x" + v.toString(16);
const DAY = 20260802n;

// Same repackaging as enroll.test.ts: circuit outputs plus the public
// d_now input form the operator-visible enrollment message.
async function runEnrollment(
  personSecret: bigint,
  rT: bigint,
  dNow: bigint,
): Promise<EnrollOutput> {
  const { returnValue } = await execute(ENROLLMENT_DIR, {
    person_secret: toHex(personSecret),
    r_t: toHex(rT),
    d_now: toHex(dNow),
  });
  const [e, cT] = (returnValue as [string, string]).map(BigInt);
  return { E: e, cT, dNow };
}

interface SpendWitness {
  personSecret: bigint;
  vIn: bigint;
  ownerSk: bigint;
  rIn: bigint;
  pathIn: Path;
  v1: bigint;
  pk1: bigint;
  r1: bigint;
  v2: bigint;
  r2: bigint;
  sOld: bigint;
  dOld: bigint;
  rT: bigint;
  pathT: Path;
  rTNew: bigint;
  root: bigint;
  dNow: bigint;
}

// Encodes a spend witness the way noir_js expects it: fields as 0x-hex,
// Merkle index bits as booleans (harness 0/1 -> false/true).
function executeSpend(w: SpendWitness) {
  return execute(SPEND_DIR, {
    person_secret: toHex(w.personSecret),
    v_in: toHex(w.vIn),
    owner_sk: toHex(w.ownerSk),
    r_in: toHex(w.rIn),
    path_in_siblings: w.pathIn.siblings.map(toHex),
    path_in_indices: w.pathIn.indices.map((bit) => bit === 1),
    v1: toHex(w.v1),
    pk1: toHex(w.pk1),
    r1: toHex(w.r1),
    v2: toHex(w.v2),
    r2: toHex(w.r2),
    s_old: toHex(w.sOld),
    d_old: toHex(w.dOld),
    r_t: toHex(w.rT),
    path_t_siblings: w.pathT.siblings.map(toHex),
    path_t_indices: w.pathT.indices.map((bit) => bit === 1),
    r_t_new: toHex(w.rTNew),
    root: toHex(w.root),
    d_now: toHex(w.dNow),
  });
}

beforeAll(() => {
  // Recompile both circuits so the tests never execute stale bytecode
  // (consistency-gate convention).
  compile(ENROLLMENT_DIR);
  compile(SPEND_DIR);
}, 240_000);

afterAll(async () => {
  await closePoseidon();
});

test(
  "spend against live pool state: outputs match the TypeScript formulas with s_new = 6000",
  { timeout: 120_000 },
  async () => {
    const pool = new Pool(DAY);
    const personSecret = 9001n;
    const rT = 71n;
    const aliceSk = 1111n;
    const alicePk = await ownerPk(aliceSk);
    const bobPk = await ownerPk(2222n);
    const r1 = 333n;
    const r2 = 444n;
    const rTNew = 555n;

    // Enroll (genesis tally lands at index 0), then deposit a transparent
    // 20000-unit note for Alice (index 1).
    const enrollment = await runEnrollment(personSecret, rT, DAY);
    await pool.enroll(enrollment);
    const { commit: cIn, index } = await pool.deposit(20000n, alicePk);
    // The deposit's documented salt convention -- r = leaf index -- is
    // what the spender later supplies as the note's r witness, so pin it.
    expect(index).toBe(1);
    expect(cIn).toBe(await paymentCommit(20000n, alicePk, BigInt(index)));

    // Spend 6000 to Bob with 14000 self-change, consuming the genesis
    // tally (s_old = 0) on the same day. Paths and root come from the live
    // post-deposit tree.
    const root = pool.tree.root();
    expect(pool.rootHistory.has(root.toString())).toBe(true);
    const { returnValue } = await executeSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(index),
      pathIn: pool.tree.path(index),
      v1: 6000n,
      pk1: bobPk,
      r1,
      v2: 14000n,
      r2,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew,
      root,
      dNow: DAY,
    });

    const [nPay, nTally, cOut1, cOut2, cTallyNew] = (
      returnValue as [string, string, string, string, string]
    ).map(BigInt);

    const pid = await personId(personSecret);
    expect(nPay, "n_pay = note_nullifier(owner_sk, C_in)").toBe(
      await noteNullifier(aliceSk, cIn),
    );
    expect(nTally, "n_tally = note_nullifier(person_secret, C_t_genesis)").toBe(
      await noteNullifier(personSecret, enrollment.cT),
    );
    expect(cOut1, "c_out1 = payment_commit(6000, bob_pk, r1)").toBe(
      await paymentCommit(6000n, bobPk, r1),
    );
    expect(cOut2, "c_out2 = change committed to Alice's own key").toBe(
      await paymentCommit(14000n, alicePk, r2),
    );
    expect(cTallyNew, "c_tally_new = tally_commit(pid, 6000, d_now, r_t_new)").toBe(
      await tallyCommit(pid, 6000n, DAY, rTNew),
    );
  },
);

test(
  "fabricated membership via an unfilled index's zero leaf is unsatisfiable",
  { timeout: 120_000 },
  async () => {
    // The hazard (Task 6 review): every unfilled index of the tree holds
    // the empty leaf 0, and a correctly-built path folds that 0 to the
    // live root -- so a circuit that accepted a RAW leaf witness would let
    // a prover "prove" membership of a note that was never deposited. The
    // spend circuit closes this by deriving the leaf from a commitment
    // opening; the attack then needs an opening that hashes to 0.
    const pool = new Pool(DAY);
    const personSecret = 9002n;
    const rT = 72n;
    const enrollment = await runEnrollment(personSecret, rT, DAY);
    await pool.enroll(enrollment);
    const { commit: cIn } = await pool.deposit(500n, await ownerPk(1111n));
    const root = pool.tree.root();

    // Hand-build the path for UNFILLED index 2 of the two-leaf tree
    // [C_t_genesis, C_in]: sibling leaf 3 is empty (0), the level-1
    // sibling is the parent of leaves 0-1, and above that lie the
    // empty-subtree roots zeros[k] = p2([zeros[k-1], zeros[k-1]]).
    const zeros: bigint[] = [0n];
    for (let k = 1; k < MERKLE_DEPTH; k++) {
      zeros.push(await p2([zeros[k - 1], zeros[k - 1]]));
    }
    const fabricated: Path = {
      siblings: [0n, await p2([enrollment.cT, cIn]), ...zeros.slice(2)],
      indices: [0, 1, ...Array<number>(MERKLE_DEPTH - 2).fill(0)],
    };
    // The attack surface is real: the zero leaf at index 2 verifies
    // against the live root...
    expect(await MerkleTree.verify(root, 0n, fabricated)).toBe(true);

    // ...but the circuit derives its leaf from the opening, so claiming a
    // never-deposited 5000-unit note at that index is unsatisfiable, with
    // every other constraint (real tally path, conservation, day) honest.
    await expect(
      executeSpend({
        personSecret,
        vIn: 5000n,
        ownerSk: 6666n,
        rIn: 77n,
        pathIn: fabricated,
        v1: 2000n,
        pk1: await ownerPk(2222n),
        r1: 333n,
        v2: 3000n,
        r2: 444n,
        sOld: 0n,
        dOld: DAY,
        rT,
        pathT: pool.tree.path(0),
        rTNew: 555n,
        root,
        dNow: DAY,
      }),
    ).rejects.toThrow("merkle_verify: root mismatch");
  },
);

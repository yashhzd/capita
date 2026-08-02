import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, expect, test } from "vitest";
import { compile, execute } from "../src/prove.js";
import { closePoseidon } from "../src/poseidon.js";
import { MerkleTree } from "../src/merkle.js";
import { enrollNullifier, personId, tallyCommit } from "../src/notes.js";
import { Pool, type EnrollOutput } from "../src/pool.js";

// Enrollment flow: execute the enrollment circuit to obtain its public
// outputs (E, C_t_genesis), then feed them to Pool.enroll() the way an
// operator would after verifying a proof. Per the plan, the executed
// witness's return value stands in for a verified proof until Task 11
// wires up real UltraHonk proving -- the pool-side acceptance logic under
// test here is identical either way.

const ENROLLMENT_DIR = fileURLToPath(
  new URL("../../circuits/enrollment/", import.meta.url),
);
const toHex = (v: bigint) => "0x" + v.toString(16);
const DAY = 20260802n;

// Runs the circuit and repackages its two public outputs plus the public
// d_now input as the operator-visible enrollment message.
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

beforeAll(() => {
  // Recompile so the tests never execute stale bytecode (consistency-gate
  // convention from Task 5).
  compile(ENROLLMENT_DIR);
}, 120_000);

afterAll(async () => {
  await closePoseidon();
});

test(
  "circuit outputs equal the TypeScript formulas (cross-implementation)",
  { timeout: 60_000 },
  async () => {
    const personSecret = 0xa11cen;
    const rT = 424242n;
    const out = await runEnrollment(personSecret, rT, DAY);

    const pid = await personId(personSecret);
    expect(out.E, "E = enroll_nullifier(person_id)").toBe(
      await enrollNullifier(pid),
    );
    expect(out.cT, "C_t genesis = tally_commit(pid, 0, d_now, r_t)").toBe(
      await tallyCommit(pid, 0n, DAY, rT),
    );
  },
);

test(
  "enroll succeeds and inserts the genesis tally note",
  { timeout: 60_000 },
  async () => {
    const pool = new Pool(DAY);
    const emptyRoot = pool.tree.root();
    const out = await runEnrollment(1001n, 71n, DAY);

    await pool.enroll(out);

    // The genesis tally commitment is now a provable member of the tree.
    const root = pool.tree.root();
    expect(root).not.toBe(emptyRoot);
    expect(await MerkleTree.verify(root, out.cT, pool.tree.path(0))).toBe(true);
    // The pool remembered both the enrollment nullifier and the new root.
    expect(pool.seenEnrollments.has(out.E.toString())).toBe(true);
    expect(pool.rootHistory.has(root.toString())).toBe(true);
    // Only post-insert roots are historical; the empty root proves nothing.
    expect(pool.rootHistory.has(emptyRoot.toString())).toBe(false);
  },
);

test(
  "second enrollment by the same person is rejected, even with a fresh salt",
  { timeout: 60_000 },
  async () => {
    const pool = new Pool(DAY);
    await pool.enroll(await runEnrollment(2002n, 81n, DAY));
    const rootAfterFirst = pool.tree.root();

    // Same person_secret, different r_t: C_t differs but E is identical --
    // this is the fifty-wallets attack the enrollment nullifier exists to
    // stop.
    const second = await runEnrollment(2002n, 82n, DAY);
    expect(second.E.toString()).toBe([...pool.seenEnrollments][0]);
    await expect(pool.enroll(second)).rejects.toThrow("duplicate-enrollment");

    // The rejected attempt left no trace: no new leaf, no new root.
    expect(pool.tree.root()).toBe(rootAfterFirst);
    expect(pool.seenEnrollments.size).toBe(1);
    expect(pool.rootHistory.size).toBe(1);
  },
);

test(
  "a different person enrolls into the same pool",
  { timeout: 60_000 },
  async () => {
    const pool = new Pool(DAY);
    const first = await runEnrollment(3003n, 91n, DAY);
    await pool.enroll(first);
    const second = await runEnrollment(3004n, 91n, DAY);
    await pool.enroll(second);

    expect(second.E).not.toBe(first.E);
    expect(pool.seenEnrollments.size).toBe(2);
    expect(pool.rootHistory.size).toBe(2);
    // Both genesis notes are members of the final tree.
    const root = pool.tree.root();
    expect(await MerkleTree.verify(root, first.cT, pool.tree.path(0))).toBe(true);
    expect(await MerkleTree.verify(root, second.cT, pool.tree.path(1))).toBe(true);
  },
);

test(
  "enrollment proven for a different day is rejected",
  { timeout: 60_000 },
  async () => {
    const pool = new Pool(DAY);
    const stale = await runEnrollment(4004n, 55n, DAY + 1n);

    await expect(pool.enroll(stale)).rejects.toThrow("wrong-day");

    // Rejected before any state change: E unrecorded, tree untouched.
    expect(pool.seenEnrollments.size).toBe(0);
    expect(pool.rootHistory.size).toBe(0);
  },
);

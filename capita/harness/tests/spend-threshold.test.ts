import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, expect, test } from "vitest";
import { compile, execute, printAcir } from "../src/prove.js";
import { closePoseidon } from "../src/poseidon.js";
import { type Path } from "../src/merkle.js";
import {
  noteNullifier,
  ownerPk,
  paymentCommit,
  personId,
  tallyCommit,
} from "../src/notes.js";
import { Pool, type EnrollOutput } from "../src/pool.js";
import { GRUMPKIN_ORDER, isOnCurve } from "../src/grumpkin.js";
import { decrypt, encrypt, keygen, type Limbs, type Memo } from "../src/elgamal.js";
import { collect } from "../src/auditor.js";
import { P, T_THRESHOLD } from "../src/constants.js";

// Task 8 flows: the threshold branch and the uniform disclosure memo.
// Every spend now carries a hash-ElGamal memo as public inputs, and the
// circuit is only satisfiable when that memo encrypts exactly the message
// its own threshold comparison dictates -- [0,0,0,0] at or below
// T_THRESHOLD, [1, pid, s_new, d_now] above it. So each successful
// execution below CERTIFIES its memo; the decrypt assertions then show
// what the auditor (and only the auditor) learns from it.
//
// Pool acceptance of spend outputs is Task 9; between the two spends of a
// flow, the new tally and change commitments are inserted into the tree by
// hand as the acceptance stand-in (executed witnesses stand in for
// verified proofs per the plan).
//
// Tests 4 and 5 read `memoLog`, accumulated by tests 1-3 -- vitest runs a
// file's tests sequentially in declaration order, and this file relies on
// that (running a later test in isolation starves the log and fails).

const SPEND_DIR = fileURLToPath(new URL("../../circuits/spend/", import.meta.url));
const ENROLLMENT_DIR = fileURLToPath(
  new URL("../../circuits/enrollment/", import.meta.url),
);
const toHex = (v: bigint) => "0x" + v.toString(16);
const MASK_128 = (1n << 128n) - 1n;
const DAY = 20260803n;

// The auditor keypair: ask stays offline with the auditor; apk is the
// public input every spend encrypts to.
const ASK = 271828n;
const APK = keygen(ASK);

const memoLog: { kind: "real" | "dummy"; memo: Memo }[] = [];

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
  rEnc: bigint;
  root: bigint;
  dNow: bigint;
}

interface SpendResult {
  memo: Memo;
  nPay: bigint;
  nTally: bigint;
  cOut1: bigint;
  cOut2: bigint;
  cTallyNew: bigint;
}

// Runs one spend end to end: computes the disclosure message the protocol
// requires for this witness (TS side), encrypts it to the auditor key, and
// executes the circuit with the memo as public inputs. Execution only
// succeeds if the circuit's own threshold branch agrees this is the
// required memo, so a returned SpendResult certifies its memo. The scalar
// handoff is the Task 5 convention: reduce rEnc mod the Grumpkin group
// order, split into 128-bit limbs.
async function spend(w: SpendWitness): Promise<SpendResult> {
  const sNew = w.dNow === w.dOld ? w.sOld + w.v1 : w.v1;
  const over = sNew > T_THRESHOLD;
  const msg: Limbs = over
    ? [1n, await personId(w.personSecret), sNew, w.dNow]
    : [0n, 0n, 0n, 0n];
  const memo = await encrypt(msg, APK, w.rEnc);
  const rEncCanonical = ((w.rEnc % GRUMPKIN_ORDER) + GRUMPKIN_ORDER) % GRUMPKIN_ORDER;

  const { returnValue } = await execute(SPEND_DIR, {
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
    r_enc_lo: toHex(rEncCanonical & MASK_128),
    r_enc_hi: toHex(rEncCanonical >> 128n),
    root: toHex(w.root),
    d_now: toHex(w.dNow),
    t_threshold: toHex(T_THRESHOLD),
    apk_x: toHex(APK.x),
    apk_y: toHex(APK.y),
    c1: [toHex(memo.c1.x), toHex(memo.c1.y)],
    ct: memo.ct.map(toHex),
  });

  const [nPay, nTally, cOut1, cOut2, cTallyNew] = (
    returnValue as [string, string, string, string, string]
  ).map(BigInt);
  memoLog.push({ kind: over ? "real" : "dummy", memo });
  return { memo, nPay, nTally, cOut1, cOut2, cTallyNew };
}

// Enroll + deposit: genesis tally at leaf 0 (subtotal 0, day dNow),
// 20000-unit payment note for the owner at leaf 1 (salt = leaf index, the
// deposit convention).
async function setupPool(
  personSecret: bigint,
  rT: bigint,
  ownerSk: bigint,
  dNow: bigint,
): Promise<{ pool: Pool; cIn: bigint; depositIndex: number }> {
  const pool = new Pool(dNow);
  await pool.enroll(await runEnrollment(personSecret, rT, dNow));
  const { commit: cIn, index } = await pool.deposit(20000n, await ownerPk(ownerSk));
  return { pool, cIn, depositIndex: index };
}

// Task 9 acceptance stand-in: admit a spend's new tally and change notes
// into the tree so the next spend can consume them.
async function admitOutputs(pool: Pool, cTallyNew: bigint, cChange: bigint) {
  await pool.tree.insert(cTallyNew);
  await pool.tree.insert(cChange);
  pool.rootHistory.add(pool.tree.root().toString());
}

beforeAll(() => {
  compile(ENROLLMENT_DIR);
  compile(SPEND_DIR);
}, 240_000);

afterAll(async () => {
  await closePoseidon();
});

test(
  "below the threshold, the memo decrypts to [0, 0, 0, 0]",
  { timeout: 120_000 },
  async () => {
    const personSecret = 4101n;
    const aliceSk = 1111n;
    const { pool, depositIndex } = await setupPool(personSecret, 41n, aliceSk, DAY);

    const { memo, cTallyNew } = await spend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 401n,
      v2: 14000n,
      r2: 402n,
      sOld: 0n,
      dOld: DAY,
      rT: 41n,
      pathT: pool.tree.path(0),
      rTNew: 403n,
      rEnc: 1001n,
      root: pool.tree.root(),
      dNow: DAY,
    });

    // 6000 <= 10000: nothing to disclose. The circuit certified this memo,
    // and to the auditor it reads as the all-zero dummy.
    expect(await decrypt(memo, ASK)).toEqual([0n, 0n, 0n, 0n]);
    // The tally still advanced under the dummy memo.
    const pid = await personId(personSecret);
    expect(cTallyNew).toBe(await tallyCommit(pid, 6000n, DAY, 403n));
  },
);

test(
  "crossing the threshold (6000 then 5000, same day) forces the real disclosure",
  { timeout: 120_000 },
  async () => {
    const personSecret = 4201n;
    const aliceSk = 1112n;
    const rT = 42n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk, DAY);
    const pid = await personId(personSecret);

    // First spend: 6000, subtotal 0 -> 6000, under the threshold.
    const first = await spend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 411n,
      v2: 14000n,
      r2: 412n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 413n,
      rEnc: 2001n,
      root: pool.tree.root(),
      dNow: DAY,
    });
    expect(await decrypt(first.memo, ASK)).toEqual([0n, 0n, 0n, 0n]);

    // Admit the updated tally (leaf 2) and the change note (leaf 3), then
    // spend 5000 out of the change on the same day: subtotal 6000 -> 11000,
    // over the threshold.
    await admitOutputs(pool, first.cTallyNew, first.cOut2);
    const second = await spend({
      personSecret,
      vIn: 14000n,
      ownerSk: aliceSk,
      rIn: 412n,
      pathIn: pool.tree.path(3),
      v1: 5000n,
      pk1: await ownerPk(2222n),
      r1: 414n,
      v2: 9000n,
      r2: 415n,
      sOld: 6000n,
      dOld: DAY,
      rT: 413n,
      pathT: pool.tree.path(2),
      rTNew: 416n,
      // A scalar above 2^128 exercises the nonzero-hi-limb handoff through
      // the spend ABI (the consistency gate covers it for the library).
      rEnc: (1n << 128n) + 77n,
      root: pool.tree.root(),
      dNow: DAY,
    });

    // The second memo is a verifiably correct report: person, day subtotal
    // crossing the threshold, and the day itself.
    expect(await decrypt(second.memo, ASK)).toEqual([1n, pid, 11000n, DAY]);
    expect(second.cTallyNew).toBe(await tallyCommit(pid, 11000n, DAY, 416n));
  },
);

test(
  "day rollover (6000 day d, 5000 day d+1) resets the subtotal; both memos dummy",
  { timeout: 120_000 },
  async () => {
    const personSecret = 4301n;
    const aliceSk = 1113n;
    const rT = 43n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk, DAY);
    const pid = await personId(personSecret);

    const first = await spend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 421n,
      v2: 14000n,
      r2: 422n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 423n,
      rEnc: 3001n,
      root: pool.tree.root(),
      dNow: DAY,
    });
    expect(await decrypt(first.memo, ASK)).toEqual([0n, 0n, 0n, 0n]);

    // Next day: the tally consumed still says day d, but d_now = d + 1, so
    // the subtotal restarts at v1 = 5000 instead of reaching 11000.
    await admitOutputs(pool, first.cTallyNew, first.cOut2);
    const second = await spend({
      personSecret,
      vIn: 14000n,
      ownerSk: aliceSk,
      rIn: 422n,
      pathIn: pool.tree.path(3),
      v1: 5000n,
      pk1: await ownerPk(2222n),
      r1: 424n,
      v2: 9000n,
      r2: 425n,
      sOld: 6000n,
      dOld: DAY,
      rT: 423n,
      pathT: pool.tree.path(2),
      rTNew: 426n,
      rEnc: 3002n,
      root: pool.tree.root(),
      dNow: DAY + 1n,
    });

    expect(await decrypt(second.memo, ASK)).toEqual([0n, 0n, 0n, 0n]);
    // The new tally binds the RESET subtotal on the new day.
    expect(second.cTallyNew).toBe(await tallyCommit(pid, 5000n, DAY + 1n, 426n));
  },
);

test("auditor.collect returns exactly the one real disclosure", async () => {
  // Five memos accumulated across the three flows above; only the
  // threshold-crossing spend carries a real report. The auditor decrypts
  // all of them and cannot be fooled by the dummies.
  expect(
    memoLog,
    "memoLog is filled by the three flow tests above -- this file's tests " +
      "are order-dependent, so run the whole file, not this test alone",
  ).toHaveLength(5);
  expect(memoLog.filter((m) => m.kind === "real")).toHaveLength(1);

  const disclosures = await collect(
    memoLog.map((m) => m.memo),
    ASK,
  );
  expect(disclosures).toEqual([
    { personId: await personId(4201n), subtotal: 11000n, day: DAY },
  ]);
});

test("real and dummy memos are structurally identical", () => {
  const realEntry = memoLog.find((m) => m.kind === "real");
  const dummyEntry = memoLog.find((m) => m.kind === "dummy");
  expect(
    realEntry,
    "needs the crossing flow (test 2) to have run first -- run the whole file",
  ).toBeDefined();
  expect(
    dummyEntry,
    "needs a dummy flow (tests 1-3) to have run first -- run the whole file",
  ).toBeDefined();
  const real = realEntry!.memo;
  const dummy = dummyEntry!.memo;

  // Same shape, field for field: an ephemeral curve point plus exactly
  // four ciphertext limbs, every limb a canonical field element.
  expect(Object.keys(real).sort()).toEqual(Object.keys(dummy).sort());
  for (const memo of [real, dummy]) {
    expect(memo.ct).toHaveLength(4);
    expect(memo.c1.inf).toBe(false);
    expect(isOnCurve(memo.c1)).toBe(true);
    for (const limb of memo.ct) {
      expect(limb >= 0n && limb < P).toBe(true);
    }
  }
  // The dummy is ENCRYPTED zeros, not literal zeros: without the auditor
  // key its ciphertext limbs are Poseidon2 pads, indistinguishable from a
  // real report's. (Deterministic: fixed rEnc makes these fixed values.)
  for (const limb of dummy.ct) {
    expect(limb).not.toBe(0n);
  }
});

test(
  "spend ACIR range-constrains the memo scalar limbs with standalone opcodes",
  { timeout: 240_000 },
  () => {
    // Review finding (fix round 1): the library's 128-bit limb checks
    // inside elgamal_encrypt are compiled OUT of this circuit's ACIR --
    // their range is subsumed into the MULTI_SCALAR_MUL inputs' declared
    // bit widths, leaving enforcement to the ACVM solver rather than an
    // opcode the proven circuit owns. The spend circuit therefore bounds
    // r_enc_lo/hi itself, and this test pins that at the artifact level:
    // every witness fed to an MSM as a scalar limb must carry its own
    // 128-bit RANGE opcode. Witness execution cannot observe this (the
    // solver rejects oversized limbs either way), so the pin reads the
    // compiled ACIR -- the thing that actually gets proven in Task 11.
    const acir = printAcir(SPEND_DIR);
    const scalarWitnesses = new Set<string>();
    for (const msm of acir.matchAll(/MULTI_SCALAR_MUL[^\n]*scalars: \[([^\]]*)\]/g)) {
      for (const w of msm[1].matchAll(/w\d+/g)) {
        scalarWitnesses.add(w[0]);
      }
    }
    // Vacuity guard: the memo's shared secret and ephemeral point are two
    // MSMs over the same (lo, hi) scalar pair.
    expect(scalarWitnesses.size).toBeGreaterThanOrEqual(2);
    for (const witness of scalarWitnesses) {
      expect(
        acir.includes(`RANGE input: ${witness}, bits: 128`),
        `MSM scalar limb ${witness} must carry a standalone 128-bit range opcode`,
      ).toBe(true);
    }
  },
);

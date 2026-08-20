import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, expect, test } from "vitest";
import { compile, execute } from "../src/prove.js";
import { closePoseidon } from "../src/poseidon.js";
import { MerkleTree, type Path } from "../src/merkle.js";
import { noteNullifier, ownerPk, paymentCommit, personId, tallyCommit } from "../src/notes.js";
import { Pool, type EnrollOutput, type SpendPublicInputs } from "../src/pool.js";
import { DAY_BITS, MERKLE_DEPTH, P, T_THRESHOLD } from "../src/constants.js";
import { GRUMPKIN_ORDER, INF, negate, type Pt } from "../src/grumpkin.js";
import { decrypt, encrypt, keygen, type Limbs, type Memo } from "../src/elgamal.js";
import { collect } from "../src/auditor.js";

// Task 9: the pool's spend acceptance rules and its day clock.
//
// The spend circuit proves a payment is well-formed, but it cannot know the
// pool's state: which roots exist, which nullifiers are burnt, what day it
// actually is, which auditor key is real, or what the policy threshold is.
// Every one of those is a PUBLIC INPUT the prover chooses freely, so each
// one is a bypass until the operator pins it. These tests build spends that
// the circuit genuinely accepts -- real executions, not hand-forged records
// -- and require the pool to reject them.
//
// Per the plan, an executed witness stands in for a verified proof until
// Task 11; the acceptance logic under test is identical either way.
//
// Every test builds its own Pool. Nothing here is order-dependent.

const SPEND_DIR = fileURLToPath(new URL("../../circuits/spend/", import.meta.url));
const ENROLLMENT_DIR = fileURLToPath(
  new URL("../../circuits/enrollment/", import.meta.url),
);
const toHex = (v: bigint) => "0x" + v.toString(16);
const MASK_128 = (1n << 128n) - 1n;
// An opaque period index, NOT a date -- see Pool.currentDay. This is the
// suite that exercises advanceDay, so it uses a plain counter: a
// YYYYMMDD-shaped fixture would make `DAY + 1n` read as "the next day" and
// quietly mislead, since 20260831 + 1 is not one.
const DAY = 900n;

// The pool's configured auditor key. ASK never leaves the auditor.
const ASK = 271828n;
const APK = keygen(ASK);

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
  /** Auditor key the memo encrypts to; defaults to the pool's real APK. */
  apk?: Pt;
  /** Threshold the prover declares; defaults to the real policy constant. */
  tThreshold?: bigint;
}

/**
 * Runs one spend through the circuit and repackages the result as the
 * operator-visible record: the public inputs the prover chose plus the five
 * public outputs. Execution only succeeds if the circuit agrees the memo is
 * the one this witness requires, so a returned record is realizable -- which
 * is the point of every rejection test below.
 */
async function runSpend(w: SpendWitness): Promise<SpendPublicInputs> {
  const apk = w.apk ?? APK;
  const tThreshold = w.tThreshold ?? T_THRESHOLD;
  const sNew = w.dNow === w.dOld ? w.sOld + w.v1 : w.v1;
  const msg: Limbs =
    sNew > tThreshold
      ? [1n, await personId(w.personSecret), sNew, w.dNow]
      : [0n, 0n, 0n, 0n];
  const memo = await encrypt(msg, apk, w.rEnc);
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
    t_threshold: toHex(tThreshold),
    apk_x: toHex(apk.x),
    apk_y: toHex(apk.y),
    c1: [toHex(memo.c1.x), toHex(memo.c1.y)],
    ct: memo.ct.map(toHex),
  });

  const [nPay, nTally, cOut1, cOut2, cTallyNew] = (
    returnValue as [string, string, string, string, string]
  ).map(BigInt);
  return {
    root: w.root,
    dNow: w.dNow,
    tThreshold,
    apkX: apk.x,
    apkY: apk.y,
    memo,
    nPay,
    nTally,
    cOut1,
    cOut2,
    cTallyNew,
  };
}

/**
 * A pool holding one enrolled person (genesis tally at leaf 0) and one
 * 20000-unit deposit for `ownerSk` (leaf 1) -- the standard starting state
 * for a spend.
 */
async function setupPool(
  personSecret: bigint,
  rT: bigint,
  ownerSk: bigint,
  day: bigint = DAY,
) {
  const pool = new Pool(day, APK);
  const enrollment = await runEnrollment(personSecret, rT, day);
  await pool.enroll(enrollment);
  const ownerPkValue = await ownerPk(ownerSk);
  const { commit: cIn, index } = await pool.deposit(20000n, ownerPkValue);
  return { pool, enrollment, cIn, depositIndex: index, ownerPk: ownerPkValue };
}

beforeAll(() => {
  // Recompile so the tests never execute stale bytecode (Task 5 convention).
  compile(ENROLLMENT_DIR);
  compile(SPEND_DIR);
}, 240_000);

afterAll(async () => {
  await closePoseidon();
});

test(
  "an accepted spend burns both nullifiers and inserts c_out1, c_out2, c_tally_new in that order",
  { timeout: 120_000 },
  async () => {
    const personSecret = 9101n;
    const rT = 81n;
    const aliceSk = 1111n;
    const { pool, enrollment, cIn, depositIndex } = await setupPool(
      personSecret,
      rT,
      aliceSk,
    );
    const bobPk = await ownerPk(2222n);
    const rootBefore = pool.tree.root();
    const rootsBefore = pool.rootHistory.size;

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: bobPk,
      r1: 811n,
      v2: 14000n,
      r2: 812n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 813n,
      rEnc: 8101n,
      root: rootBefore,
      dNow: DAY,
    });

    await pool.spend(sp);

    // Both consumed notes are burnt: the payment note and the tally note.
    expect(pool.seenNullifiers.has(sp.nPay.toString())).toBe(true);
    expect(pool.seenNullifiers.has(sp.nTally.toString())).toBe(true);
    expect(pool.seenNullifiers.size).toBe(2);
    expect(sp.nPay).toBe(await noteNullifier(aliceSk, cIn));
    expect(sp.nTally).toBe(await noteNullifier(personSecret, enrollment.cT));

    // Exactly three new leaves, in the documented order -- Task 10 reads
    // these indices back when it chains spends.
    expect(pool.tree.leafCount()).toBe(5);
    const root = pool.tree.root();
    expect(root).not.toBe(rootBefore);
    expect(await MerkleTree.verify(root, sp.cOut1, pool.tree.path(2))).toBe(true);
    expect(await MerkleTree.verify(root, sp.cOut2, pool.tree.path(3))).toBe(true);
    expect(await MerkleTree.verify(root, sp.cTallyNew, pool.tree.path(4))).toBe(true);
    expect(sp.cOut1).toBe(await paymentCommit(6000n, bobPk, 811n));
    expect(sp.cOut2).toBe(await paymentCommit(14000n, await ownerPk(aliceSk), 812n));
    expect(sp.cTallyNew).toBe(
      await tallyCommit(await personId(personSecret), 6000n, DAY, 813n),
    );

    // One new root recorded, and the accepted record is on the transcript.
    expect(pool.rootHistory.has(root.toString())).toBe(true);
    expect(pool.rootHistory.size).toBe(rootsBefore + 1);
    expect(pool.spendLog).toEqual([sp]);
  },
);

test(
  "replaying an accepted spend throws double-spend and changes nothing",
  { timeout: 120_000 },
  async () => {
    const personSecret = 9102n;
    const rT = 82n;
    const aliceSk = 1112n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 821n,
      v2: 14000n,
      r2: 822n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 823n,
      rEnc: 8201n,
      root: pool.tree.root(),
      dNow: DAY,
    });

    await pool.spend(sp);
    const rootAfter = pool.tree.root();

    // The identical record, resubmitted: its root is now a known root and
    // its day is still today, so only the nullifier set can stop it.
    await expect(pool.spend(sp)).rejects.toThrow("double-spend");

    expect(pool.tree.leafCount()).toBe(5);
    expect(pool.tree.root()).toBe(rootAfter);
    expect(pool.seenNullifiers.size).toBe(2);
    expect(pool.spendLog).toHaveLength(1);
  },
);

test(
  "a second spend against the already-consumed tally throws double-spend on n_tally",
  { timeout: 120_000 },
  async () => {
    // The tally chain is what makes the limit person-bound, so reusing a
    // spent tally note is the direct attack: the payer would keep restarting
    // from the same subtotal. The second spend below is entirely fresh on
    // the payment side (a different note, so a different n_pay) and reuses
    // ONLY the consumed genesis tally, isolating n_tally as the rejection.
    const personSecret = 9103n;
    const rT = 83n;
    const aliceSk = 1113n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);

    const first = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 831n,
      v2: 14000n,
      r2: 832n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 833n,
      rEnc: 8301n,
      root: pool.tree.root(),
      dNow: DAY,
    });
    await pool.spend(first);

    // Spend the change note (leaf 3) but consume the GENESIS tally (leaf 0)
    // again -- still a real leaf under the current root, so the circuit is
    // perfectly happy. Subtotal would restart from 0 instead of 6000.
    const second = await runSpend({
      personSecret,
      vIn: 14000n,
      ownerSk: aliceSk,
      rIn: 832n,
      pathIn: pool.tree.path(3),
      v1: 5000n,
      pk1: await ownerPk(2222n),
      r1: 834n,
      v2: 9000n,
      r2: 835n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 836n,
      rEnc: 8302n,
      root: pool.tree.root(),
      dNow: DAY,
    });

    // Precisely one of its two nullifiers is already burnt: the tally's.
    expect(second.nTally).toBe(first.nTally);
    expect(second.nPay).not.toBe(first.nPay);
    expect(pool.seenNullifiers.has(second.nPay.toString())).toBe(false);

    await expect(pool.spend(second)).rejects.toThrow("double-spend");

    // The rejection recorded nothing -- in particular the fresh n_pay must
    // not have been burnt on the way out.
    expect(pool.seenNullifiers.has(second.nPay.toString())).toBe(false);
    expect(pool.seenNullifiers.size).toBe(2);
    expect(pool.tree.leafCount()).toBe(5);
  },
);

test(
  "a spend proved against a tree the pool never saw throws unknown-root",
  { timeout: 120_000 },
  async () => {
    // Merkle membership only says "this note is in SOME tree". Without the
    // root-history check a prover mints value out of nothing: build a
    // private tree containing a fabricated 1,000,000-unit note and a
    // fabricated tally, prove against its root, and the circuit is
    // satisfied. Only the pool knowing which roots are real stops it.
    const personSecret = 9104n;
    const rT = 84n;
    const aliceSk = 1114n;
    const { pool, ownerPk: alicePk } = await setupPool(personSecret, rT, aliceSk);
    const rootBefore = pool.tree.root();

    const fake = new MerkleTree();
    await fake.insert(await tallyCommit(await personId(personSecret), 0n, DAY, rT));
    await fake.insert(await paymentCommit(1_000_000n, alicePk, 777n));
    const fakeRoot = fake.root();
    expect(pool.rootHistory.has(fakeRoot.toString())).toBe(false);

    const sp = await runSpend({
      personSecret,
      vIn: 1_000_000n,
      ownerSk: aliceSk,
      rIn: 777n,
      pathIn: fake.path(1),
      v1: 9000n,
      pk1: await ownerPk(2222n),
      r1: 841n,
      v2: 991_000n,
      r2: 842n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: fake.path(0),
      rTNew: 843n,
      rEnc: 8401n,
      root: fakeRoot,
      dNow: DAY,
    });

    await expect(pool.spend(sp)).rejects.toThrow("unknown-root");

    // The empty-tree root is excluded from rootHistory by contract, so the
    // literal "pre-insertion root" is unusable too.
    const emptyRoot = new MerkleTree().root();
    expect(pool.rootHistory.has(emptyRoot.toString())).toBe(false);
    await expect(pool.spend({ ...sp, root: emptyRoot })).rejects.toThrow("unknown-root");

    expect(pool.tree.root()).toBe(rootBefore);
    expect(pool.tree.leafCount()).toBe(2);
    expect(pool.seenNullifiers.size).toBe(0);
    expect(pool.spendLog).toHaveLength(0);
  },
);

test(
  "a spend carrying yesterday's d_now after advanceDay throws wrong-day",
  { timeout: 120_000 },
  async () => {
    const personSecret = 9105n;
    const rT = 85n;
    const aliceSk = 1115n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 851n,
      v2: 14000n,
      r2: 852n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 853n,
      rEnc: 8501n,
      root: pool.tree.root(),
      dNow: DAY,
    });

    await pool.advanceDay();
    expect(pool.currentDay).toBe(DAY + 1n);

    await expect(pool.spend(sp)).rejects.toThrow("wrong-day");
    expect(pool.seenNullifiers.size).toBe(0);
    expect(pool.tree.leafCount()).toBe(2);
  },
);

test(
  "a prover cannot date a spend tomorrow to reset today's subtotal",
  { timeout: 120_000 },
  async () => {
    // THE bypass this task exists to close (carried from the Task 8 review).
    // d_now is a free public input and the circuit only checks d_now >=
    // d_old, so a payer sitting on a 9900 subtotal can date the next spend
    // tomorrow, get s_new = v1 instead of s_old + v1, and settle with a
    // DUMMY memo -- total limit evasion, with an entirely honest proof. The
    // circuit cannot see a clock; only the pool can.
    const personSecret = 9106n;
    const rT = 86n;
    const aliceSk = 1116n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);
    const pid = await personId(personSecret);
    const bobPk = await ownerPk(2222n);

    // Spend 1: 9900, just under T = 10000. Accepted, dummy memo.
    const first = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 9900n,
      pk1: bobPk,
      r1: 861n,
      v2: 10100n,
      r2: 862n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 863n,
      rEnc: 8601n,
      root: pool.tree.root(),
      dNow: DAY,
    });
    expect(await decrypt(first.memo, ASK)).toEqual([0n, 0n, 0n, 0n]);
    await pool.spend(first);

    // Spend 2, dated TOMORROW: subtotal resets to 5000 and the memo is a
    // dummy. The circuit accepts it -- the execution below is the proof
    // that this attack is realizable, not hypothetical.
    const evasion = await runSpend({
      personSecret,
      vIn: 10100n,
      ownerSk: aliceSk,
      rIn: 862n,
      pathIn: pool.tree.path(3),
      v1: 5000n,
      pk1: bobPk,
      r1: 864n,
      v2: 5100n,
      r2: 865n,
      sOld: 9900n,
      dOld: DAY,
      rT: 863n,
      pathT: pool.tree.path(4),
      rTNew: 866n,
      rEnc: 8602n,
      root: pool.tree.root(),
      dNow: DAY + 1n,
    });
    expect(
      await decrypt(evasion.memo, ASK),
      "the evasion discloses nothing -- 14900 moved in a day, T = 10000",
    ).toEqual([0n, 0n, 0n, 0n]);
    expect(evasion.cTallyNew).toBe(await tallyCommit(pid, 5000n, DAY + 1n, 866n));

    // Pinning d_now to the pool's clock is the whole defence.
    await expect(pool.spend(evasion)).rejects.toThrow("wrong-day");
    expect(pool.seenNullifiers.size).toBe(2);
    expect(pool.tree.leafCount()).toBe(5);

    // Dated honestly, the same payment must disclose: 9900 + 5000 = 14900.
    const honest = await runSpend({
      personSecret,
      vIn: 10100n,
      ownerSk: aliceSk,
      rIn: 862n,
      pathIn: pool.tree.path(3),
      v1: 5000n,
      pk1: bobPk,
      r1: 864n,
      v2: 5100n,
      r2: 865n,
      sOld: 9900n,
      dOld: DAY,
      rT: 863n,
      pathT: pool.tree.path(4),
      rTNew: 866n,
      rEnc: 8602n,
      root: pool.tree.root(),
      dNow: DAY,
    });
    expect(await decrypt(honest.memo, ASK)).toEqual([1n, pid, 14900n, DAY]);
    await pool.spend(honest);
    expect(pool.tree.leafCount()).toBe(8);
  },
);

test(
  "a memo encrypted to a different auditor key is rejected on both coordinates",
  { timeout: 120_000 },
  async () => {
    // Carried from the Task 8 review. The circuit only asserts apk is ON
    // THE CURVE, and (x, -y) is on the curve whenever (x, y) is -- so a
    // payer who must disclose can encrypt to the negated key, publish a
    // memo that is well-formed by every in-circuit check, and hand the
    // auditor ciphertext that decrypts to garbage. A SILENT disclosure
    // void: nothing looks wrong, and nothing is reported. Pinning apk by
    // x alone would let it through, so the pool pins the full pair.
    const personSecret = 9107n;
    const rT = 87n;
    const aliceSk = 1117n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);
    const pid = await personId(personSecret);
    const mirrored = negate(APK);
    expect(mirrored.x, "the negated key shares the real key's x").toBe(APK.x);

    const voided = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 15000n,
      pk1: await ownerPk(2222n),
      r1: 871n,
      v2: 5000n,
      r2: 872n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 873n,
      rEnc: 8701n,
      root: pool.tree.root(),
      dNow: DAY,
      apk: mirrored,
    });

    // This spend is above the threshold, so it owes a real report -- and
    // what the auditor actually recovers is neither the report nor a dummy.
    const recovered = await decrypt(voided.memo, ASK);
    expect(recovered).not.toEqual([1n, pid, 15000n, DAY]);
    expect(recovered).not.toEqual([0n, 0n, 0n, 0n]);

    await expect(pool.spend(voided)).rejects.toThrow("wrong-auditor-key");

    // A wholly different (also on-curve) key is rejected the same way.
    const stranger = keygen(999n);
    await expect(
      pool.spend({ ...voided, apkX: stranger.x, apkY: stranger.y }),
    ).rejects.toThrow("wrong-auditor-key");

    expect(pool.seenNullifiers.size).toBe(0);
    expect(pool.tree.leafCount()).toBe(2);
  },
);

test(
  "a spend declaring its own threshold is rejected",
  { timeout: 120_000 },
  async () => {
    // Same class of hole as a free d_now: t_threshold is a public input the
    // circuit range-checks to 64 bits but never ties to policy. Declaring
    // T = 2^64 - 1 makes every subtotal "below threshold", so a 15000-unit
    // spend settles with a dummy memo and discloses nothing.
    const personSecret = 9108n;
    const rT = 88n;
    const aliceSk = 1118n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);
    const declared = (1n << 64n) - 1n;

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 15000n,
      pk1: await ownerPk(2222n),
      r1: 881n,
      v2: 5000n,
      r2: 882n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 883n,
      rEnc: 8801n,
      root: pool.tree.root(),
      dNow: DAY,
      tThreshold: declared,
    });

    expect(sp.tThreshold).toBe(declared);
    expect(
      await decrypt(sp.memo, ASK),
      "15000 > T_THRESHOLD yet the memo is a dummy -- the evasion",
    ).toEqual([0n, 0n, 0n, 0n]);

    await expect(pool.spend(sp)).rejects.toThrow("wrong-threshold");
    expect(pool.seenNullifiers.size).toBe(0);
    expect(pool.tree.leafCount()).toBe(2);
  },
);

test(
  "a v1 = 0 spend that reissues the identical tally note is rejected as duplicate-tally",
  { timeout: 120_000 },
  async () => {
    // Carried from the Task 7 review. With v1 = 0 on the same day and
    // r_t_new = r_t, the new tally commits to the same (pid, s, d, r) as
    // the consumed one -- so c_tally_new IS c_t_old, and its nullifier is
    // the n_tally this very spend burns. Admitting it inserts a leaf that
    // is dead on arrival and ends the payer's tally chain, and with it
    // their ability to spend at all.
    const personSecret = 9109n;
    const rT = 89n;
    const aliceSk = 1119n;
    const { pool, enrollment, depositIndex } = await setupPool(personSecret, rT, aliceSk);
    const rootBefore = pool.tree.root();

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 0n,
      pk1: await ownerPk(2222n),
      r1: 891n,
      v2: 20000n,
      r2: 892n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: rT,
      rEnc: 8901n,
      root: rootBefore,
      dNow: DAY,
    });

    // The circuit produced a "new" tally identical to the one it consumed,
    // so the note the pool is asked to insert is born nullified.
    expect(sp.cTallyNew).toBe(enrollment.cT);
    expect(sp.nTally).toBe(await noteNullifier(personSecret, sp.cTallyNew));
    expect(pool.tree.hasLeaf(sp.cTallyNew)).toBe(true);

    await expect(pool.spend(sp)).rejects.toThrow("duplicate-tally");

    expect(pool.tree.root()).toBe(rootBefore);
    expect(pool.tree.leafCount()).toBe(2);
    expect(pool.seenNullifiers.size).toBe(0);
    expect(pool.spendLog).toHaveLength(0);

    // A fresh salt makes the same payment admissible -- the rule rejects
    // the collision, not the zero-value spend.
    const fixed = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 0n,
      pk1: await ownerPk(2222n),
      r1: 891n,
      v2: 20000n,
      r2: 892n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 893n,
      rEnc: 8901n,
      root: rootBefore,
      dNow: DAY,
    });
    await pool.spend(fixed);
    expect(pool.tree.leafCount()).toBe(5);
  },
);

test(
  "a non-canonical output is rejected before any of the three inserts lands",
  { timeout: 120_000 },
  async () => {
    // A spend inserts THREE leaves. If validation were interleaved with
    // insertion, a bad third output would leave the first two in the tree
    // with no nullifiers burnt -- unbacked notes, and the same shape of bug
    // as the poisoned leaf that once bricked the tree in Task 6. Every
    // output is therefore range-checked before the first insert.
    const personSecret = 9110n;
    const rT = 90n;
    const aliceSk = 1120n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 901n,
      v2: 14000n,
      r2: 902n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 903n,
      rEnc: 9001n,
      root: pool.tree.root(),
      dNow: DAY,
    });

    const rootBefore = pool.tree.root();
    // A verified proof can never output a value >= P, but the operator must
    // not fall over -- or half-apply -- on unverified input.
    for (const field of ["cOut1", "cOut2", "cTallyNew"] as const) {
      await expect(
        pool.spend({ ...sp, [field]: P + 5n }),
        `tampered ${field}`,
      ).rejects.toThrow(RangeError);
      expect(pool.tree.leafCount(), `tampered ${field}`).toBe(2);
      expect(pool.tree.root(), `tampered ${field}`).toBe(rootBefore);
      expect(pool.seenNullifiers.size, `tampered ${field}`).toBe(0);
      expect(pool.spendLog, `tampered ${field}`).toHaveLength(0);
    }

    // Nothing was poisoned: the untampered record still settles.
    await pool.spend(sp);
    expect(pool.tree.leafCount()).toBe(5);
  },
);

test(
  "a spend that would overflow the tree is rejected before any insert",
  { timeout: 120_000 },
  async () => {
    // The other half of the three-insert atomicity surface: a tree with
    // room for two more leaves must refuse the whole spend, not insert what
    // fits and wedge on the third. Filling 65k leaves honestly would cost
    // 65k hashes, but the guard runs before any hashing -- so seeding the
    // leaf count reaches it, the technique Task 2's review noted for
    // MerkleTree's own full-tree guard.
    const personSecret = 9116n;
    const rT = 96n;
    const aliceSk = 1126n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 961n,
      v2: 14000n,
      r2: 962n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 963n,
      rEnc: 9601n,
      root: pool.tree.root(),
      dNow: DAY,
    });

    const nearlyFull = 2 ** MERKLE_DEPTH - 2;
    (pool.tree as unknown as { leaves: bigint[] }).leaves.length = nearlyFull;

    await expect(pool.spend(sp)).rejects.toThrow(
      /room for 2 more leaves, spend needs 3/,
    );
    expect(pool.tree.leafCount()).toBe(nearlyFull);
    expect(pool.seenNullifiers.size).toBe(0);
    expect(pool.spendLog).toHaveLength(0);
  },
);

test(
  "two in-flight copies of one spend cannot both be accepted",
  { timeout: 120_000 },
  async () => {
    // Task 6's TOCTOU bug, in the spend path: check the nullifier set,
    // yield at `await tree.insert`, record afterwards -- and two un-awaited
    // submissions both pass the check. Acceptance must be serialized.
    const personSecret = 9111n;
    const rT = 91n;
    const aliceSk = 1121n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 911n,
      v2: 14000n,
      r2: 912n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 913n,
      rEnc: 9101n,
      root: pool.tree.root(),
      dNow: DAY,
    });

    const [first, second] = await Promise.allSettled([pool.spend(sp), pool.spend(sp)]);
    expect(first.status).toBe("fulfilled");
    expect(second.status).toBe("rejected");
    expect((second as PromiseRejectedResult).reason).toEqual(new Error("double-spend"));

    expect(pool.tree.leafCount()).toBe(5);
    expect(pool.seenNullifiers.size).toBe(2);
    expect(pool.spendLog).toHaveLength(1);
  },
);

test(
  "concurrent spends by different people each land a contiguous block of three leaves",
  { timeout: 120_000 },
  async () => {
    // Serialization is not only about duplicate submissions. Two spends
    // with disjoint nullifiers are both valid and each inserts three
    // leaves; unserialized, their `await tree.insert` calls interleave and
    // a spend's outputs end up scattered instead of contiguous. Task 10
    // chains spends by reading those indices back, so the block must stay
    // whole -- and a wallet computing a path for its own change note must
    // be able to predict where the note landed.
    const aliceSecret = 9114n;
    const bobSecret = 9115n;
    const aliceSk = 1124n;
    const bobSk = 1125n;
    const pool = new Pool(DAY, APK);

    await pool.enroll(await runEnrollment(aliceSecret, 94n, DAY));
    const alice = await pool.deposit(20000n, await ownerPk(aliceSk));
    await pool.enroll(await runEnrollment(bobSecret, 95n, DAY));
    const bob = await pool.deposit(20000n, await ownerPk(bobSk));
    expect([alice.index, bob.index]).toEqual([1, 3]);

    const root = pool.tree.root();
    const spA = await runSpend({
      personSecret: aliceSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(alice.index),
      pathIn: pool.tree.path(alice.index),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 941n,
      v2: 14000n,
      r2: 942n,
      sOld: 0n,
      dOld: DAY,
      rT: 94n,
      pathT: pool.tree.path(0),
      rTNew: 943n,
      rEnc: 9401n,
      root,
      dNow: DAY,
    });
    const spB = await runSpend({
      personSecret: bobSecret,
      vIn: 20000n,
      ownerSk: bobSk,
      rIn: BigInt(bob.index),
      pathIn: pool.tree.path(bob.index),
      v1: 7000n,
      pk1: await ownerPk(3333n),
      r1: 951n,
      v2: 13000n,
      r2: 952n,
      sOld: 0n,
      dOld: DAY,
      rT: 95n,
      pathT: pool.tree.path(2),
      rTNew: 953n,
      rEnc: 9501n,
      root,
      dNow: DAY,
    });

    const [a, b] = await Promise.allSettled([pool.spend(spA), pool.spend(spB)]);
    expect(a.status).toBe("fulfilled");
    expect(b.status).toBe("fulfilled");
    expect(pool.tree.leafCount()).toBe(10);

    // Submitted in that order, so Alice's block sits at 4-6 and Bob's at
    // 7-9, neither split by the other.
    const finalRoot = pool.tree.root();
    for (const [sp, base] of [
      [spA, 4],
      [spB, 7],
    ] as const) {
      const block = [sp.cOut1, sp.cOut2, sp.cTallyNew];
      for (const [offset, leaf] of block.entries()) {
        expect(
          await MerkleTree.verify(finalRoot, leaf, pool.tree.path(base + offset)),
          `leaf ${offset} of the block at ${base}`,
        ).toBe(true);
      }
    }
  },
);

test(
  "advanceDay cannot jump the acceptance queue",
  { timeout: 120_000 },
  async () => {
    // The clock is pool state, so it moves through the same queue as
    // acceptance. A spend submitted before the rollover is judged against
    // the day it was submitted under; one submitted after is not.
    const personSecret = 9112n;
    const rT = 92n;
    const aliceSk = 1122n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 921n,
      v2: 14000n,
      r2: 922n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 923n,
      rEnc: 9201n,
      root: pool.tree.root(),
      dNow: DAY,
    });

    // Submitted first, so it settles under DAY even though the rollover is
    // already queued behind it.
    const accepted = pool.spend(sp);
    const rolled = pool.advanceDay();
    const [a, b] = await Promise.allSettled([accepted, rolled]);
    expect(a.status).toBe("fulfilled");
    expect(b.status).toBe("fulfilled");
    expect(pool.currentDay).toBe(DAY + 1n);
    expect(pool.tree.leafCount()).toBe(5);
  },
);

test(
  "an accepted record is a snapshot: mutating the submission cannot void the disclosure",
  { timeout: 120_000 },
  async () => {
    // The transcript is the auditor's evidence base, so it must not alias
    // the payer's object. Storing `pub` by reference let a payer settle a
    // crossing spend, be collected correctly, and THEN reach back into the
    // record they still held and blank the memo -- the silent disclosure
    // void of hand-off 2, reopened on the far side of acceptance.
    const personSecret = 9117n;
    const rT = 97n;
    const aliceSk = 1127n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);
    const pid = await personId(personSecret);

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 15000n,
      pk1: await ownerPk(2222n),
      r1: 971n,
      v2: 5000n,
      r2: 972n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 973n,
      rEnc: 9701n,
      root: pool.tree.root(),
      dNow: DAY,
    });

    await pool.spend(sp);
    const owed = [{ personId: pid, subtotal: 15000n, day: DAY }];
    expect((await collect(pool.spendLog.map((r) => r.memo), ASK)).disclosures).toEqual(owed);

    // The payer still holds their submission. Everything they can reach
    // must be a different object from what the pool kept.
    expect(pool.spendLog[0]).not.toBe(sp);
    expect(pool.spendLog[0].memo).not.toBe(sp.memo);
    expect(pool.spendLog[0].memo.c1).not.toBe(sp.memo.c1);
    expect(pool.spendLog[0].memo.ct).not.toBe(sp.memo.ct);

    // Blank the memo and rewrite the declared inputs on their copy.
    sp.memo.ct[0] = 0n;
    sp.memo.ct[1] = 0n;
    sp.memo.ct[2] = 0n;
    sp.memo.ct[3] = 0n;
    sp.memo.c1 = INF;
    sp.dNow = 999n;
    sp.tThreshold = (1n << 64n) - 1n;

    // The transcript is unmoved and the disclosure still stands.
    expect(pool.spendLog[0].dNow).toBe(DAY);
    expect(pool.spendLog[0].tThreshold).toBe(T_THRESHOLD);
    expect((await collect(pool.spendLog.map((r) => r.memo), ASK)).disclosures).toEqual(owed);
  },
);

test(
  "a structurally invalid memo is rejected on acceptance",
  { timeout: 120_000 },
  async () => {
    // The pool stores memos it never inspected. The shapes below fail in
    // three different ways, and only two of them are breakages: an infinite
    // c1 makes decrypt throw, taking down every honest disclosure in the
    // batch; an off-curve c1 decrypts to garbage, so a disclosure that was
    // owed is lost; a non-canonical c1 decrypts CORRECTLY (verified) and is
    // rejected as hygiene, because grumpkin's add compares x with raw
    // bigint equality and states normalization as a precondition -- the
    // collision merely happens not to arise inside mul(ask, c1).
    //
    // Task 11 does NOT cover this. The circuit ABI carries c1 as
    // [Field; 2], but the harness Pt carries a third field, `inf`, with no
    // ABI counterpart -- so {x: realX, y: realY, inf: true} satisfies any
    // coordinate-based proof binding and still breaks decrypt.
    const personSecret = 9118n;
    const rT = 98n;
    const aliceSk = 1128n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 15000n,
      pk1: await ownerPk(2222n),
      r1: 981n,
      v2: 5000n,
      r2: 982n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 983n,
      rEnc: 9801n,
      root: pool.tree.root(),
      dNow: DAY,
    });
    const good = sp.memo;

    const broken: [string, Memo][] = [
      // The reviewer's probe: a real execution submitted with a blanked memo.
      ["infinite c1", { c1: INF, ct: [0n, 0n, 0n, 0n] }],
      ["off-curve c1", { c1: { x: 1n, y: 2n, inf: false }, ct: good.ct }],
      // On-curve by the mod-P equation, but outside [0, P) -- grumpkin's
      // group law compares x raw, so an unnormalized point misbehaves.
      [
        "non-canonical c1 coordinate",
        { c1: { x: good.c1.x + P, y: good.c1.y, inf: false }, ct: good.ct },
      ],
      [
        "non-canonical ct limb",
        { c1: good.c1, ct: [good.ct[0], good.ct[1], good.ct[2], P] },
      ],
    ];

    for (const [label, memo] of broken) {
      await expect(pool.spend({ ...sp, memo }), label).rejects.toThrow("invalid-memo");
      expect(pool.seenNullifiers.size, label).toBe(0);
      expect(pool.tree.leafCount(), label).toBe(2);
      expect(pool.spendLog, label).toHaveLength(0);
    }

    // The well-formed memo still settles.
    await pool.spend(sp);
    expect(pool.spendLog).toHaveLength(1);
  },
);

test(
  "a memo the pool did not validate is never the memo it stores",
  { timeout: 120_000 },
  async () => {
    // The structural defect: validating `pub.memo` while STORING a
    // reconstruction means the thing checked is not the thing kept, and
    // anything that differs between the two reads slips through. Both
    // witnesses below are that one defect, so both are fixed by taking the
    // snapshot FIRST and validating THAT.
    //
    // Task 11 would kill both witnesses by binding ct as [Field; 4] and c1
    // as [Field; 2], but it would NOT repair validate-A-store-B, and the
    // defect outlives any particular witness.
    const personSecret = 9121n;
    const rT = 101n;
    const aliceSk = 1131n;
    const pid = await personId(personSecret);
    const owed = [{ personId: pid, subtotal: 15000n, day: DAY }];

    const crossing = async (pool: Pool, depositIndex: number, rEnc: bigint) =>
      runSpend({
        personSecret,
        vIn: 20000n,
        ownerSk: aliceSk,
        rIn: BigInt(depositIndex),
        pathIn: pool.tree.path(depositIndex),
        v1: 15000n,
        pk1: await ownerPk(2222n),
        r1: 1011n,
        v2: 5000n,
        r2: 1012n,
        sOld: 0n,
        dOld: DAY,
        rT,
        pathT: pool.tree.path(0),
        rTNew: 1013n,
        rEnc,
        root: pool.tree.root(),
        dNow: DAY,
      });

    // WITNESS 1 -- arity. `Array.prototype.every` is vacuous past the end
    // of a short array, so a three-limb ct passes a per-limb predicate. A
    // snapshot that hard-codes four slots then stores [a, b, c, undefined],
    // which fails that same predicate -- and collect drops it in silence.
    // A payer who owes a disclosure would file none, and settle anyway.
    const a = await setupPool(personSecret, rT, aliceSk);
    const short = await crossing(a.pool, a.depositIndex, 10101n);
    expect(await decrypt(short.memo, ASK)).toEqual([1n, pid, 15000n, DAY]);
    const threeLimb = {
      c1: short.memo.c1,
      ct: [short.memo.ct[0], short.memo.ct[1], short.memo.ct[2]] as unknown as Limbs,
    };

    await expect(a.pool.spend({ ...short, memo: threeLimb })).rejects.toThrow(
      "invalid-memo",
    );

    // The over-length case is the same defect from the other side, and it
    // is the one a per-slot copy cannot catch: four hard-coded slots read
    // a five-limb ct as a well-formed four-limb one and store the
    // truncation, whereas a faithful copy preserves the arity for the
    // length check to reject. A memo whose arity is not four is not a memo.
    const fiveLimb = [...short.memo.ct, 7n] as unknown as Limbs;
    await expect(
      a.pool.spend({ ...short, memo: { c1: short.memo.c1, ct: fiveLimb } }),
    ).rejects.toThrow("invalid-memo");

    expect(a.pool.seenNullifiers.size).toBe(0);
    expect(a.pool.tree.leafCount()).toBe(2);
    expect(a.pool.spendLog).toHaveLength(0);

    // WITNESS 2 -- a second read that differs from the first. Whatever the
    // pool decides, the record it keeps must be the record it checked, so
    // the disclosure survives.
    const b = await setupPool(personSecret, rT, aliceSk);
    const real = await crossing(b.pool, b.depositIndex, 10102n);
    let reads = 0;
    const twoFaced: Memo = {
      get c1() {
        reads += 1;
        return reads === 1 ? real.memo.c1 : INF;
      },
      ct: real.memo.ct,
    };

    await b.pool.spend({ ...real, memo: twoFaced });
    expect(reads, "vacuity guard: the pool did read c1").toBeGreaterThan(0);
    expect(b.pool.spendLog).toHaveLength(1);
    expect(b.pool.spendLog[0].memo.c1.inf).toBe(false);
    expect((await collect(b.pool.spendLog.map((r) => r.memo), ASK)).disclosures).toEqual(
      owed,
    );
  },
);

test("the pool clock stays inside the circuit's 32-bit day range", async () => {
  // The spend circuit range-bounds both days to 32 bits (main.nr), so a
  // period index outside [0, 2^32) is one no spend can ever be proved
  // against: a pool whose clock reached the ceiling would accept nothing,
  // forever. Unreachable in practice at ~11.7M business days, but the
  // clock is exactly what the day rule pins, so the bound is explicit.
  const limit = 1n << BigInt(DAY_BITS);

  expect(() => new Pool(limit, APK)).toThrow(RangeError);
  expect(() => new Pool(-1n, APK)).toThrow(RangeError);
  expect(() => new Pool(limit - 1n, APK)).not.toThrow();

  const pool = new Pool(limit - 1n, APK);
  await expect(pool.advanceDay()).rejects.toThrow(RangeError);
  expect(pool.currentDay, "a refused rollover leaves the clock where it was").toBe(
    limit - 1n,
  );
});

test("collect survives a record it cannot decrypt", async () => {
  // Defence in depth for the auditor, who may read memos that never came
  // from this pool. A structurally invalid record carries no recoverable
  // plaintext, so skipping it discards nothing -- but throwing would
  // discard every honest disclosure batched with it.
  const pid = await personId(4242n);
  const real = await encrypt([1n, pid, 15000n, DAY], APK, 1234n);
  const poisoned: Memo = { c1: INF, ct: [0n, 0n, 0n, 0n] };

  const owed = [{ personId: pid, subtotal: 15000n, day: DAY }];
  const first = await collect([real, poisoned], ASK);
  expect(first.disclosures).toEqual(owed);
  // The skip must not be silent. Dropping the record loses no plaintext,
  // but it does hide the FACT that a malformed record was there, and after
  // the pool stopped admitting them that fact is the only signal anything
  // is wrong -- so collect names the records it could not read.
  expect(first.skipped).toEqual([1]);

  // Order must not matter: the bad record cannot shadow a later good one.
  const second = await collect([poisoned, real], ASK);
  expect(second.disclosures).toEqual(owed);
  expect(second.skipped).toEqual([0]);

  // A clean batch reports no skips at all.
  expect((await collect([real], ASK)).skipped).toEqual([]);
});

test(
  "a storage failure between inserts still leaves the consumed notes burnt",
  { timeout: 120_000 },
  async () => {
    // The fail-closed ordering, pinned. A spend performs three inserts, and
    // the pre-checks make every PREDICTABLE failure impossible -- but if the
    // store fails anyway, the consumed notes must already be burnt.
    // Destroying value beats leaving it spendable twice: inflation is the
    // worst class of bug in a shielded pool.
    const personSecret = 9119n;
    const rT = 99n;
    const aliceSk = 1129n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);

    const sp = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 6000n,
      pk1: await ownerPk(2222n),
      r1: 991n,
      v2: 14000n,
      r2: 992n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 993n,
      rEnc: 9901n,
      root: pool.tree.root(),
      dNow: DAY,
    });

    // Fail the SECOND insert, so the sequence dies partway through.
    const realInsert = pool.tree.insert.bind(pool.tree);
    let calls = 0;
    pool.tree.insert = async (leaf: bigint) => {
      calls += 1;
      if (calls === 2) throw new Error("simulated storage failure");
      return realInsert(leaf);
    };

    await expect(pool.spend(sp)).rejects.toThrow("simulated storage failure");

    // Both consumed notes are burnt, so neither can be spent again...
    expect(pool.seenNullifiers.has(sp.nPay.toString())).toBe(true);
    expect(pool.seenNullifiers.has(sp.nTally.toString())).toBe(true);
    // ...the spend never settled, so it is not on the transcript...
    expect(pool.spendLog).toHaveLength(0);
    // ...one leaf did land, and the root it produced was never recorded, so
    // no later proof can build on the half-written state. Recovering from a
    // real storage fault needs the operator, which is the intended outcome.
    expect(pool.tree.leafCount()).toBe(3);
    expect(pool.rootHistory.has(pool.tree.root().toString())).toBe(false);
  },
);

test(
  "after advanceDay a spend dated the new period is accepted and its subtotal resets",
  { timeout: 120_000 },
  async () => {
    // The legitimate counterpart to the tomorrow-dating evasion, and the
    // pin on what advanceDay actually means: it moves the clock to exactly
    // the period a next-period spend must declare. Days are opaque
    // consecutive indices, so this is `+ 1n` in both places or neither.
    const personSecret = 9120n;
    const rT = 100n;
    const aliceSk = 1130n;
    const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);
    const pid = await personId(personSecret);
    const bobPk = await ownerPk(2222n);

    const first = await runSpend({
      personSecret,
      vIn: 20000n,
      ownerSk: aliceSk,
      rIn: BigInt(depositIndex),
      pathIn: pool.tree.path(depositIndex),
      v1: 9900n,
      pk1: bobPk,
      r1: 1001n,
      v2: 10100n,
      r2: 1002n,
      sOld: 0n,
      dOld: DAY,
      rT,
      pathT: pool.tree.path(0),
      rTNew: 1003n,
      rEnc: 10001n,
      root: pool.tree.root(),
      dNow: DAY,
    });
    await pool.spend(first);

    await pool.advanceDay();
    expect(pool.currentDay).toBe(DAY + 1n);

    // The same 5000 that was an evasion when self-dated is legitimate now
    // that the pool's own clock has moved: subtotal restarts, memo dummy.
    const next = await runSpend({
      personSecret,
      vIn: 10100n,
      ownerSk: aliceSk,
      rIn: 1002n,
      pathIn: pool.tree.path(3),
      v1: 5000n,
      pk1: bobPk,
      r1: 1004n,
      v2: 5100n,
      r2: 1005n,
      sOld: 9900n,
      dOld: DAY,
      rT: 1003n,
      pathT: pool.tree.path(4),
      rTNew: 1006n,
      rEnc: 10002n,
      root: pool.tree.root(),
      dNow: DAY + 1n,
    });
    await pool.spend(next);

    expect(await decrypt(next.memo, ASK)).toEqual([0n, 0n, 0n, 0n]);
    expect(next.cTallyNew).toBe(await tallyCommit(pid, 5000n, DAY + 1n, 1006n));
    expect(pool.tree.leafCount()).toBe(8);
    expect(pool.spendLog).toHaveLength(2);
  },
);

test("a pool with no auditor key configured accepts no spends", { timeout: 120_000 }, async () => {
  // The auditor key is a launch parameter: without one the pool has nothing
  // to pin a memo against, so it must refuse rather than wave spends
  // through. (Pools built for enrollment-only tests take no key.)
  const personSecret = 9113n;
  const rT = 93n;
  const aliceSk = 1123n;
  const { pool, depositIndex } = await setupPool(personSecret, rT, aliceSk);

  const sp = await runSpend({
    personSecret,
    vIn: 20000n,
    ownerSk: aliceSk,
    rIn: BigInt(depositIndex),
    pathIn: pool.tree.path(depositIndex),
    v1: 6000n,
    pk1: await ownerPk(2222n),
    r1: 931n,
    v2: 14000n,
    r2: 932n,
    sOld: 0n,
    dOld: DAY,
    rT,
    pathT: pool.tree.path(0),
    rTNew: 933n,
    rEnc: 9301n,
    root: pool.tree.root(),
    dNow: DAY,
  });

  const keyless = new Pool(DAY);
  expect(keyless.auditorKey).toBe(null);
  await expect(keyless.spend(sp)).rejects.toThrow("no-auditor-key");
});

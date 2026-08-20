import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, expect, test } from "vitest";
import { compile, execute } from "../src/prove.js";
import { closePoseidon } from "../src/poseidon.js";
import { type Path } from "../src/merkle.js";
import {
  noteNullifier,
  ownerPk,
  paymentCommit,
  personId,
  tallyCommit,
} from "../src/notes.js";
import { Pool, type EnrollOutput, type SpendPublicInputs } from "../src/pool.js";
import { P, T_THRESHOLD } from "../src/constants.js";
import { GRUMPKIN_ORDER, isOnCurve } from "../src/grumpkin.js";
import { decrypt, encrypt, keygen, type Limbs } from "../src/elgamal.js";
import { collect } from "../src/auditor.js";

// The end-to-end scenario: one pool, one day, two people, three wallets, and
// the whole protocol exercised as a narrative rather than a rule at a time.
// Everything below runs against the real circuits and the real pool -- the
// enrollment and spend witnesses are executed, and every spend is submitted
// through `pool.spend`, so nothing here is a stand-in for acceptance.
//
// The scenario, in the plan's eight steps:
//
//   1. Alice enrolls with passport-mock secret s_A; Bob with s_B.
//   2. Alice funds TWO wallets under DIFFERENT owner keys; Bob funds one.
//   3. Alice spends 6000 from wallet A1        -> subtotal 6000, dummy memo.
//   4. Alice spends 5000 from wallet A2        -> subtotal 11000 > T, REAL
//      disclosure. This is the claim the protocol exists to make: a second
//      wallet is not a second allowance.
//   5. Bob spends 9000 -- more in one payment than either of Alice's -- and
//      discloses nothing, because HE has not crossed.
//   6. Alice tries to re-enroll to reset her tally: duplicate-enrollment.
//   7. The public transcript names nobody and hides which spend disclosed.
//   8. The day rolls over; Alice's subtotal restarts.
//
// TASK 11 BOUNDARY, as everywhere else in this suite: an executed witness
// stands in for a verified proof (see the note at the top of pool.ts). What
// that stand-in does NOT weaken is anything below, because every spend here
// is honestly generated -- the executions establish that these flows are
// realizable, and the pool then judges them under its real rules.
//
// ORDER-DEPENDENT BY DESIGN. This is one continuous history, so the tests
// share a pool and run in declaration order (vitest runs a file's tests
// sequentially). Running a later test alone starves the state it needs;
// run the whole file.

const SPEND_DIR = fileURLToPath(new URL("../../circuits/spend/", import.meta.url));
const ENROLLMENT_DIR = fileURLToPath(
  new URL("../../circuits/enrollment/", import.meta.url),
);
const toHex = (v: bigint) => "0x" + v.toString(16);
const MASK_128 = (1n << 128n) - 1n;

// An opaque period index, not a date -- see Pool.currentDay. This suite calls
// advanceDay, so it uses a plain counter: a YYYYMMDD-shaped fixture would
// make `DAY + 1n` read as "the next day" and quietly mislead.
const DAY = 500n;

// The auditor keypair. ASK never leaves the auditor; APK is the pool's
// launch parameter and the key every memo must encrypt to.
const ASK = 271828n;
const APK = keygen(ASK);

// Passport-mock person secrets. In a deployment these come out of the
// credential layer; here they stand for "the one secret a person has".
const S_A = 4_000_001n;
const S_B = 4_000_002n;

// Wallet spending keys. Alice's two wallets are unrelated at the key level --
// that is the point of step 4 -- and Carol is the recipient throughout.
const ALICE_A1_SK = 1_100_001n;
const ALICE_A2_SK = 1_100_002n;
const BOB_SK = 1_200_001n;
const CAROL_SK = 1_300_001n;

// Deposits and payments. The relations between these amounts are what makes
// the scenario demonstrate the claim, so step 4 and step 5 assert them
// rather than leaving them as fixture trivia.
const DEPOSIT_A1 = 20_000n;
const DEPOSIT_A2 = 8_000n;
const DEPOSIT_B = 20_000n;
const PAY_A1 = 6_000n;
const PAY_A2 = 5_000n;
const PAY_B = 9_000n;
const PAY_A_NEXT_DAY = 4_000n;

// Note salts, one per output. Distinct everywhere so no two commitments can
// coincide by accident.
const R_A1_OUT = 5001n, R_A1_CHANGE = 5002n, R_A1_TALLY = 5003n;
const R_A2_OUT = 5011n, R_A2_CHANGE = 5012n, R_A2_TALLY = 5013n;
const R_B_OUT = 5021n, R_B_CHANGE = 5022n, R_B_TALLY = 5023n;
const R_NEXT_OUT = 5031n, R_NEXT_CHANGE = 5032n, R_NEXT_TALLY = 5033n;
const R_T_A = 5101n, R_T_B = 5102n, R_T_A_REENROLL = 5199n;

// Leaf indices, asserted as the scenario fills them. Enrollment and deposit
// each add one leaf; every accepted spend adds exactly three, as
// (c_out1, c_out2, c_tally_new) -- the contiguous block Task 9 pins.
const LEAF_TALLY_A = 0;
const LEAF_TALLY_B = 1;
const LEAF_WALLET_A1 = 2;
const LEAF_WALLET_A2 = 3;
const LEAF_WALLET_B = 4;
const LEAF_A1_CHANGE = 6;
const LEAF_A1_TALLY = 7;
const LEAF_A2_TALLY = 10;

// ---- the scenario's running state -------------------------------------
// One pool, one history. Assigned by the step 1-2 test and read by the rest.

let pool: Pool;
let pidA: bigint;
let pidB: bigint;
let aliceA1Pk: bigint;
let aliceA2Pk: bigint;
let bobPk: bigint;
let carolPk: bigint;
let enrollA: EnrollOutput;
let enrollB: EnrollOutput;
let depositA1: bigint;
let depositA2: bigint;
let depositB: bigint;
let spendA1: SpendPublicInputs;
let spendA2: SpendPublicInputs;
let spendB: SpendPublicInputs;
let spendNextDay: SpendPublicInputs;

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
  /**
   * Publish the encryption of THIS message instead of the one the flow
   * requires. Only step 4 uses it, to show that a crossing spend cannot
   * settle with a dummy memo.
   */
  forceMemo?: Limbs;
}

/**
 * Runs one spend through the circuit and repackages the result as the
 * operator-visible record: the public inputs the prover chose plus the five
 * public outputs. The memo is derived the way a wallet would -- the message
 * the payer's threshold position dictates, encrypted to the auditor key --
 * so a returned record is one the circuit certified.
 */
async function runSpend(w: SpendWitness): Promise<SpendPublicInputs> {
  const sNew = w.dNow === w.dOld ? w.sOld + w.v1 : w.v1;
  const required: Limbs =
    sNew > T_THRESHOLD
      ? [1n, await personId(w.personSecret), sNew, w.dNow]
      : [0n, 0n, 0n, 0n];
  const memo = await encrypt(w.forceMemo ?? required, APK, w.rEnc);
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
  return {
    root: w.root,
    dNow: w.dNow,
    tThreshold: T_THRESHOLD,
    apkX: APK.x,
    apkY: APK.y,
    memo,
    nPay,
    nTally,
    cOut1,
    cOut2,
    cTallyNew,
  };
}

/** What the auditor recovers from the whole transcript, in memo order. */
async function auditorView() {
  return collect(
    pool.spendLog.map((record) => record.memo),
    ASK,
  );
}

// ---- step 7's instruments ----------------------------------------------
// Step 7 is a PRIVACY assertion, and a weak version of it would be worse
// than none, because the paper cites this property ("What an observer
// sees": per spend, two nullifiers, three fresh commitments, one memo, all
// of fixed shape; and per-person state never visible as a repeated value).
// So the sweep below walks records structurally rather than checking a
// hand-listed set of fields: a field added later is swept automatically,
// and a value that is not a field element is COUNTED rather than skipped,
// so it cannot hide from the search by changing representation.
//
// That second property is easy to write and easy to get wrong, and an
// earlier version of this file did. Enumerating with `Object.values` and
// recursing into every object silently misses Map and Set contents,
// non-enumerable properties and Symbol keys -- and, worse, such a value
// lands in NEITHER bucket, so it defeats the count pins too. `pid_A` could
// be hidden three separate ways with the whole file green. `walk` therefore
// enumerates own keys and treats only PLAIN objects and arrays as
// transparent; everything else is counted, not entered.
//
// The lesson generalises past this file: a mutation matrix proves the
// assertions bite on the values they name, and says nothing about whether
// the instrument surveys the surface it claims to. When a test's value is
// COVERAGE, mutate the surface and the representation, not just the values.

/**
 * Recursively splits a value into the field elements it contains and
 * everything else. `others` exists so the sweep cannot pass vacuously: a
 * value stored as a string or number would land there instead of being
 * silently ignored, and step 7 pins both counts.
 */
function walk(value: unknown, fields: bigint[], others: unknown[]): void {
  if (typeof value === "bigint") {
    fields.push(value);
    return;
  }
  // Own keys, not `Object.values`: a non-enumerable or Symbol-keyed property
  // is still a property of the published record, and enumerating by value
  // would step straight past it.
  if (Array.isArray(value)) {
    for (const key of Reflect.ownKeys(value)) {
      if (key === "length") continue;
      walk((value as unknown as Record<PropertyKey, unknown>)[key], fields, others);
    }
    return;
  }
  // Only a PLAIN object is transparent. Anything exotic -- a Map, a Set, a
  // Date, a typed array, a class instance, a null-prototype object -- is
  // COUNTED as an other rather than recursed into. That distinction is the
  // whole point: recursing into a container we cannot enumerate faithfully
  // would let a value hide from BOTH buckets at once, so it would defeat the
  // count pins as well as the search. Landing in `others` makes it loud.
  if (
    typeof value === "object" &&
    value !== null &&
    Object.getPrototypeOf(value) === Object.prototype
  ) {
    for (const key of Reflect.ownKeys(value)) {
      walk((value as Record<PropertyKey, unknown>)[key], fields, others);
    }
    return;
  }
  others.push(value);
}

function partition(record: SpendPublicInputs) {
  const fields: bigint[] = [];
  const others: unknown[] = [];
  walk(record, fields, others);
  return { fields, others };
}

/** The canonical fixed-width encoding of a field element: 32 bytes, always. */
const toBytes32 = (v: bigint) => v.toString(16).padStart(64, "0");

/**
 * Everything about a transcript record that an observer WITHOUT the auditor
 * key can measure: which fields exist, of what types, how many field
 * elements they hold, what the non-field values are, and the memo's arity.
 * Encoded length is deliberately absent: it is `fieldCount * 64` identically,
 * so including it would restate a comparison already made. Two records that agree here
 * are indistinguishable on shape -- which is the on-chain half of the
 * uniformity result. What they encode to is deliberately NOT part of this:
 * the values differ, and must, or the records would be literally identical.
 */
function observableShape(record: SpendPublicInputs) {
  const { fields, others } = partition(record);
  return {
    keys: Object.keys(record).sort(),
    types: Object.entries(record)
      .map(([key, value]) => `${key}: ${typeof value}`)
      .sort(),
    fieldCount: fields.length,
    nonFieldValues: others,
    memoKeys: Object.keys(record.memo).sort(),
    c1Keys: Object.keys(record.memo.c1).sort(),
    ctLength: record.memo.ct.length,
  };
}

/** The canonical encoding of a whole record: every field element, in order. */
const encodeRecord = (record: SpendPublicInputs) =>
  partition(record).fields.map(toBytes32).join("");

/**
 * Every value the pool has made public: the spend transcript walked to its
 * leaves, the three nullifier/root sets, and the enrollment and deposit
 * artifacts the operator handled directly. Keyed by decimal string, the
 * harness-wide set-key encoding.
 */
function publishedBySource(): Record<string, Set<string>> {
  const spendLog = new Set<string>();
  for (const record of pool.spendLog) {
    for (const field of partition(record).fields) spendLog.add(field.toString());
  }
  const enrollments = new Set<string>();
  for (const enrollment of [enrollA, enrollB]) {
    enrollments.add(enrollment.E.toString());
    enrollments.add(enrollment.cT.toString());
    enrollments.add(enrollment.dNow.toString());
  }
  const deposits = new Set<string>();
  for (const commit of [depositA1, depositA2, depositB]) {
    deposits.add(commit.toString());
  }
  return {
    spendLog,
    rootHistory: new Set(pool.rootHistory),
    seenNullifiers: new Set(pool.seenNullifiers),
    seenEnrollments: new Set(pool.seenEnrollments),
    enrollments,
    deposits,
  };
}

/** The union of every source. Kept derived so a source cannot be dropped here. */
function published(): Set<string> {
  const values = new Set<string>();
  for (const source of Object.values(publishedBySource())) {
    for (const value of source) values.add(value);
  }
  return values;
}

/**
 * No person identifier and no person secret occurs anywhere the pool has
 * published, at any depth. Every record's structure is pinned at the same
 * time, so the sweep cannot quietly stop covering a field.
 */
function assertNoIdentifiersPublished() {
  // Each record must be exactly what the paper says an observer sees:
  // sixteen field elements -- root, day, threshold, both auditor-key
  // coordinates, the memo's two point coordinates and four ciphertext
  // limbs, two nullifiers and three commitments -- plus one non-field
  // value, the point's `inf` flag.
  for (const [index, record] of pool.spendLog.entries()) {
    const { fields, others } = partition(record);
    expect(fields, `record ${index}: field element count`).toHaveLength(16);
    expect(others, `record ${index}: non-field values`).toEqual([false]);
  }

  const values = published();

  // Vacuity guard, part 1 -- SURFACE. Every source must exist, contribute
  // something, and be covered by the union. Without this a source could be
  // dropped from `published()` and the sweep would still pass, because the
  // remaining sources satisfy the value-level guards below on their own: a
  // record's own nullifier is in the transcript as well as in the nullifier
  // set, so no single value can isolate a set. Pinning the source LIST and
  // each source's coverage is what makes deleting any one of the six go red.
  const sources = publishedBySource();
  expect(Object.keys(sources).sort(), "the swept surface itself").toEqual([
    "deposits",
    "enrollments",
    "rootHistory",
    "seenEnrollments",
    "seenNullifiers",
    "spendLog",
  ]);
  for (const [name, source] of Object.entries(sources)) {
    expect(source.size, `source ${name} contributed nothing`).toBeGreaterThan(0);
    for (const value of source) {
      expect(values.has(value), `source ${name} is not covered by published()`).toBe(
        true,
      );
    }
  }

  // Vacuity guard, part 2 -- DEPTH. The search must actually reach the values
  // it claims to have searched, INCLUDING the ones nested inside the memo.
  // Without these, a walk that returned nothing would "prove" perfect privacy.
  const witness = pool.spendLog[0];
  expect(values.has(witness.cTallyNew.toString()), "a top-level commitment").toBe(true);
  expect(values.has(witness.memo.c1.x.toString()), "a nested point coordinate").toBe(
    true,
  );
  expect(values.has(witness.memo.ct[3].toString()), "a nested ciphertext limb").toBe(
    true,
  );
  expect(values.has(enrollA.E.toString()), "an enrollment nullifier").toBe(true);
  expect(values.has(witness.nTally.toString()), "a burnt nullifier").toBe(true);

  // The property itself. pid is a scoped hash of the person secret and the
  // paper's disclosure argument turns on the auditor being the only party
  // that ever sees one; a person secret appearing anywhere would be worse
  // still, since it is the whole credential.
  for (const [label, secret] of [
    ["pid_A", pidA],
    ["pid_B", pidB],
    ["s_A", S_A],
    ["s_B", S_B],
  ] as const) {
    expect(
      values.has(secret.toString()),
      `${label} must never occur as a published field value`,
    ).toBe(false);
  }
}

/**
 * Every spend record has the same observable shape as every other, and each
 * memo is a well-formed ciphertext with no all-zero tell. Callers pass the
 * below/above pair they care about so the comparison that matters is named
 * rather than merely included in a sweep.
 */
function assertRecordsAreShapeIdentical(below: SpendPublicInputs, above: SpendPublicInputs) {
  // The headline comparison: a spend that disclosed nothing against a spend
  // that filed a real report.
  expect(observableShape(above)).toEqual(observableShape(below));
  // ...and it is not vacuous by being the same record twice, nor by the two
  // encoding identically -- they are different payments and must differ.
  expect(above).not.toBe(below);
  expect(encodeRecord(above)).not.toBe(encodeRecord(below));
  // No length comparison here on purpose: p is 254 bits, so `toBytes32` is 64
  // characters for EVERY field element and equal encoded length follows
  // identically from the field counts already compared above. Asserting it
  // would read as independent evidence while proving nothing.

  // The same shape holds across the whole transcript, not just that pair.
  const reference = observableShape(pool.spendLog[0]);
  for (const [index, record] of pool.spendLog.entries()) {
    expect(observableShape(record), `record ${index}`).toEqual(reference);

    // Nothing about the memo separates a report from a dummy: a genuine
    // curve point, four canonical limbs, and no limb left at zero -- so
    // "the all-zero one is the dummy" is not a distinguisher either. The
    // dummy encrypts zeros; it does not publish them.
    expect(record.memo.c1.inf, `record ${index}`).toBe(false);
    expect(isOnCurve(record.memo.c1), `record ${index}`).toBe(true);
    expect(record.memo.ct, `record ${index}`).toHaveLength(4);
    for (const [limb, value] of record.memo.ct.entries()) {
      expect(value >= 0n && value < P, `record ${index} limb ${limb}`).toBe(true);
      expect(value, `record ${index} limb ${limb}`).not.toBe(0n);
    }
  }
}

beforeAll(() => {
  // Recompile both circuits so the scenario never runs on stale bytecode.
  compile(ENROLLMENT_DIR);
  compile(SPEND_DIR);
}, 240_000);

afterAll(async () => {
  await closePoseidon();
});

test(
  "steps 1-2: Alice and Bob enroll, and Alice funds two wallets under different owner keys",
  { timeout: 120_000 },
  async () => {
    pool = new Pool(DAY, APK);
    pidA = await personId(S_A);
    pidB = await personId(S_B);
    aliceA1Pk = await ownerPk(ALICE_A1_SK);
    aliceA2Pk = await ownerPk(ALICE_A2_SK);
    bobPk = await ownerPk(BOB_SK);
    carolPk = await ownerPk(CAROL_SK);

    // One enrollment per person, each minting that person's genesis tally
    // note: subtotal 0, today's period, and their pid bound inside it.
    enrollA = await runEnrollment(S_A, R_T_A, DAY);
    enrollB = await runEnrollment(S_B, R_T_B, DAY);
    await pool.enroll(enrollA);
    await pool.enroll(enrollB);
    expect(enrollA.cT).toBe(await tallyCommit(pidA, 0n, DAY, R_T_A));
    expect(enrollB.cT).toBe(await tallyCommit(pidB, 0n, DAY, R_T_B));
    expect(pool.seenEnrollments.size).toBe(2);

    // Alice's two wallets are unrelated as far as the pool can tell: two
    // different spending keys, therefore two different owner keys, and two
    // deposits that share nothing. Nothing on-chain ties them together --
    // which is precisely why step 4 is the interesting one.
    expect(ALICE_A2_SK).not.toBe(ALICE_A1_SK);
    expect(aliceA2Pk).not.toBe(aliceA1Pk);

    ({ commit: depositA1 } = await pool.deposit(DEPOSIT_A1, aliceA1Pk));
    ({ commit: depositA2 } = await pool.deposit(DEPOSIT_A2, aliceA2Pk));
    ({ commit: depositB } = await pool.deposit(DEPOSIT_B, bobPk));

    // Deposit salts are the leaf index by convention (Task 7), which is what
    // each wallet later supplies as its note's `r` witness.
    expect(depositA1).toBe(
      await paymentCommit(DEPOSIT_A1, aliceA1Pk, BigInt(LEAF_WALLET_A1)),
    );
    expect(depositA2).toBe(
      await paymentCommit(DEPOSIT_A2, aliceA2Pk, BigInt(LEAF_WALLET_A2)),
    );
    expect(depositB).toBe(await paymentCommit(DEPOSIT_B, bobPk, BigInt(LEAF_WALLET_B)));

    // Two genesis tallies then three deposits: leaves 0-4.
    expect(pool.tree.leafCount()).toBe(5);
    expect(pool.spendLog).toHaveLength(0);
  },
);

test(
  "step 3: Alice's 6000 from wallet A1 settles under the threshold with a dummy memo",
  { timeout: 120_000 },
  async () => {
    spendA1 = await runSpend({
      personSecret: S_A,
      vIn: DEPOSIT_A1,
      ownerSk: ALICE_A1_SK,
      rIn: BigInt(LEAF_WALLET_A1),
      pathIn: pool.tree.path(LEAF_WALLET_A1),
      v1: PAY_A1,
      pk1: carolPk,
      r1: R_A1_OUT,
      v2: DEPOSIT_A1 - PAY_A1,
      r2: R_A1_CHANGE,
      sOld: 0n,
      dOld: DAY,
      rT: R_T_A,
      pathT: pool.tree.path(LEAF_TALLY_A),
      rTNew: R_A1_TALLY,
      rEnc: 6001n,
      root: pool.tree.root(),
      dNow: DAY,
    });
    await pool.spend(spendA1);

    // 6000 <= T: nothing to disclose, and what the auditor reads is the
    // all-zero dummy.
    expect(PAY_A1).toBeLessThanOrEqual(T_THRESHOLD);
    expect(await decrypt(spendA1.memo, ASK)).toEqual([0n, 0n, 0n, 0n]);
    expect((await auditorView()).disclosures).toEqual([]);

    // The tally chain starts at Alice's enrollment: this spend consumed the
    // genesis tally note and produced her subtotal for the day.
    expect(spendA1.nPay).toBe(await noteNullifier(ALICE_A1_SK, depositA1));
    expect(spendA1.nTally).toBe(await noteNullifier(S_A, enrollA.cT));
    expect(spendA1.cTallyNew).toBe(await tallyCommit(pidA, PAY_A1, DAY, R_A1_TALLY));
    expect(spendA1.cOut2).toBe(
      await paymentCommit(DEPOSIT_A1 - PAY_A1, aliceA1Pk, R_A1_CHANGE),
    );

    // Three leaves, in the pinned order: c_out1, c_out2, c_tally_new.
    expect(pool.tree.leafCount()).toBe(8);
    expect(pool.spendLog).toHaveLength(1);
  },
);

test(
  "step 4: THE CENTRAL CLAIM -- a second wallet is not a second allowance, so Alice's 5000 from A2 " +
    "crosses her person-level threshold and forces a real disclosure the auditor recovers as (pid_A, 11000, d)",
  { timeout: 120_000 },
  async () => {
    // This step is the entire point of the protocol and the claim the paper
    // is built on. Alice pays from a wallet whose owner_sk is unrelated to
    // the one she used in step 3. Nothing on-chain links the two wallets.
    // But the tally is bound to the PERSON, not the wallet: the circuit
    // derives the consumed tally note from `person_secret` and keys its
    // nullifier with the same value, so the only tally note Alice can
    // consume from ANY wallet is the one her last spend produced. Her
    // subtotal therefore accumulates across wallets -- 6000 + 5000 = 11000 --
    // and the threshold branch becomes satisfiable only with a real report.
    //
    // The two payments in isolation would each disclose nothing. It is the
    // person who crossed, not either payment.
    expect(PAY_A1).toBeLessThanOrEqual(T_THRESHOLD);
    expect(PAY_A2).toBeLessThanOrEqual(T_THRESHOLD);
    expect(PAY_A1 + PAY_A2).toBeGreaterThan(T_THRESHOLD);

    const fromWalletA2: SpendWitness = {
      personSecret: S_A,
      vIn: DEPOSIT_A2,
      // DIFFERENT WALLET: A2's spending key, not A1's.
      ownerSk: ALICE_A2_SK,
      rIn: BigInt(LEAF_WALLET_A2),
      pathIn: pool.tree.path(LEAF_WALLET_A2),
      v1: PAY_A2,
      pk1: carolPk,
      r1: R_A2_OUT,
      v2: DEPOSIT_A2 - PAY_A2,
      r2: R_A2_CHANGE,
      // SAME TALLY CHAIN: the note step 3 produced, carrying 6000.
      sOld: PAY_A1,
      dOld: DAY,
      rT: R_A1_TALLY,
      pathT: pool.tree.path(LEAF_A1_TALLY),
      rTNew: R_A2_TALLY,
      // A scalar above 2^128, so the crossing spend -- the one that matters
      // most -- also exercises the nonzero-hi-limb handoff through the ABI.
      rEnc: (1n << 128n) + 6002n,
      root: pool.tree.root(),
      dNow: DAY,
    };

    // The disclosure is FORCED, not merely emitted. This exact witness,
    // published with a well-formed dummy memo instead of the report it owes,
    // is unsatisfiable -- so Alice cannot settle the crossing payment
    // silently. (c1 depends only on r_enc, so it still matches and the
    // failure isolates to the ciphertext equality.) Attempted BEFORE the
    // honest spend, while the root and paths it references are still live.
    await expect(
      runSpend({ ...fromWalletA2, forceMemo: [0n, 0n, 0n, 0n] }),
      "a crossing spend must not be satisfiable with a dummy memo",
    ).rejects.toThrow("spend: memo ct mismatch");

    // The other way out of the chain, also closed -- and closed at the other
    // layer, which is why both belong here. Nothing in the CIRCUIT stops
    // Alice from opening her GENESIS tally again from the second wallet:
    // leaf 0 is still a real leaf under the current root, so the proof below
    // is fully satisfiable, its subtotal restarts at 5000, and it settles
    // with a dummy memo. What stops it is that a tally chain is a chain --
    // step 3 already burnt that note's nullifier.
    const reusingTheSpentTally = await runSpend({
      ...fromWalletA2,
      sOld: 0n,
      rT: R_T_A,
      pathT: pool.tree.path(LEAF_TALLY_A),
      rEnc: 6012n,
    });
    expect(
      await decrypt(reusingTheSpentTally.memo, ASK),
      "the evasion would disclose nothing -- 11000 moved, T = 10000",
    ).toEqual([0n, 0n, 0n, 0n]);
    expect(reusingTheSpentTally.nTally).toBe(spendA1.nTally);
    await expect(pool.spend(reusingTheSpentTally)).rejects.toThrow("double-spend");
    expect(pool.spendLog, "the rejection left no trace").toHaveLength(1);

    spendA2 = await runSpend(fromWalletA2);
    await pool.spend(spendA2);

    // The payment side is genuinely the second wallet: this spend burnt a
    // note owned by A2's key, using A2's secret.
    expect(spendA2.nPay).toBe(await noteNullifier(ALICE_A2_SK, depositA2));
    expect(spendA2.nPay).not.toBe(spendA1.nPay);
    expect(spendA2.cOut2).toBe(
      await paymentCommit(DEPOSIT_A2 - PAY_A2, aliceA2Pk, R_A2_CHANGE),
    );

    // THE MECHANISM, in one line: the tally note this second wallet consumed
    // is exactly the one the FIRST wallet's spend created. The chain is the
    // person's, and it is single.
    expect(
      spendA2.nTally,
      "the second wallet consumed the tally note the first wallet produced",
    ).toBe(await noteNullifier(S_A, spendA1.cTallyNew));

    // THE CONSEQUENCE: the subtotal accumulated across wallets and crossed.
    expect(spendA2.cTallyNew).toBe(
      await tallyCommit(pidA, PAY_A1 + PAY_A2, DAY, R_A2_TALLY),
    );
    expect(await decrypt(spendA2.memo, ASK)).toEqual([1n, pidA, 11_000n, DAY]);

    // THE OUTCOME the auditor sees: exactly one report, naming Alice's
    // person id, her day subtotal, and the day -- and nothing else.
    const { disclosures, skipped } = await auditorView();
    expect(
      skipped,
      "every memo on this transcript is a circuit-certified ciphertext",
    ).toEqual([]);
    expect(disclosures).toEqual([{ personId: pidA, subtotal: 11_000n, day: DAY }]);

    expect(pool.tree.leafCount()).toBe(11);
    expect(pool.spendLog).toHaveLength(2);
  },
);

test(
  "step 5: Bob moves more in one payment than either of Alice's and still discloses nothing",
  { timeout: 120_000 },
  async () => {
    // The per-transaction / per-person distinction, made concrete. Bob's
    // single 9000 payment is larger than either of Alice's, and larger than
    // her 6000 that also stayed silent -- but Bob has not crossed, so
    // nothing is filed. A per-transaction trigger would have this backwards.
    expect(PAY_B).toBeGreaterThan(PAY_A1);
    expect(PAY_B).toBeGreaterThan(PAY_A2);
    expect(PAY_B).toBeLessThanOrEqual(T_THRESHOLD);

    spendB = await runSpend({
      personSecret: S_B,
      vIn: DEPOSIT_B,
      ownerSk: BOB_SK,
      rIn: BigInt(LEAF_WALLET_B),
      pathIn: pool.tree.path(LEAF_WALLET_B),
      v1: PAY_B,
      pk1: carolPk,
      r1: R_B_OUT,
      v2: DEPOSIT_B - PAY_B,
      r2: R_B_CHANGE,
      sOld: 0n,
      dOld: DAY,
      rT: R_T_B,
      pathT: pool.tree.path(LEAF_TALLY_B),
      rTNew: R_B_TALLY,
      rEnc: 6003n,
      root: pool.tree.root(),
      dNow: DAY,
    });
    await pool.spend(spendB);

    expect(spendB.nTally).toBe(await noteNullifier(S_B, enrollB.cT));
    expect(spendB.cTallyNew).toBe(await tallyCommit(pidB, PAY_B, DAY, R_B_TALLY));
    expect(await decrypt(spendB.memo, ASK)).toEqual([0n, 0n, 0n, 0n]);

    // The auditor's collection is unchanged: still Alice's one report, and
    // nothing whatsoever about Bob.
    const { disclosures, skipped } = await auditorView();
    expect(skipped).toEqual([]);
    expect(disclosures.filter((d) => d.personId === pidB)).toEqual([]);
    expect(disclosures).toEqual([{ personId: pidA, subtotal: 11_000n, day: DAY }]);

    expect(pool.tree.leafCount()).toBe(14);
    expect(pool.spendLog).toHaveLength(3);
  },
);

test(
  "step 6: Alice cannot re-enroll to hand herself a fresh tally chain",
  { timeout: 120_000 },
  async () => {
    // The obvious way out of a person-bound limit is to become a second
    // person. The enrollment nullifier E is a deterministic function of the
    // person secret ALONE -- a fresh tally salt changes the genesis note but
    // not E -- so the pool recognizes the re-enrollment and refuses it.
    const again = await runEnrollment(S_A, R_T_A_REENROLL, DAY);
    expect(again.E, "E is determined by the person secret, not the salt").toBe(
      enrollA.E,
    );
    expect(again.cT, "the genesis note itself is different -- E is what pins it").not.toBe(
      enrollA.cT,
    );

    await expect(pool.enroll(again)).rejects.toThrow("duplicate-enrollment");

    // The refusal changed nothing: no second genesis tally landed, so Alice
    // still has exactly one live chain, still carrying 11000 for the day.
    expect(pool.seenEnrollments.size).toBe(2);
    expect(pool.tree.leafCount()).toBe(14);
    expect(pool.tree.hasLeaf(again.cT)).toBe(false);
    expect(pool.spendLog).toHaveLength(3);
  },
);

test(
  "step 7: the public transcript names nobody, and a spend that disclosed is shaped exactly like one that did not",
  async () => {
    // The privacy side of the ledger, and the one step here that is a claim
    // about what CANNOT be seen. Two properties, both cited by the paper.
    //
    // First: per-person state is never visible as a repeated value. Neither
    // person id nor either person secret occurs anywhere the pool published,
    // at any depth -- the sweep walks each record to its leaves, including
    // the memo's point coordinates and every ciphertext limb, and also
    // covers the nullifier sets, the root history, and the enrollment and
    // deposit artifacts.
    assertNoIdentifiersPublished();

    // Second: the memo does not announce the crossing it reports. Establish
    // WITH the auditor key that these two records really are opposites --
    // record 0 disclosed nothing, record 1 filed a real report...
    const below = pool.spendLog[0];
    const above = pool.spendLog[1];
    expect(await decrypt(below.memo, ASK)).toEqual([0n, 0n, 0n, 0n]);
    expect(await decrypt(above.memo, ASK)).toEqual([1n, pidA, 11_000n, DAY]);

    // ...and then that WITHOUT it they are indistinguishable on every
    // structural measure an observer has: the same fields of the same types,
    // the same count of field elements, the same memo arity, and canonical
    // encodings of identical length.
    assertRecordsAreShapeIdentical(below, above);

    // Scope, stated honestly: this is the structural precondition the
    // paper's unlinkability argument needs -- no identifier is published and
    // the memo carries no shape tell -- not the game-based property itself,
    // which rests on commitment hiding, nullifier pseudorandomness, and
    // IND-CPA security of the memo encryption.
  },
);

test(
  "step 8: after the day rolls over Alice's subtotal restarts and 4000 settles silently",
  { timeout: 120_000 },
  async () => {
    await pool.advanceDay();
    expect(pool.currentDay).toBe(DAY + 1n);

    // Alice spends her step-3 change note on the new period, consuming the
    // tally that carries 11000 from the old one. The rollover is decided
    // in-circuit by d_now != d_old, so the subtotal restarts at v1.
    spendNextDay = await runSpend({
      personSecret: S_A,
      vIn: DEPOSIT_A1 - PAY_A1,
      ownerSk: ALICE_A1_SK,
      rIn: R_A1_CHANGE,
      pathIn: pool.tree.path(LEAF_A1_CHANGE),
      v1: PAY_A_NEXT_DAY,
      pk1: carolPk,
      r1: R_NEXT_OUT,
      v2: DEPOSIT_A1 - PAY_A1 - PAY_A_NEXT_DAY,
      r2: R_NEXT_CHANGE,
      sOld: PAY_A1 + PAY_A2,
      dOld: DAY,
      rT: R_A2_TALLY,
      pathT: pool.tree.path(LEAF_A2_TALLY),
      rTNew: R_NEXT_TALLY,
      rEnc: 6004n,
      root: pool.tree.root(),
      dNow: DAY + 1n,
    });
    await pool.spend(spendNextDay);

    // The reset is real: the new tally binds 4000 on the new period, not
    // 15000 carried over -- and the memo is a dummy again.
    expect(spendNextDay.cTallyNew).toBe(
      await tallyCommit(pidA, PAY_A_NEXT_DAY, DAY + 1n, R_NEXT_TALLY),
    );
    expect(spendNextDay.nTally).toBe(await noteNullifier(S_A, spendA2.cTallyNew));
    expect(await decrypt(spendNextDay.memo, ASK)).toEqual([0n, 0n, 0n, 0n]);

    // The auditor's complete view of the whole scenario: four spends across
    // two people and two periods, and exactly one report -- Alice's crossing
    // day. Nothing was skipped, so every memo the pool admitted was
    // decryptable, which is a claim about this scenario's memos and not
    // boilerplate.
    const { disclosures, skipped } = await auditorView();
    expect(skipped).toEqual([]);
    expect(disclosures).toEqual([{ personId: pidA, subtotal: 11_000n, day: DAY }]);

    expect(pool.tree.leafCount()).toBe(17);
    expect(pool.spendLog).toHaveLength(4);

    // Step 7's two privacy properties, re-checked over the COMPLETE
    // transcript rather than the three records that existed when it ran --
    // same instruments, so this cannot be a weaker copy.
    assertNoIdentifiersPublished();
    assertRecordsAreShapeIdentical(pool.spendLog[0], pool.spendLog[1]);
  },
);

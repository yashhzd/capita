import { DAY_BITS, MERKLE_DEPTH, P, T_THRESHOLD } from "./constants.js";
import { isWellFormedMemo, type Limbs, type Memo } from "./elgamal.js";
import { type Pt } from "./grumpkin.js";
import { MerkleTree } from "./merkle.js";
import { paymentCommit } from "./notes.js";

// Pool-operator state: the public, unencrypted side of the protocol. The
// operator never sees secrets -- it sees proof outputs (commitments and
// nullifiers, all opaque field elements) and enforces the acceptance rules
// on them. Enrollment landed in Task 6, deposits in Task 7, and spend
// acceptance plus the day clock in Task 9.
//
// Set-key encoding: every Set<string> below keys field elements by their
// decimal bigint string (x.toString()). Later tasks must use the same
// encoding when they probe or extend these sets.
//
// TASK 11 BOUNDARY: no method here verifies a proof. Until then an executed
// witness stands in for a verified one, so the operator is trusting the
// caller that these field elements really are some proof's public
// inputs/outputs. Task 11 cuts in at the top of `enroll` and `spend`: verify
// the proof, then bind the verified public inputs and outputs to the record
// being judged. Acceptance is only ever as strong as that binding -- the
// rules below assume the record is a faithful transcript of one proof.

/**
 * Public outputs of the enrollment circuit, as the operator receives them:
 * the enrollment nullifier E, the genesis tally commitment C_t, and the
 * public input d_now the proof was made against. Until Task 11 wires up
 * real proving, executed-witness return values stand in for verified proof
 * outputs (a plan-level choice; the acceptance logic is identical).
 */
export interface EnrollOutput {
  E: bigint;
  cT: bigint;
  dNow: bigint;
}

/**
 * The operator-visible record of one spend, in the spend circuit's own ABI
 * order (`circuits/spend/src/main.nr`): first the public inputs the prover
 * chose, then the five public outputs the circuit returned.
 *
 * The split matters. `nPay` onward are CONSTRAINED -- the circuit derived
 * them from a witness it checked. Everything before them is DECLARED: the
 * prover picked those values, and the circuit only checked how they relate
 * to each other, never whether they are true of the world. It has no clock,
 * no view of the tree, and no idea which auditor key or threshold is the
 * real one. Each declared input is therefore a complete bypass of some
 * protocol property until `Pool.spend` pins it to pool state.
 */
/**
 * One past the largest usable period index: the spend circuit range-bounds
 * both days to DAY_BITS, so a pool clock at or above this could never be
 * matched by any provable `d_now`, and the pool would accept nothing ever
 * again. Roughly 11.7 million business days away, but the clock is the one
 * thing the day rule pins, so the ceiling is enforced rather than assumed.
 */
const PERIOD_LIMIT = 1n << BigInt(DAY_BITS);

export interface SpendPublicInputs {
  /** Tree root the membership proofs were made against. */
  root: bigint;
  /** Period index the prover dated the spend to; see `Pool.currentDay`. */
  dNow: bigint;
  /** Disclosure threshold the prover declared. */
  tThreshold: bigint;
  /** Auditor key the memo was encrypted to, x then y. */
  apkX: bigint;
  apkY: bigint;
  /** The uniform disclosure memo: ephemeral point plus four limbs. */
  memo: Memo;
  /** Nullifier of the consumed payment note. */
  nPay: bigint;
  /** Nullifier of the consumed tally note. */
  nTally: bigint;
  /** Recipient note, self-change note, and the updated tally note. */
  cOut1: bigint;
  cOut2: bigint;
  cTallyNew: bigint;
}

/**
 * CLASS INVARIANT (serialized acceptance): pool state -- `tree`, the three
 * sets, `rootHistory`, `currentDay` -- is only read or written from inside
 * a `serialize()`d operation, so operations run strictly one at a time, in
 * call order, like an operator draining a submission queue. The
 * check-then-mutate body of an acceptance operation spans an `await`
 * (tree insertion hashes asynchronously), which is NOT atomic on its own:
 * without the queue, two in-flight enrollments with the same E could both
 * pass the duplicate check before either records its nullifier. Every
 * acceptance method -- `enroll`, `deposit`, `spend`, and `advanceDay` --
 * wraps its body in `serialize()`, and none may call `serialize()` from
 * inside an already-serialized operation, which would wait on itself.
 *
 * The clock is queued for the same reason: `advanceDay` mutates pool state
 * that `spend` reads, so a rollover fired alongside in-flight spends must
 * take its turn rather than retroactively invalidating them.
 */
export class Pool {
  /**
   * Commitment tree over every note the pool has accepted. Readonly so no
   * caller can swap the tree out from under the queue; its `insert` is
   * still reachable, which spend-threshold.test.ts relies on as its
   * pre-Task-9 acceptance stand-in (see the note on `spend`).
   */
  readonly tree = new MerkleTree();
  /** Spent-note nullifiers: one entry per consumed payment or tally note. */
  readonly seenNullifiers = new Set<string>();
  /** Enrollment nullifiers: one entry per enrolled person, ever. */
  readonly seenEnrollments = new Set<string>();
  /**
   * Every root the tree has had after an accepted insertion. Spend proofs
   * may reference any historical root, so a proof prepared against an
   * older tree state stays valid. The empty-tree root is deliberately not
   * in the set: no note has ever been under it, so nothing should be
   * provable against it.
   */
  readonly rootHistory = new Set<string>();
  /**
   * Public transcript of accepted spends, in acceptance order -- what a
   * chain observer would see. Rejected submissions leave no trace. The
   * auditor's `collect` reads the memos off it.
   */
  readonly spendLog: SpendPublicInputs[] = [];
  /**
   * The auditor key every accepted memo must encrypt to, or null for a
   * pool that accepts no spends. A launch parameter, not per-submission
   * state: pinning it is what stops a payer voiding their own disclosure
   * by encrypting to a key the auditor does not hold.
   */
  readonly auditorKey: Pt | null;

  /** Backing store for `currentDay`; only `advanceDay` may move it. */
  private day: bigint;

  /** Tail of the acceptance queue; see the class invariant above. */
  private opQueue: Promise<unknown> = Promise.resolve();

  constructor(currentDay: bigint = 0n, auditorKey: Pt | null = null) {
    if (currentDay < 0n || currentDay >= PERIOD_LIMIT) {
      throw new RangeError(
        `currentDay outside the circuit's ${DAY_BITS}-bit day range: ${currentDay}`,
      );
    }
    this.day = currentDay;
    this.auditorKey = auditorKey;
  }

  /**
   * The period every submission is judged against.
   *
   * This is an OPAQUE MONOTONIC COUNTER, not a date. The protocol needs
   * only two things of it: consecutive business days get consecutive
   * indices, and `advanceDay` moves to the next one. The spend circuit
   * agrees -- it tests days for equality and ordering and never does
   * arithmetic on them -- so the encoding is free, and mapping wall-clock
   * business days onto indices is the deployment's job, outside the pool.
   *
   * Consequently a YYYYMMDD-shaped value is NOT a valid encoding here, and
   * where the older suites use one it is a cosmetic label that happens to
   * be monotonic; those suites never call `advanceDay`. Reading such a
   * value as a date is the trap this comment exists to close, because
   * 20260831 + 1 is 20260832, which is not a day.
   *
   * Read-only from outside: a caller that could assign it would move the
   * clock outside the queue, which is the same subtotal-reset bypass as an
   * unpinned `d_now`, just reached from the operator's side.
   */
  get currentDay(): bigint {
    return this.day;
  }

  /**
   * Appends `op` to the acceptance queue: it starts only after every
   * previously queued operation has settled, and its result (or thrown
   * error) goes to this caller alone. A rejected operation does not stall
   * the queue.
   */
  protected serialize<T>(op: () => Promise<T>): Promise<T> {
    const result = this.opQueue.then(op);
    this.opQueue = result.catch(() => {});
    return result;
  }

  /**
   * Accepts one enrollment: checks the proof's public day matches the
   * pool's, rejects a re-enrollment by the same person (same E), then
   * admits the genesis tally note into the tree.
   *
   * The whole body is one serialized operation, and validation (including
   * the tree's own leaf range check) precedes every state change -- so a
   * rejected enrollment leaves the pool untouched, and concurrent calls
   * cannot slip past the duplicate check. Throws `"wrong-day"` /
   * `"duplicate-enrollment"`.
   */
  async enroll(proofOut: EnrollOutput): Promise<void> {
    return this.serialize(async () => {
      if (proofOut.dNow !== this.currentDay) {
        throw new Error("wrong-day");
      }
      const key = proofOut.E.toString();
      if (this.seenEnrollments.has(key)) {
        throw new Error("duplicate-enrollment");
      }
      await this.tree.insert(proofOut.cT);
      this.seenEnrollments.add(key);
      this.rootHistory.add(this.tree.root().toString());
    });
  }

  /**
   * Accepts one transparent deposit: mints a payment note of `v` units for
   * `ownerPk`, inserts its commitment into the tree, and returns the
   * commitment with its leaf index.
   *
   * Transparent means `v` and `ownerPk` are operator-visible at mint time
   * (this is the on-ramp; value enters against a public payment), so the
   * commitment needs no hiding salt here. Its salt is instead fixed to the
   * LEAF INDEX: the depositor reads it off the returned `index` and later
   * supplies it as the note's `r` witness when spending, and repeated
   * deposits of the same `(v, ownerPk)` still land on distinct commitments
   * -- and therefore distinct nullifiers. Privacy begins at the first
   * spend, which proves membership under a root without revealing which
   * leaf.
   *
   * The value is checked against the spend circuit's u64 range up front --
   * a larger `v` would mint a note the circuit can never consume -- and
   * `paymentCommit` rejects a non-canonical `ownerPk` (p2's RangeError)
   * before any state changes, preserving validate-then-mutate. The whole
   * body is one serialized operation (class invariant), so the index read
   * before the insert is the index the leaf lands on.
   */
  async deposit(
    v: bigint,
    ownerPk: bigint,
  ): Promise<{ commit: bigint; index: number }> {
    return this.serialize(async () => {
      if (v < 0n || v >= 1n << 64n) {
        throw new RangeError(`deposit value out of u64 range: ${v}`);
      }
      const index = this.tree.leafCount();
      const commit = await paymentCommit(v, ownerPk, BigInt(index));
      await this.tree.insert(commit);
      this.rootHistory.add(this.tree.root().toString());
      return { commit, index };
    });
  }

  /**
   * Accepts one spend. The circuit proved the payment is well-formed; this
   * decides whether it is well-formed against THIS pool, checking the
   * prover's declared public inputs in order:
   *
   *  0. an auditor key is configured at all -- `"no-auditor-key"`
   *  1. `root` is a root the tree really had -- `"unknown-root"`
   *  2. `dNow` is today -- `"wrong-day"`
   *  3. `tThreshold` is the policy constant -- `"wrong-threshold"`
   *  4. `(apkX, apkY)` is the configured auditor key -- `"wrong-auditor-key"`
   *  5. the memo is a decryptable ciphertext -- `"invalid-memo"`
   *  6. neither nullifier is already burnt -- `"double-spend"`
   *  7. the new tally is not already a leaf -- `"duplicate-tally"`
   *
   * then admits: burns both nullifiers, inserts `cOut1`, `cOut2`,
   * `cTallyNew` in that order, records the new root, and appends the record
   * to the public transcript.
   *
   * Rules 1-2 and 5 are the plan's; the rest close bypasses that adversarial
   * review demonstrated against the circuit alone, and each is load-bearing:
   *
   * - `dNow` is the big one. The circuit only checks `d_now >= d_old`, so a
   *   payer sitting just under the threshold can date the next spend
   *   tomorrow, get `s_new = v1` instead of `s_old + v1`, and settle with a
   *   dummy memo -- the daily limit evaded with an entirely honest proof.
   *   The circuit cannot see a clock. Only this check closes it.
   * - `tThreshold` is the same hole with a different lever: declare
   *   `T = 2^64 - 1` and no subtotal ever crosses.
   * - `apk` must be pinned on BOTH coordinates. `(x, -y)` is on the curve
   *   whenever `(x, y)` is, so it passes the circuit's on-curve assert while
   *   producing a memo the real auditor decrypts to garbage -- a silent
   *   disclosure void, where nothing looks wrong and nothing is reported.
   * - `cTallyNew` duplicating an existing leaf means `v1 = 0` on the same
   *   day with `r_t_new = r_t`, which reissues the very note this spend is
   *   consuming. The pool cannot see `c_t_old` (it is a witness), but it
   *   does not need to: if the two are equal then `cTallyNew` is already in
   *   the tree, because the circuit proved its membership. Admitting it
   *   would insert a note whose nullifier was just burnt, ending the payer's
   *   tally chain and with it their ability to spend. Self-harm only -- no
   *   one else can produce a leaf carrying their `person_id` -- but the pool
   *   should not knowingly store a dead note.
   * - The rule is deliberately confined to the tally. Payment outputs are
   *   NOT deduplicated. A duplicate payment leaf cannot mint: both copies
   *   came out of a value-conserving circuit and share one nullifier, so
   *   the effect is destruction, never inflation. It is not costless to
   *   everyone, though, and the party who bears it is not the one who
   *   caused it -- `pk1` is the RECIPIENT's key, so the duplicate note is
   *   theirs, and a single nullifier covering both leaves them able to
   *   realise only one of two settled-looking payments. It is nonetheless
   *   the recipient's check to make rather than the pool's: a note is
   *   identified by its commitment, so a wallet that has already seen this
   *   commitment must reject the second copy, exactly as it must reject any
   *   replayed bearer note. Pool-side dedup would duplicate that check
   *   rather than replace it. Note that the reach of an attacker does not
   *   enter into it either way:
   *   no insertion path lets any actor place a CHOSEN field element in the
   *   tree -- `enroll` inserts a circuit-output `C_t`, `deposit` inserts a
   *   commitment whose salt the pool fixes to the leaf index, and `spend`
   *   inserts three circuit-derived commitments -- so every leaf is a
   *   Poseidon2 image, and aiming at an existing digest would mean
   *   inverting it.
   * - The memo is checked for structure, not content: the circuit already
   *   proved it encrypts the required message, but nothing there constrains
   *   the SHAPE the operator receives. The rejected shapes fail in three
   *   different ways and it is worth being exact about which, because only
   *   two of them are breakages. A `c1` at infinity makes the auditor's
   *   `decrypt` throw, so one such record costs the honest disclosures
   *   batched with it. An off-curve `c1` decrypts to garbage, so a
   *   disclosure that was owed is simply lost. A non-canonical `c1` -- a
   *   coordinate outside [0, P) -- in fact decrypts CORRECTLY (verified),
   *   so it is rejected as hygiene, not as a demonstrated break: grumpkin's
   *   `add` compares x with raw bigint equality and does throw on two
   *   congruent-but-differently-represented points, a precondition that
   *   module states explicitly, and the collision merely happens not to
   *   arise inside `mul(ask, c1)`. Rejecting it keeps stored records
   *   canonical and keeps the pool off a dependency on that accident.
   *   Task 11 does not subsume any of this: the ABI carries `c1` as
   *   `[Field; 2]` and `ct` as `[Field; 4]`, while the harness point
   *   carries a third field, `inf`, with no ABI counterpart to bind -- and
   *   no proof binding repairs checking one object while storing another.
   *
   * Validation runs to completion before any state changes -- including the
   * range and capacity checks that `tree.insert` would otherwise raise
   * mid-sequence. That matters more here than anywhere else in the class:
   * a spend performs THREE inserts, so a failure discovered on the second
   * would leave the first leaf in the tree with no nullifiers burnt. The
   * nullifiers are then burnt before the inserts, so even a hashing failure
   * inside the tree fails closed (notes destroyed) rather than open (notes
   * spendable twice).
   *
   * Throws the strings above, or a RangeError for a non-canonical output.
   */
  async spend(pub: SpendPublicInputs): Promise<void> {
    return this.serialize(async () => {
      // STEP 0, before any rule runs: take the snapshot. Every check below
      // reads THIS object, and this is the object stored, so the thing
      // validated is always the thing kept.
      //
      // Checking the caller's object and storing a reconstruction of it is
      // not equivalent, and the gap is exploitable: anything that differs
      // between the two reads passes the check and lands in the transcript
      // unchecked. A `memo.c1` getter yielding a real point first and the
      // identity second, or a ct whose true arity differs from the four
      // slots a reconstruction assumes, both void a disclosure that way.
      // Snapshotting first collapses that whole class -- the defect
      // outlives any individual witness, so the ordering is the fix.
      //
      // `pub` is untrusted external input: read each field exactly once,
      // here, and never again.
      const c1 = pub.memo.c1;
      const record: SpendPublicInputs = {
        root: pub.root,
        dNow: pub.dNow,
        tThreshold: pub.tThreshold,
        apkX: pub.apkX,
        apkY: pub.apkY,
        memo: {
          c1: { x: c1.x, y: c1.y, inf: c1.inf },
          // Spread rather than four hard-coded slots: a copy that assumes
          // the arity would manufacture `undefined` limbs out of a short
          // ct instead of preserving it for `isWellFormedMemo` to reject.
          ct: [...pub.memo.ct] as Limbs,
        },
        nPay: pub.nPay,
        nTally: pub.nTally,
        cOut1: pub.cOut1,
        cOut2: pub.cOut2,
        cTallyNew: pub.cTallyNew,
      };

      if (this.auditorKey === null) {
        throw new Error("no-auditor-key");
      }
      if (!this.rootHistory.has(record.root.toString())) {
        throw new Error("unknown-root");
      }
      // `dNow` inherits the circuit's 32-bit day bound from this equality:
      // the clock is bounded at construction and by `advanceDay`.
      if (record.dNow !== this.currentDay) {
        throw new Error("wrong-day");
      }
      if (record.tThreshold !== T_THRESHOLD) {
        throw new Error("wrong-threshold");
      }
      if (record.apkX !== this.auditorKey.x || record.apkY !== this.auditorKey.y) {
        throw new Error("wrong-auditor-key");
      }
      if (!isWellFormedMemo(record.memo)) {
        throw new Error("invalid-memo");
      }
      const nPay = record.nPay.toString();
      const nTally = record.nTally.toString();
      if (this.seenNullifiers.has(nPay) || this.seenNullifiers.has(nTally)) {
        throw new Error("double-spend");
      }
      if (this.tree.hasLeaf(record.cTallyNew)) {
        throw new Error("duplicate-tally");
      }

      const outputs = [record.cOut1, record.cOut2, record.cTallyNew];
      for (const commit of outputs) {
        if (commit < 0n || commit >= P) {
          throw new RangeError(`spend output out of field range [0, P): ${commit}`);
        }
      }
      const capacity = 2 ** MERKLE_DEPTH;
      const room = capacity - this.tree.leafCount();
      if (room < outputs.length) {
        throw new Error(
          `MerkleTree has room for ${room} more leaves, spend needs ${outputs.length} (max ${capacity})`,
        );
      }

      this.seenNullifiers.add(nPay);
      this.seenNullifiers.add(nTally);
      for (const commit of outputs) {
        await this.tree.insert(commit);
      }
      this.rootHistory.add(this.tree.root().toString());
      // The validated snapshot, which shares no object with the caller.
      // The transcript is the auditor's evidence base, so it must not alias
      // something the payer still holds: storing `pub` directly let a payer
      // settle a crossing spend, be collected correctly, and then blank the
      // memo they had submitted -- voiding their own disclosure after the
      // fact.
      this.spendLog.push(record);
    });
  }

  /**
   * Rolls the pool over to the next period, resetting nothing: subtotals
   * are carried inside each person's tally note, so a spend dated on the
   * new period restarts its own subtotal in-circuit.
   *
   * `+ 1n` is exact because `currentDay` counts periods rather than
   * encoding dates -- see the note there before giving it calendar meaning.
   *
   * Queued like every other operation (class invariant), so spends
   * submitted before the rollover are still judged against the old day and
   * ones submitted after are not.
   */
  async advanceDay(): Promise<void> {
    return this.serialize(async () => {
      if (this.day + 1n >= PERIOD_LIMIT) {
        throw new RangeError(
          `pool clock exhausted: no period after ${this.day} fits the circuit's ${DAY_BITS}-bit day range`,
        );
      }
      this.day += 1n;
    });
  }
}

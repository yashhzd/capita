import { MerkleTree } from "./merkle.js";

// Pool-operator state: the public, unencrypted side of the protocol. The
// operator never sees secrets -- it sees proof outputs (commitments and
// nullifiers, all opaque field elements) and enforces the acceptance rules
// on them. This file starts with enrollment (Task 6); spend acceptance and
// day advancement extend the same class in Tasks 7/9.
//
// Set-key encoding: every Set<string> below keys field elements by their
// decimal bigint string (x.toString()). Later tasks must use the same
// encoding when they probe or extend these sets.

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
 * CLASS INVARIANT (serialized acceptance): pool state -- `tree`, the three
 * sets, `rootHistory`, `currentDay` -- is only read or written from inside
 * a `serialize()`d operation, so operations run strictly one at a time, in
 * call order, like an operator draining a submission queue. The
 * check-then-mutate body of an acceptance operation spans an `await`
 * (tree insertion hashes asynchronously), which is NOT atomic on its own:
 * without the queue, two in-flight enrollments with the same E could both
 * pass the duplicate check before either records its nullifier. Every
 * acceptance method later tasks add (spend in Task 7, day advancement in
 * Task 9) must wrap its body in `serialize()` exactly as `enroll` does --
 * and must not call `serialize()` from inside an already-serialized
 * operation, which would wait on itself.
 */
export class Pool {
  /** Current day index; advancing it is Task 9's job. */
  currentDay: bigint;
  /** Commitment tree over every note the pool has accepted. */
  tree = new MerkleTree();
  /** Spent-note nullifiers -- populated by the spend flow (Tasks 7/9). */
  seenNullifiers = new Set<string>();
  /** Enrollment nullifiers: one entry per enrolled person, ever. */
  seenEnrollments = new Set<string>();
  /**
   * Every root the tree has had after an accepted insertion. Spend proofs
   * may reference any historical root, so a proof prepared against an
   * older tree state stays valid. The empty-tree root is deliberately not
   * in the set: no note has ever been under it, so nothing should be
   * provable against it.
   */
  rootHistory = new Set<string>();

  /** Tail of the acceptance queue; see the class invariant above. */
  private opQueue: Promise<unknown> = Promise.resolve();

  constructor(currentDay: bigint = 0n) {
    this.currentDay = currentDay;
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
}

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

  constructor(currentDay: bigint = 0n) {
    this.currentDay = currentDay;
  }

  /**
   * Accepts one enrollment: checks the proof's public day matches the
   * pool's, rejects a re-enrollment by the same person (same E), then
   * admits the genesis tally note into the tree.
   *
   * Validation happens before any state change, so a rejected enrollment
   * leaves the pool untouched. Throws `"wrong-day"` / `"duplicate-enrollment"`.
   */
  async enroll(proofOut: EnrollOutput): Promise<void> {
    if (proofOut.dNow !== this.currentDay) {
      throw new Error("wrong-day");
    }
    if (this.seenEnrollments.has(proofOut.E.toString())) {
      throw new Error("duplicate-enrollment");
    }
    await this.tree.insert(proofOut.cT);
    this.seenEnrollments.add(proofOut.E.toString());
    this.rootHistory.add(this.tree.root().toString());
  }
}

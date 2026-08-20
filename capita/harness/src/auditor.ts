import { decrypt, isWellFormedMemo, type Memo } from "./elgamal.js";

// The auditor's side of the disclosure mechanism: a passive off-chain
// observer holding the audit secret key. It reads the memo attached to
// every accepted payment, decrypts each one, and keeps the real reports --
// the memos whose flag limb is 1. It does no verification and touches no
// pool state: the spend circuit already guaranteed that every accepted
// memo encrypts exactly the message the payer's threshold position
// dictates, so decryption alone separates reports from dummies. Nobody
// without `ask` can make that separation; that is the uniformity property
// the memo shape exists to protect.

/** One above-threshold report, as the spend circuit encoded it. */
export interface Disclosure {
  personId: bigint;
  subtotal: bigint;
  day: bigint;
}

/** The result of one collection run over a batch of memos. */
export interface Collection {
  /** Real reports, in memo order. */
  disclosures: Disclosure[];
  /**
   * Positions of memos that were not ciphertexts at all and so could not
   * be read. Empty for any batch taken off a pool transcript; a non-empty
   * list means the batch came from somewhere else, or the pool's
   * acceptance rules have a hole.
   */
  skipped: number[];
}

/**
 * Decrypts every memo with the audit key and returns the real disclosures
 * (flag limb 1), in memo order. Dummy memos decrypt to [0, 0, 0, 0] and
 * are dropped.
 *
 * Structurally undecryptable memos are skipped rather than thrown on, so a
 * single malformed record cannot take down a whole collection run and cost
 * the auditor the honest disclosures batched with it. Skipping discards
 * nothing recoverable: such a record is not a ciphertext at all, so there
 * is no plaintext it could have been hiding -- unlike a well-formed memo
 * that decrypts to garbage, which still yields limbs and is simply not a
 * disclosure.
 *
 * But the skip is REPORTED, never silent. Dropping the record loses no
 * plaintext; it would lose the fact that a malformed record existed, and
 * once the pool stopped admitting them that fact is the only remaining
 * signal that something is wrong. Before skipping was introduced such a
 * record threw and was impossible to miss, so `skipped` is what keeps the
 * failure visible after trading loud for survivable.
 *
 * This is defence in depth for memos that did not come from this pool.
 * `Pool.spend` applies the same predicate to the record it stores -- the
 * snapshot it validated, not the caller's object -- so `skipped` is empty
 * for any batch taken off a pool transcript.
 */
export async function collect(memos: Memo[], ask: bigint): Promise<Collection> {
  const disclosures: Disclosure[] = [];
  const skipped: number[] = [];
  for (const [index, memo] of memos.entries()) {
    if (!isWellFormedMemo(memo)) {
      skipped.push(index);
      continue;
    }
    const [flag, personId, subtotal, day] = await decrypt(memo, ask);
    if (flag === 1n) {
      disclosures.push({ personId, subtotal, day });
    }
  }
  return { disclosures, skipped };
}

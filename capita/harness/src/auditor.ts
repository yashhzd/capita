import { decrypt, type Memo } from "./elgamal.js";

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

/**
 * Decrypts every memo with the audit key and returns the real disclosures
 * (flag limb 1), in memo order. Dummy memos decrypt to [0, 0, 0, 0] and
 * are dropped.
 */
export async function collect(memos: Memo[], ask: bigint): Promise<Disclosure[]> {
  const disclosures: Disclosure[] = [];
  for (const memo of memos) {
    const [flag, personId, subtotal, day] = await decrypt(memo, ask);
    if (flag === 1n) {
      disclosures.push({ personId, subtotal, day });
    }
  }
  return disclosures;
}

import { p2 } from "./poseidon.js";
import {
  APP_SCOPE,
  DOMAIN_ENROLL,
  DOMAIN_NULLIFIER,
  DOMAIN_PAYMENT,
  DOMAIN_TALLY,
} from "./constants.js";

// Core protocol formulas: person identity, note commitments, nullifiers.
// Each function is a direct transcription of one spec formula (spec §7.1-7.2,
// plan "Global Constraints") so this file can be diffed line by line against
// the spec -- and against the Noir common lib, which must reproduce these
// exact input arrays. Keep it that way: no helpers, no reordering, no extra
// hashing. Inputs are range-checked inside p2() (RangeError outside [0, P)),
// so nothing is re-checked here.

/** Person identity: `person_id = p2([person_secret, APP_SCOPE])`. */
export async function personId(personSecret: bigint): Promise<bigint> {
  return p2([personSecret, APP_SCOPE]);
}

/** Payment note owner key: `owner_pk = p2([owner_sk])`. */
export async function ownerPk(ownerSk: bigint): Promise<bigint> {
  return p2([ownerSk]);
}

/** Payment note `{v, owner_pk, r}`: `C = p2([DOMAIN_PAYMENT, v, owner_pk, r])`. */
export async function paymentCommit(
  v: bigint,
  ownerPk: bigint,
  r: bigint,
): Promise<bigint> {
  return p2([DOMAIN_PAYMENT, v, ownerPk, r]);
}

/**
 * Tally note `{person_id, subtotal s, day d, r}`:
 * `C_t = p2([DOMAIN_TALLY, person_id, s, d, r])`.
 */
export async function tallyCommit(
  personId: bigint,
  s: bigint,
  d: bigint,
  r: bigint,
): Promise<bigint> {
  return p2([DOMAIN_TALLY, personId, s, d, r]);
}

/** One-time enrollment nullifier: `E = p2([DOMAIN_ENROLL, person_id])`. */
export async function enrollNullifier(personId: bigint): Promise<bigint> {
  return p2([DOMAIN_ENROLL, personId]);
}

/**
 * Note nullifier: `N = p2([DOMAIN_NULLIFIER, secret, C])`, where `secret` is
 * `owner_sk` for payment notes and `person_secret` for tally notes.
 */
export async function noteNullifier(
  secret: bigint,
  commit: bigint,
): Promise<bigint> {
  return p2([DOMAIN_NULLIFIER, secret, commit]);
}

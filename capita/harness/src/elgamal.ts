import { P } from "./constants.js";
import { G, mul, type Pt } from "./grumpkin.js";
import { p2 } from "./poseidon.js";

// Hash-ElGamal over Grumpkin for the encrypted disclosure memo. Every
// payment carries one of these, identically shaped whether the disclosure is
// real (above threshold) or a dummy (below), so the primitive itself must
// never branch on content.
//
// Encryption: S = rEnc * apk (shared secret), c1 = rEnc * G (ephemeral key),
// ct[i] = msg[i] + p2([S.x, S.y, i]) mod P. The limb index i sits INSIDE the
// hash, so the four pads are distinct and equal plaintext limbs do not leak
// equality. Decryption recomputes S = ask * c1 (since apk = ask * G) and
// subtracts the same pads.
//
// rEnc is an explicit parameter, never generated here: tests stay
// deterministic, and the circuit receives it as a witness the same way.

/** Four plaintext or ciphertext limbs, each an element of the field mod P. */
export type Limbs = [bigint, bigint, bigint, bigint];

/** Encrypted disclosure memo: ElGamal ephemeral point + four padded limbs. */
export type Memo = { c1: Pt; ct: Limbs };

export function keygen(sk: bigint): Pt {
  return mul(sk, G);
}

// pad_i = p2([S.x, S.y, i]). Coordinates are < P by construction and i is
// 0..3, so every p2 input is in range -- the scalars rEnc/ask (which live
// mod GRUMPKIN_ORDER, not mod P) never enter the hash. Hashes run
// sequentially to keep a single, ordered stream of calls into the shared
// Barretenberg instance, matching how merkle.ts uses it.
async function pads(S: Pt): Promise<Limbs> {
  const out: bigint[] = [];
  for (let i = 0n; i < 4n; i += 1n) {
    out.push(await p2([S.x, S.y, i]));
  }
  return out as Limbs;
}

export async function encrypt(msg: Limbs, apk: Pt, rEnc: bigint): Promise<Memo> {
  for (const limb of msg) {
    if (limb < 0n || limb >= P) {
      throw new RangeError(`encrypt: plaintext limb out of field range [0, P): ${limb}`);
    }
  }
  const S = mul(rEnc, apk);
  if (S.inf) {
    throw new Error("encrypt: degenerate shared secret (rEnc = 0 mod group order, or apk is the identity)");
  }
  const c1 = mul(rEnc, G);
  const pad = await pads(S);
  // Both addends are < P, so a single reduction of their sum is exact.
  return { c1, ct: msg.map((m, i) => (m + pad[i]) % P) as Limbs };
}

export async function decrypt(memo: Memo, ask: bigint): Promise<Limbs> {
  const S = mul(ask, memo.c1);
  if (S.inf) {
    throw new Error("decrypt: degenerate shared secret (ask = 0 mod group order, or c1 is the identity)");
  }
  const pad = await pads(S);
  // ct and pad are both in [0, P), so the difference sits in (-P, P); adding
  // P before the final reduction keeps the intermediate non-negative.
  return memo.ct.map((c, i) => (c - pad[i] + P) % P) as Limbs;
}

// Throwaway probe binary for the TypeScript <-> Noir consistency gate
// (capita/harness/tests/consistency.test.ts). Not a protocol circuit: it
// evaluates every common-library primitive on caller-supplied inputs and
// returns the raw results so the harness can diff them against the
// TypeScript reference implementation. Output layout:
//   0 person_id         1 owner_pk          2 payment_commit
//   3 tally_commit      4 enroll_nullifier  5 note_nullifier
//   6 merkle_root       7 G.x               8 G.y
//   9 c1.x             10 c1.y             11..14 ct[0..3]
// payment_commit consumes the in-circuit owner_pk, tally_commit and
// enroll_nullifier the in-circuit person_id, and note_nullifier the
// in-circuit payment_commit (secret = owner_sk), so composition is
// exercised, not just the leaf formulas.

use common::MERKLE_DEPTH;
use std::embedded_curve_ops::EmbeddedCurvePoint;

fn main(
    person_secret: Field,
    owner_sk: Field,
    v: Field,
    r: Field,
    s: Field,
    d: Field,
    r2: Field,
    leaf: Field,
    siblings: [Field; MERKLE_DEPTH],
    indices: [bool; MERKLE_DEPTH],
    msg: [Field; 4],
    apk_x: Field,
    apk_y: Field,
    r_enc_lo: Field,
    r_enc_hi: Field,
) -> pub [Field; 15] {
    let pid = common::person_id(person_secret);
    let opk = common::owner_pk(owner_sk);
    let pc = common::payment_commit(v, opk, r);
    let tc = common::tally_commit(pid, s, d, r2);
    let en = common::enroll_nullifier(pid);
    let nn = common::note_nullifier(owner_sk, pc);
    let root = common::merkle_root(leaf, siblings, indices);
    let g = EmbeddedCurvePoint::generator();
    let (c1, ct) = common::elgamal_encrypt(msg, apk_x, apk_y, r_enc_lo, r_enc_hi);
    [pid, opk, pc, tc, en, nn, root, g.x, g.y, c1[0], c1[1], ct[0], ct[1], ct[2], ct[3]]
}

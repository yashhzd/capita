// Spend circuit: one shielded payment, coupled to the payer's per-person
// tally note. This coupling is the heart of the protocol -- a payment is
// only valid if it also consumes the payer's single live tally note (their
// running daily subtotal) and produces the updated one, so every payment
// from every wallet a person owns moves one shared total. Task 8 completes
// the statement with day rollover, the threshold comparison, and the
// uniform disclosure memo: every payment must carry a hash-ElGamal memo to
// the auditor key, and the circuit is only satisfiable when that memo
// encrypts exactly the message the payer's threshold position dictates --
// all zeros at or below the threshold, the real report above it. On-chain
// observers see identically shaped ciphertexts either way; only the
// auditor, decrypting, finds the reports among the dummies.
//
// Statement (arity fixed at 1 payment input, 2 outputs):
//
//   pk_self = owner_pk(owner_sk)
//   C_in    = payment_commit(v_in, pk_self, r_in)        member of root
//   N_pay   = note_nullifier(owner_sk, C_in)             (public output)
//   pid     = person_id(person_secret)
//   C_t_old = tally_commit(pid, s_old, d_old, r_t)       member of root
//   N_tally = note_nullifier(person_secret, C_t_old)     (public output)
//   d_now  >= d_old          over 32-bit range-checked days
//   v_in   == v1 + v2        over 64-bit range-checked values
//   C_out1  = payment_commit(v1, pk1, r1)                (public output)
//   C_out2  = payment_commit(v2, pk_self, r2)            (public output)
//   s_new   = s_old + v1  if d_now == d_old  else  v1    (day rollover)
//   C_t_new = tally_commit(pid, s_new, d_now, r_t_new)   (public output)
//   over    = s_new > t_threshold                        (strict)
//   msg     = [over, over*pid, over*s_new, over*d_now]
//   (c1, ct) == elgamal_encrypt(msg, apk, r_enc)         (public memo)
//
// Design notes, in constraint order:
//
// - Membership is proven from commitment OPENINGS: both Merkle leaves are
//   derived in-circuit from their openings, never accepted as raw witness
//   values. A raw-leaf interface would be unsound -- the tree's empty
//   leaves are 0, so a zero leaf at any unfilled index folds to every
//   root, and a prover could fabricate membership. Deriving the leaf
//   forces the prover to open a commitment that actually hashes to it.
//
// - The tally is bound to the person, not the wallet: the same
//   person_secret witness reconstructs the consumed tally's person_id and
//   keys its nullifier, and the new tally carries that same pid. A prover
//   without a tally's person_secret cannot consume it (the derived
//   commitment misses the tree), and cannot shift their subtotal onto
//   anyone else's tally.
//
// - The tally counts v1 (the recipient output) only; self-change never
//   counts. A self-transfer (pk1 = own key) therefore still burns
//   allowance -- an accepted PoC simplification, noted in the paper.
//
// - The change output is provably to self: C_out2 commits under the
//   in-circuit pk_self, not a free witness key, so "change" cannot be
//   routed elsewhere to understate v1.
//
// - s_old is range-checked to 128 bits -- not because honest values need
//   it (tallies enter the tree at s = 0 on enrollment or s_old + v1 here,
//   v1 < 2^64 per spend, and the depth-16 tree caps notes at 2^16, so
//   every reachable subtotal stays below 2^80 by induction) but so that
//   circuit-local soundness does not lean on pool admission discipline: a
//   tally leaf forged with s_old near the field modulus would otherwise
//   wrap s_new = s_old + v1 into a limit reset. With s_old < 2^128 and
//   v1 < 2^64 the sum stays far below the modulus; the threshold gadget
//   below relies on exactly that bound (s_new < 2^128 + 2^64).
//
// - Days are range-checked to 32 bits BEFORE the rollover comparison: a
//   Field-to-u32 cast truncates without constraining, so comparing raw
//   days would let a forged tally with d_old = d_now + 2^32 slip the
//   ordering check on truncated-equal values while failing the field
//   equality below it -- a subtotal reset on demand. Bounded, the casts
//   are exact and the ordering is true integer ordering.
//
// - The threshold flag is a hinted witness pinned by one muxed range
//   check (assert_over_threshold_iff below); a huge s_new from a forged
//   tally can only satisfy the OVER side, so forgery forces disclosure
//   rather than evading it.
//
// - The memo is uniform by construction: both threshold branches run the
//   identical encryption over a message that is all zeros below the
//   threshold (flag * x zeroes every limb), so real and dummy memos cost
//   the same constraints and differ only under the auditor key. The apk
//   on-curve assert keeps the memo's shared secret a genuine group
//   element even if the pool's published auditor key were corrupted --
//   same fail-safe stance as the s_old bound.

use common::{
    MERKLE_DEPTH, elgamal_encrypt, merkle_verify, note_nullifier, owner_pk, payment_commit,
    person_id, tally_commit,
};

// Witness-generation hint for the threshold flag: exact big-endian byte
// comparison of two canonical field values. Unconstrained -- the proof
// system lets a malicious prover return anything here, which is why main
// pins the result with assert_over_threshold_iff immediately after.
unconstrained fn gt_hint(a: Field, b: Field) -> bool {
    let a_bytes: [u8; 32] = a.to_be_bytes();
    let b_bytes: [u8; 32] = b.to_be_bytes();
    let mut gt = false;
    let mut decided = false;
    for i in 0..32 {
        if !decided {
            if a_bytes[i] != b_bytes[i] {
                gt = a_bytes[i] > b_bytes[i];
                decided = true;
            }
        }
    }
    gt
}

// Constrains `over == (s_new > t)` as integers, given t < 2^64 (checked
// here) and s_new below 2^129 (guaranteed by the caller: s_old < 2^128 and
// v1 < 2^64 bound both rollover branches). One muxed 129-bit range check
// does it:
//
//   over = true:  diff = s_new - t - 1. If s_new > t this is an integer in
//                 [0, 2^129) and passes. If s_new <= t it wraps to
//                 P - k with k <= 2^64 + 1, far above 2^129 -- fails.
//   over = false: diff = t - s_new. If s_new <= t this is an integer
//                 below 2^64 and passes. If s_new > t it wraps to at
//                 least P - 2^129, again far above 2^129 -- fails.
//
// So for every satisfiable assignment the flag equals the true comparison
// of canonical values; lying in either direction is unsatisfiable. The
// t < 2^64 check is load-bearing: with t near P, "over" would satisfy for
// small s_new (diff = s_new + (P - t) - 1 sneaks under 2^129). s_new needs
// no check of its own here -- beyond 2^129 the over side is satisfiable
// only up to 2^129 + t, where "over" is still the true verdict, and the
// dummy side never is: a forged tally can only force disclosure, not
// escape it. Completeness at the top: the largest reachable s_new is
// 2^128 + 2^64 - 2, whose diff fits 129 bits with room to spare.
fn assert_over_threshold_iff(over: bool, s_new: Field, t: Field) {
    t.assert_max_bit_size::<64>();
    let diff = if over { s_new - t - 1 } else { t - s_new };
    diff.assert_max_bit_size::<129>();
}

fn main(
    // Payer identity and the consumed payment note's opening.
    person_secret: Field,
    v_in: Field,
    owner_sk: Field,
    r_in: Field,
    path_in_siblings: [Field; MERKLE_DEPTH],
    path_in_indices: [bool; MERKLE_DEPTH],
    // Payment outputs: recipient (v1 to pk1) and self-change (v2).
    v1: Field,
    pk1: Field,
    r1: Field,
    v2: Field,
    r2: Field,
    // The consumed tally note's opening and the new tally's salt.
    s_old: Field,
    d_old: Field,
    r_t: Field,
    path_t_siblings: [Field; MERKLE_DEPTH],
    path_t_indices: [bool; MERKLE_DEPTH],
    r_t_new: Field,
    // Memo encryption randomness: a Grumpkin scalar, entering as canonical
    // 128-bit limbs (r_enc = lo + 2^128 * hi, reduced mod the group order
    // before splitting) -- the Task 5 convention, range-checked inside
    // elgamal_encrypt.
    r_enc_lo: Field,
    r_enc_hi: Field,
    // Public inputs.
    root: pub Field,
    d_now: pub Field,
    t_threshold: pub Field,
    apk_x: pub Field,
    apk_y: pub Field,
    c1: pub [Field; 2],
    ct: pub [Field; 4],
) -> pub (Field, Field, Field, Field, Field) {
    // Amounts are u64. These are explicit range-constraint opcodes
    // (Field::assert_max_bit_size), not type casts: a Field merely used
    // "as u64" would let v2 = -x wrap the field and satisfy conservation.
    v_in.assert_max_bit_size::<64>();
    v1.assert_max_bit_size::<64>();
    v2.assert_max_bit_size::<64>();

    // Ownership and membership of the consumed payment note, with the leaf
    // derived from its opening.
    let pk_self = owner_pk(owner_sk);
    let c_in = payment_commit(v_in, pk_self, r_in);
    merkle_verify(c_in, root, path_in_siblings, path_in_indices);
    let n_pay = note_nullifier(owner_sk, c_in);

    // The payer's tally note, likewise from its opening. person_secret
    // both reconstructs the commitment's pid and keys the nullifier. The
    // 128-bit bound on s_old keeps s_new = s_old + v1 wrap-free even for
    // a tally leaf that slipped past pool admission (see header note).
    s_old.assert_max_bit_size::<128>();
    let pid = person_id(person_secret);
    let c_t_old = tally_commit(pid, s_old, d_old, r_t);
    merkle_verify(c_t_old, root, path_t_siblings, path_t_indices);
    let n_tally = note_nullifier(person_secret, c_t_old);

    // Day ordering: time only moves forward. Both days are bounded to 32
    // bits first so the u32 casts below cannot truncate (see header note);
    // the rollover decision itself is the exact field equality further
    // down, which the bounds make consistent with this ordering.
    d_now.assert_max_bit_size::<32>();
    d_old.assert_max_bit_size::<32>();
    assert(d_now as u32 >= d_old as u32, "spend: tally day is in the future");

    // Conservation over the range-checked amounts: all three below 2^64,
    // so v1 + v2 < 2^65 << P cannot wrap, and the field equation is exact
    // integer conservation.
    assert(v_in == v1 + v2, "spend: value conservation violated");

    // Outputs: recipient note, self-change note, updated tally. The tally
    // accumulates v1 on the same day and restarts at v1 on a later one
    // (subtotals aggregate per business day, like real CTR aggregation).
    let c_out1 = payment_commit(v1, pk1, r1);
    let c_out2 = payment_commit(v2, pk_self, r2);
    let s_new = if d_now == d_old { s_old + v1 } else { v1 };
    let c_tally_new = tally_commit(pid, s_new, d_now, r_t_new);

    // Threshold comparison: strict "s_new > t_threshold" over integers.
    // Safety: gt_hint is advisory; assert_over_threshold_iff makes any
    // dishonest flag unsatisfiable.
    let over = unsafe { gt_hint(s_new, t_threshold) };
    assert_over_threshold_iff(over, s_new, t_threshold);

    // The uniform disclosure memo. flag zeroes every message limb below
    // the threshold, so both branches encrypt through the identical path
    // and the published (c1, ct) is structurally the same either way. The
    // memo travels as public inputs and the circuit re-derives the one
    // encryption it is allowed to carry; any other memo is unsatisfiable.
    // The auditor key must be a genuine curve point BEFORE it enters the
    // scalar multiplication inside elgamal_encrypt (y^2 = x^3 - 17).
    let flag = over as Field;
    let msg = [flag, flag * pid, flag * s_new, flag * d_now];
    assert(
        apk_y * apk_y == apk_x * apk_x * apk_x - 17,
        "spend: auditor key is not on the curve",
    );
    let (c1_required, ct_required) = elgamal_encrypt(msg, apk_x, apk_y, r_enc_lo, r_enc_hi);
    assert(c1 == c1_required, "spend: memo c1 mismatch");
    assert(ct == ct_required, "spend: memo ct mismatch");

    (n_pay, n_tally, c_out1, c_out2, c_tally_new)
}

mod tests {
    use super::{assert_over_threshold_iff, gt_hint, main};
    use common::{
        elgamal_encrypt, note_nullifier, owner_pk, p2, payment_commit, person_id, tally_commit,
    };
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    // Fixed honest openings shared by the tests. Values are pairwise
    // distinct (enrollment-test convention) so an argument-order swap in
    // main breaks an equality instead of aliasing: v_in = 500 splits into
    // v1 = 200 + v2 = 300, and s_old = 1000 grows to s_new = 1200.
    global SECRET: Field = 7; // person_secret
    global SK: Field = 11; // owner_sk
    global V_IN: Field = 500;
    global R_IN: Field = 17;
    global V1: Field = 200;
    global PK1: Field = 555; // recipient key: an arbitrary field element
    global R1: Field = 19;
    global V2: Field = 300;
    global R2: Field = 23;
    global S_OLD: Field = 1000;
    global DAY: Field = 9;
    global R_T: Field = 13;
    global R_T_NEW: Field = 29;
    // Task 8 additions: the test threshold, the memo randomness (lo limb;
    // hi is 0), and boundary constants for the gadget tests.
    global T_TEST: Field = 10000;
    global R_ENC: Field = 7;
    global TWO_POW_32: Field = 4294967296;
    global TWO_POW_64: Field = 18446744073709551616;
    global TWO_POW_128: Field = 340282366920938463463374607431768211456;

    // The auditor key used by every test memo: an arbitrary genuine curve
    // point (2G).
    fn apk() -> EmbeddedCurvePoint {
        EmbeddedCurvePoint::generator().double()
    }

    // Mirrors the protocol's memo derivation for a flow, so each test can
    // hand main exactly the memo its witness requires. (The vitest flows
    // re-derive the same thing independently in TypeScript and decrypt it
    // back; this helper is the nargo-side stand-in for that wallet logic.)
    fn memo_for(
        pid: Field,
        s_old: Field,
        v1: Field,
        d_old: Field,
        d_now: Field,
    ) -> ([Field; 2], [Field; 4]) {
        let s_new = if d_now == d_old { s_old + v1 } else { v1 };
        // Safety: test-side mirror of main's hint; main re-derives and
        // constrains its own flag.
        let over = unsafe { gt_hint(s_new, T_TEST) };
        let flag = over as Field;
        let a = apk();
        elgamal_encrypt([flag, flag * pid, flag * s_new, flag * d_now], a.x, a.y, R_ENC, 0)
    }

    // Depth-16 tree holding exactly [c_pay, c_tally]: returns (root,
    // siblings for leaf 0, siblings for leaf 1). Leaf 0's indices are
    // [false; 16]; leaf 1's are tally_indices(). Mirrors the harness
    // MerkleTree: empty leaf 0, zeros[k] = p2([zeros[k-1], zeros[k-1]]).
    fn two_leaf_tree(c_pay: Field, c_tally: Field) -> (Field, [Field; 16], [Field; 16]) {
        let mut zeros: [Field; 16] = [0; 16];
        for k in 1..16 {
            zeros[k] = p2([zeros[k - 1], zeros[k - 1]]);
        }
        let mut pay_sibs = zeros;
        pay_sibs[0] = c_tally;
        let mut tally_sibs = zeros;
        tally_sibs[0] = c_pay;
        let mut node = p2([c_pay, c_tally]);
        for k in 1..16 {
            node = p2([node, zeros[k]]);
        }
        (node, pay_sibs, tally_sibs)
    }

    fn tally_indices() -> [bool; 16] {
        let mut idx = [false; 16];
        idx[0] = true;
        idx
    }

    // The two honest leaves: the payer's payment note at index 0 and their
    // current tally at index 1.
    fn honest_leaves() -> (Field, Field) {
        let c_pay = payment_commit(V_IN, owner_pk(SK), R_IN);
        let c_tally = tally_commit(person_id(SECRET), S_OLD, DAY, R_T);
        (c_pay, c_tally)
    }

    #[test]
    fn valid_spend_produces_the_contract_outputs() {
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(person_id(SECRET), S_OLD, V1, DAY, DAY);

        let (n_pay, n_tally, c_out1, c_out2, c_tally_new) = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x, apk().y,
            c1, ct,
        );

        assert_eq(n_pay, note_nullifier(SK, c_pay));
        assert_eq(n_tally, note_nullifier(SECRET, c_tally));
        assert_eq(c_out1, payment_commit(V1, PK1, R1));
        // Change is committed under the payer's own derived key...
        assert_eq(c_out2, payment_commit(V2, owner_pk(SK), R2));
        // ...and the new tally binds (pid, s_old + v1, d_now): 1000 + 200.
        assert_eq(c_tally_new, tally_commit(person_id(SECRET), 1200, DAY, R_T_NEW));
    }

    #[test]
    fn crossing_spend_is_satisfiable_only_with_the_real_disclosure() {
        // s_old = 9900 + v1 = 200 crosses T = 10000: the memo carries
        // [1, pid, 10100, DAY] (the tampered-memo tests pin that no OTHER
        // memo would do), and the tally still advances normally.
        let s_old = 9900;
        let pid = person_id(SECRET);
        let c_pay = payment_commit(V_IN, owner_pk(SK), R_IN);
        let c_tally = tally_commit(pid, s_old, DAY, R_T);
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(pid, s_old, V1, DAY, DAY);

        let (_, _, _, _, c_tally_new) = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, s_old, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x, apk().y,
            c1, ct,
        );
        assert_eq(c_tally_new, tally_commit(pid, 10100, DAY, R_T_NEW));
    }

    #[test]
    fn subtotal_equal_to_the_threshold_stays_dummy() {
        // Strictness pin at the circuit level: s_new = exactly T = 10000
        // is NOT over, so the flow satisfies with the all-zero memo.
        let s_old = 9800;
        let pid = person_id(SECRET);
        let c_pay = payment_commit(V_IN, owner_pk(SK), R_IN);
        let c_tally = tally_commit(pid, s_old, DAY, R_T);
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let a = apk();
        let (c1, ct) = elgamal_encrypt([0, 0, 0, 0], a.x, a.y, R_ENC, 0);

        let (_, _, _, _, c_tally_new) = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, s_old, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x, apk().y,
            c1, ct,
        );
        assert_eq(c_tally_new, tally_commit(pid, 10000, DAY, R_T_NEW));
    }

    #[test]
    fn rollover_resets_the_subtotal_and_stays_dummy() {
        // Same 9900 subtotal as the crossing test, but d_now = DAY + 1:
        // the consumed tally's day is over, so the subtotal restarts at
        // v1 = 200 -- under the threshold, dummy memo, new tally on the
        // new day.
        let s_old = 9900;
        let pid = person_id(SECRET);
        let c_pay = payment_commit(V_IN, owner_pk(SK), R_IN);
        let c_tally = tally_commit(pid, s_old, DAY, R_T);
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(pid, s_old, V1, DAY, DAY + 1);

        let (_, _, _, _, c_tally_new) = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, s_old, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY + 1, T_TEST, apk().x,
            apk().y, c1, ct,
        );
        assert_eq(c_tally_new, tally_commit(pid, 200, DAY + 1, R_T_NEW));
    }

    #[test(should_fail_with = "spend: value conservation violated")]
    fn conservation_violation_is_unsatisfiable() {
        // v1 + v2 = 200 + 999 != 500. Every other constraint holds (both
        // memberships open honest leaves; 999 is in u64 range), isolating
        // the conservation equation.
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(person_id(SECRET), S_OLD, V1, DAY, DAY);

        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, 999, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x, apk().y,
            c1, ct,
        );
    }

    #[test(should_fail)]
    fn negative_change_wrapping_the_field_is_unsatisfiable() {
        // The classic soundness hole this circuit must close: v1 = v_in +
        // 100 overspends the input, and v2 = -100 (i.e. P - 100) makes
        // v_in == v1 + v2 hold as FIELD arithmetic. Only the explicit
        // 64-bit range constraint on v2 rejects it; every other constraint
        // holds by construction (the memo matches the s_new = 1600 dummy
        // flow). (Plain should_fail: the failing opcode is the builtin
        // range constraint, whose message is not a stable string to pin.)
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);

        let v1 = V_IN + 100;
        let v2 = 0 - 100;
        let (c1, ct) = memo_for(person_id(SECRET), S_OLD, v1, DAY, DAY);
        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], v1, PK1, R1, v2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x, apk().y,
            c1, ct,
        );
    }

    #[test(should_fail)]
    fn negative_recipient_amount_wrapping_the_field_is_unsatisfiable() {
        // Mirror of the v2 case, closing the worse direction: v1 = -100
        // (P - 100) with v2 = v_in + 100 satisfies conservation as FIELD
        // arithmetic and would DECREASE the tally (s_new = s_old - 100 --
        // direct limit evasion) while inflating change past v_in. Only
        // v1's 64-bit range constraint rejects it; every other constraint
        // holds by construction (the memo matches the wrapped s_new = 900
        // dummy flow), so this test fails if that constraint is ever
        // deleted.
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);

        let v1 = 0 - 100;
        let v2 = V_IN + 100;
        let (c1, ct) = memo_for(person_id(SECRET), S_OLD, v1, DAY, DAY);
        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], v1, PK1, R1, v2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x, apk().y,
            c1, ct,
        );
    }

    #[test(should_fail)]
    fn forged_note_with_oversized_value_is_unsatisfiable() {
        // v_in's own range constraint, isolated. A forged payment leaf
        // carries v_in = 2^64 + 40; v1 = 2^63 and v2 = 2^63 + 40 both pass
        // their 64-bit checks and conserve v_in exactly (as integers, no
        // wrap), and the membership check passes because the forged leaf
        // IS in the test tree. Only v_in's range constraint rejects it.
        // (s_new = 1000 + 2^63 crosses T, so the matching memo here is a
        // REAL disclosure -- the threshold gadget and memo asserts stay
        // satisfied, keeping v_in's opcode the only failure.)
        let two63: Field = 9223372036854775808;
        let v_in = two63 + two63 + 40;
        let c_pay = payment_commit(v_in, owner_pk(SK), R_IN);
        let c_tally = tally_commit(person_id(SECRET), S_OLD, DAY, R_T);
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(person_id(SECRET), S_OLD, two63, DAY, DAY);

        let _ = main(
            SECRET, v_in, SK, R_IN, pay_sibs, [false; 16], two63, PK1, R1, two63 + 40, R2, S_OLD,
            DAY, R_T, tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x,
            apk().y, c1, ct,
        );
    }

    #[test(should_fail)]
    fn forged_tally_subtotal_near_the_modulus_is_unsatisfiable() {
        // The review's probe, pinned: a tally leaf forged with s_old =
        // P - 50 (only reachable by bypassing pool admission -- every
        // honest entry path constrains s) would wrap s_new to 150, a limit
        // reset. The commitment opens the forged leaf, so membership,
        // conservation, ranges on v, the day, and the memo (dummy, for the
        // wrapped s_new = 150) all hold; only s_old's 128-bit bound
        // rejects it, making circuit-local soundness independent of
        // admission discipline.
        let s_old = 0 - 50;
        let c_pay = payment_commit(V_IN, owner_pk(SK), R_IN);
        let c_tally = tally_commit(person_id(SECRET), s_old, DAY, R_T);
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(person_id(SECRET), s_old, V1, DAY, DAY);

        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, s_old, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x, apk().y,
            c1, ct,
        );
    }

    #[test(should_fail_with = "merkle_verify: root mismatch")]
    fn another_persons_tally_is_unspendable() {
        // The tree holds the tally of person SECRET; the prover runs with
        // person_secret = 8 and every other witness honest. The derived
        // C_t_old then differs from the leaf under root, so the tally
        // membership fails: consuming a tally requires its person_secret.
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(person_id(8), S_OLD, V1, DAY, DAY);

        let _ = main(
            8, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x, apk().y,
            c1, ct,
        );
    }

    #[test(should_fail_with = "merkle_verify: root mismatch")]
    fn stale_tally_path_does_not_verify_against_the_fresh_root() {
        // The tree grew from [c_pay, c_tally] to [c_pay, c_tally, c_extra]
        // (say an updated tally landed at index 2). A proof reusing the OLD
        // tree's tally path against the NEW root must be unsatisfiable --
        // paths have to be re-derived against the root the proof
        // references. The payment path IS re-derived here, isolating the
        // stale tally path as the failing constraint.
        let (c_pay, c_tally) = honest_leaves();
        let (_, _, stale_tally_sibs) = two_leaf_tree(c_pay, c_tally);

        // Three-leaf tree by hand: level 1 is [p2([c_pay, c_tally]),
        // p2([c_extra, 0])], then fold up with empty-subtree roots.
        let c_extra = 4242;
        let mut zeros: [Field; 16] = [0; 16];
        for k in 1..16 {
            zeros[k] = p2([zeros[k - 1], zeros[k - 1]]);
        }
        let n10 = p2([c_pay, c_tally]);
        let n11 = p2([c_extra, 0]);
        let mut fresh_pay_sibs = zeros;
        fresh_pay_sibs[0] = c_tally;
        fresh_pay_sibs[1] = n11;
        let mut fresh_root = p2([n10, n11]);
        for k in 2..16 {
            fresh_root = p2([fresh_root, zeros[k]]);
        }
        let (c1, ct) = memo_for(person_id(SECRET), S_OLD, V1, DAY, DAY);

        let _ = main(
            SECRET, V_IN, SK, R_IN, fresh_pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY,
            R_T, stale_tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, fresh_root, DAY, T_TEST,
            apk().x, apk().y, c1, ct,
        );
    }

    #[test(should_fail_with = "spend: tally day is in the future")]
    fn spend_dated_before_the_tally_day_is_unsatisfiable() {
        // d_now = DAY - 1 against a tally minted on DAY: time only moves
        // forward. (Task 7's same-day assert became this ordering.)
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(person_id(SECRET), S_OLD, V1, DAY, DAY - 1);

        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY - 1, T_TEST, apk().x,
            apk().y, c1, ct,
        );
    }

    #[test(should_fail)]
    fn forged_tally_day_beyond_u32_is_unsatisfiable() {
        // d_old's 32-bit bound, isolated. A forged tally dated DAY + 2^32
        // truncates to DAY inside the u32 ordering cast, so the ordering
        // check passes -- while the exact field equality d_now == d_old
        // fails, flipping the branch into a subtotal reset. Membership
        // opens the forged leaf, and the memo matches the reset flow
        // (s_new = 200, dummy); only d_old's range opcode rejects it.
        let d_old = DAY + TWO_POW_32;
        let pid = person_id(SECRET);
        let c_pay = payment_commit(V_IN, owner_pk(SK), R_IN);
        let c_tally = tally_commit(pid, S_OLD, d_old, R_T);
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(pid, S_OLD, V1, d_old, DAY);

        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, d_old, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x, apk().y,
            c1, ct,
        );
    }

    #[test(should_fail)]
    fn public_day_beyond_u32_is_unsatisfiable() {
        // d_now's own 32-bit bound, isolated the same way: d_now = DAY +
        // 2^32 truncates to DAY for the ordering check against an honest
        // tally on DAY, then differs from it in the field, resetting the
        // subtotal onto a nonsense day. Only d_now's range opcode rejects
        // it (the memo matches the reset flow).
        let d_now = DAY + TWO_POW_32;
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(person_id(SECRET), S_OLD, V1, DAY, d_now);

        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, d_now, T_TEST, apk().x, apk().y,
            c1, ct,
        );
    }

    #[test(should_fail_with = "spend: memo c1 mismatch")]
    fn tampered_memo_c1_is_unsatisfiable() {
        // An honest flow whose published ephemeral point is off by one
        // coordinate: the memo no longer equals the circuit's own
        // encryption, so the payment cannot settle with it.
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(person_id(SECRET), S_OLD, V1, DAY, DAY);
        let tampered = [c1[0] + 1, c1[1]];

        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x, apk().y,
            tampered, ct,
        );
    }

    #[test(should_fail_with = "spend: memo ct mismatch")]
    fn tampered_memo_ciphertext_is_unsatisfiable() {
        // Same flow, one ciphertext limb bumped: a prover cannot publish a
        // memo whose payload differs from the required disclosure -- this
        // is the "verifiably correct encrypted report" constraint.
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);
        let (c1, ct) = memo_for(person_id(SECRET), S_OLD, V1, DAY, DAY);
        let tampered = [ct[0], ct[1], ct[2], ct[3] + 1];

        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, apk().x, apk().y,
            c1, tampered,
        );
    }

    #[test(should_fail_with = "spend: auditor key is not on the curve")]
    fn off_curve_auditor_key_is_unsatisfiable() {
        // apk = (1, 2) satisfies no Grumpkin equation (1 - 17 != 4): the
        // on-curve assert fires before the point ever reaches the scalar
        // multiplication inside elgamal_encrypt. The memo arguments are
        // irrelevant zeros -- execution never gets that far.
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);

        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, R_ENC, 0, root, DAY, T_TEST, 1, 2, [0, 0],
            [0, 0, 0, 0],
        );
    }

    // ---- threshold gadget unit tests -------------------------------------
    // These call assert_over_threshold_iff directly with a CHOSEN flag,
    // simulating the malicious prover the hint architecture allows: in the
    // proof system `over` is just a witness, and nargo's honest witness
    // generator can never exercise a lie through main. Each lie must be
    // unsatisfiable on the gadget's own constraints.

    #[test]
    fn threshold_flag_accepts_honest_verdicts() {
        // Just over, exactly at (strictly-greater means NOT over), zero,
        // and the largest reachable s_new (2^128 + 2^64 - 2, from s_old <
        // 2^128 and v1 < 2^64) on the over side -- the fail-safe
        // direction: a forged-tally subtotal stays satisfiable ONLY as a
        // disclosure.
        assert_over_threshold_iff(true, T_TEST + 1, T_TEST);
        assert_over_threshold_iff(false, T_TEST, T_TEST);
        assert_over_threshold_iff(false, 0, T_TEST);
        assert_over_threshold_iff(true, TWO_POW_128 + TWO_POW_64 - 2, T_TEST);
    }

    #[test(should_fail)]
    fn threshold_flag_cannot_lie_high() {
        // over = true with s_new <= t: diff = s - t - 1 wraps to P - 6,
        // far beyond 129 bits.
        assert_over_threshold_iff(true, 5, 10);
    }

    #[test(should_fail)]
    fn threshold_flag_cannot_lie_low() {
        // over = false with s_new > t: diff = t - s wraps to P - 5.
        assert_over_threshold_iff(false, 10, 5);
    }

    #[test(should_fail)]
    fn huge_subtotal_cannot_claim_the_dummy_branch() {
        // The fail-safe property, adversarially: a subtotal past 2^128
        // (only reachable through a forged tally) must not satisfy the
        // dummy side. diff = t - s wraps huge; only the over side of the
        // mux can accept such an s_new.
        assert_over_threshold_iff(false, TWO_POW_128 + 5, T_TEST);
    }

    #[test(should_fail)]
    fn oversized_threshold_cannot_flip_the_flag() {
        // t's 64-bit bound, isolated: with t = P - 1 admitted, over = true
        // at s_new = 5 would satisfy the muxed check (diff = 5 - (P-1) - 1
        // wraps to exactly 5) -- the comparison would lie for small
        // subtotals. The bound rejects such a t before the mux runs.
        assert_over_threshold_iff(true, 5, 0 - 1);
    }
}

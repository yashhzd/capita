// Spend circuit core: one shielded payment, coupled to the payer's
// per-person tally note. This coupling is the heart of the protocol -- a
// payment is only valid if it also consumes the payer's single live tally
// note (their running daily subtotal) and produces the updated one, so
// every payment from every wallet a person owns moves one shared total.
// Task 7 scope is same-day accumulation only; the threshold / disclosure
// branch and day rollover extend this circuit in Task 8.
//
// Statement (arity fixed at 1 payment input, 2 outputs):
//
//   pk_self = owner_pk(owner_sk)
//   C_in    = payment_commit(v_in, pk_self, r_in)        member of root
//   N_pay   = note_nullifier(owner_sk, C_in)             (public output)
//   pid     = person_id(person_secret)
//   C_t_old = tally_commit(pid, s_old, d_old, r_t)       member of root
//   N_tally = note_nullifier(person_secret, C_t_old)     (public output)
//   d_old  == d_now
//   v_in   == v1 + v2         over 64-bit range-checked values
//   C_out1  = payment_commit(v1, pk1, r1)                (public output)
//   C_out2  = payment_commit(v2, pk_self, r2)            (public output)
//   C_t_new = tally_commit(pid, s_old + v1, d_now, r_t_new)  (public output)
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
// - s_old carries no range check, deliberately: it is bound by C_t_old,
//   which must open a tally already in the tree. Tallies enter the tree at
//   s = 0 (enrollment) or s_old + v1 (here), v1 < 2^64 per spend, and the
//   depth-16 tree caps total notes at 2^16 -- so every reachable subtotal
//   stays below 2^80, far from the field modulus, and s_old + v1 cannot
//   wrap. Task 8's threshold comparison must bound s_new explicitly when
//   it compares against T.

use common::{
    MERKLE_DEPTH, merkle_verify, note_nullifier, owner_pk, payment_commit, person_id,
    tally_commit,
};

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
    // Public inputs.
    root: pub Field,
    d_now: pub Field,
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
    // both reconstructs the commitment's pid and keys the nullifier.
    let pid = person_id(person_secret);
    let c_t_old = tally_commit(pid, s_old, d_old, r_t);
    merkle_verify(c_t_old, root, path_t_siblings, path_t_indices);
    let n_tally = note_nullifier(person_secret, c_t_old);

    // Same-day accumulation only (Task 7 scope); Task 8 replaces this with
    // the day-rollover branch.
    assert(d_now == d_old, "spend: tally day does not match d_now");

    // Conservation over the range-checked amounts: all three below 2^64,
    // so v1 + v2 < 2^65 << P cannot wrap, and the field equation is exact
    // integer conservation.
    assert(v_in == v1 + v2, "spend: value conservation violated");

    // Outputs: recipient note, self-change note, updated tally. The tally
    // accumulates v1 only and stays on d_now (== d_old).
    let c_out1 = payment_commit(v1, pk1, r1);
    let c_out2 = payment_commit(v2, pk_self, r2);
    let s_new = s_old + v1;
    let c_tally_new = tally_commit(pid, s_new, d_now, r_t_new);

    (n_pay, n_tally, c_out1, c_out2, c_tally_new)
}

mod tests {
    use super::main;
    use common::{note_nullifier, owner_pk, p2, payment_commit, person_id, tally_commit};

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

        let (n_pay, n_tally, c_out1, c_out2, c_tally_new) = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, root, DAY,
        );

        assert_eq(n_pay, note_nullifier(SK, c_pay));
        assert_eq(n_tally, note_nullifier(SECRET, c_tally));
        assert_eq(c_out1, payment_commit(V1, PK1, R1));
        // Change is committed under the payer's own derived key...
        assert_eq(c_out2, payment_commit(V2, owner_pk(SK), R2));
        // ...and the new tally binds (pid, s_old + v1, d_now): 1000 + 200.
        assert_eq(c_tally_new, tally_commit(person_id(SECRET), 1200, DAY, R_T_NEW));
    }

    #[test(should_fail_with = "spend: value conservation violated")]
    fn conservation_violation_is_unsatisfiable() {
        // v1 + v2 = 200 + 999 != 500. Every other constraint holds (both
        // memberships open honest leaves; 999 is in u64 range), isolating
        // the conservation equation.
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);

        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, 999, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, root, DAY,
        );
    }

    #[test(should_fail)]
    fn negative_change_wrapping_the_field_is_unsatisfiable() {
        // The classic soundness hole this circuit must close: v1 = v_in +
        // 100 overspends the input, and v2 = -100 (i.e. P - 100) makes
        // v_in == v1 + v2 hold as FIELD arithmetic. Only the explicit
        // 64-bit range constraint on v2 rejects it; every other constraint
        // holds by construction. (Plain should_fail: the failing opcode is
        // the builtin range constraint, whose message is not a stable
        // string to pin.)
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);

        let v1 = V_IN + 100;
        let v2 = 0 - 100;
        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], v1, PK1, R1, v2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, root, DAY,
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

        let _ = main(
            8, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, root, DAY,
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

        let _ = main(
            SECRET, V_IN, SK, R_IN, fresh_pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY,
            R_T, stale_tally_sibs, tally_indices(), R_T_NEW, fresh_root, DAY,
        );
    }

    #[test(should_fail_with = "spend: tally day does not match d_now")]
    fn cross_day_spend_is_unsatisfiable_in_this_task() {
        // d_now = DAY + 1 against a tally minted on DAY: Task 7 is
        // same-day accumulation only. Task 8 replaces this assert with the
        // rollover branch.
        let (c_pay, c_tally) = honest_leaves();
        let (root, pay_sibs, tally_sibs) = two_leaf_tree(c_pay, c_tally);

        let _ = main(
            SECRET, V_IN, SK, R_IN, pay_sibs, [false; 16], V1, PK1, R1, V2, R2, S_OLD, DAY, R_T,
            tally_sibs, tally_indices(), R_T_NEW, root, DAY + 1,
        );
    }
}

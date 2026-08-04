// Capita Protocol common circuit library.
//
// Mirrors the TypeScript reference implementation in `capita/harness/src/`
// (constants.ts, poseidon.ts over bb.js poseidon2Hash, merkle.ts,
// grumpkin.ts / elgamal.ts, notes.ts). The cross-implementation consistency
// gate in `capita/harness/tests/consistency.test.ts` executes the probe
// circuit in `circuits/consistency` and asserts every function here agrees
// with the TypeScript side on fixed inputs; any change to a formula below
// must land on both sides together.

use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul,
};
use std::hash::poseidon2_permutation;
use std::static_assert;

// Protocol constants, transcribed from harness/src/constants.ts. APP_SCOPE
// stays in hex on both sides so the two files diff cleanly against each
// other and the spec.
pub global DOMAIN_PAYMENT: Field = 1;
pub global DOMAIN_TALLY: Field = 2;
pub global DOMAIN_ENROLL: Field = 3;
pub global DOMAIN_NULLIFIER: Field = 4;
pub global APP_SCOPE: Field = 0xca717a;
pub global MERKLE_DEPTH: u32 = 16;

// Poseidon2 sponge shape for the bn254 backend: state width 4, rate 3.
global P2_STATE: u32 = 4;
global P2_RATE: u32 = 3;
global TWO_POW_64: Field = 18446744073709551616;

/// Poseidon2 hash over the BN254 scalar field, matching bb.js
/// `poseidon2Hash` (the harness's `p2()`): barretenberg's fixed-length
/// sponge with rate 3, capacity 1, iv = N * 2^64 seeded into state[3], and
/// output state[0] after the final permutation. The message length N is
/// part of the domain: p2([x]) != p2([x, 0]).
///
/// The sponge is spelled out here over the `poseidon2_permutation`
/// blackbox because this stdlib version exposes no public fixed-length
/// Poseidon2 hash (its `Poseidon2Hasher` is pub(crate) comptime support,
/// on a different absorption schedule). Barretenberg's lazy duplex --
/// flush a full 3-element cache only when the next element arrives, then
/// once more in squeeze -- permutes exactly once per ceil(N/3) block with
/// the tail block folded into the last permutation, which is what the
/// eager per-block loop below computes.
pub fn p2<let N: u32>(input: [Field; N]) -> Field {
    // Barretenberg's arity-0 sponge still permutes once before squeezing;
    // the loop below would instead return state[0] = 0 without permuting.
    // No protocol formula hashes an empty message, so rather than matching
    // that edge, make it unreachable at compile time.
    static_assert(N > 0, "p2: empty input is outside the sponge contract");
    let mut state: [Field; P2_STATE] = [0, 0, 0, (N as Field) * TWO_POW_64];
    for block in 0..(N + P2_RATE - 1) / P2_RATE {
        for j in 0..P2_RATE {
            let idx = block * P2_RATE + j;
            if idx < N {
                state[j] += input[idx];
            }
        }
        state = poseidon2_permutation(state);
    }
    state[0]
}

/// Person identity: `person_id = p2([person_secret, APP_SCOPE])`.
pub fn person_id(person_secret: Field) -> Field {
    p2([person_secret, APP_SCOPE])
}

/// Payment note owner key: `owner_pk = p2([owner_sk])`.
pub fn owner_pk(owner_sk: Field) -> Field {
    p2([owner_sk])
}

/// Payment note `{v, owner_pk, r}`: `C = p2([DOMAIN_PAYMENT, v, owner_pk, r])`.
pub fn payment_commit(v: Field, owner_pk: Field, r: Field) -> Field {
    p2([DOMAIN_PAYMENT, v, owner_pk, r])
}

/// Tally note `{person_id, subtotal s, day d, r}`:
/// `C_t = p2([DOMAIN_TALLY, person_id, s, d, r])`.
pub fn tally_commit(person_id: Field, s: Field, d: Field, r: Field) -> Field {
    p2([DOMAIN_TALLY, person_id, s, d, r])
}

/// One-time enrollment nullifier: `E = p2([DOMAIN_ENROLL, person_id])`.
pub fn enroll_nullifier(person_id: Field) -> Field {
    p2([DOMAIN_ENROLL, person_id])
}

/// Note nullifier: `N = p2([DOMAIN_NULLIFIER, secret, c])`, where `secret`
/// is `owner_sk` for payment notes and `person_secret` for tally notes.
pub fn note_nullifier(secret: Field, c: Field) -> Field {
    p2([DOMAIN_NULLIFIER, secret, c])
}

/// Fold a Merkle authentication path, leaf-level first (merkle.ts
/// convention): `indices[k]` true means the current node is the RIGHT
/// child at level k, so that level folds as `p2([sibling, current])`;
/// false means LEFT, folding as `p2([current, sibling])`. (The plan wrote
/// this parameter as `[u1; 16]`; this compiler version has removed `u1`,
/// and `bool` is its stated replacement -- the harness's 0/1 index bits
/// map to false/true.) Empty leaf is 0 and internal nodes are
/// `p2([left, right])`, so an all-zero path reproduces the zero-subtree
/// chain `zeros[k] = p2([zeros[k-1], zeros[k-1]])`.
pub fn merkle_root(
    leaf: Field,
    siblings: [Field; MERKLE_DEPTH],
    indices: [bool; MERKLE_DEPTH],
) -> Field {
    let mut current = leaf;
    for k in 0..MERKLE_DEPTH {
        let sibling = siblings[k];
        let (left, right) = if indices[k] {
            (sibling, current)
        } else {
            (current, sibling)
        };
        current = p2([left, right]);
    }
    current
}

/// Assert that `leaf` sits under `root` along the given path.
pub fn merkle_verify(
    leaf: Field,
    root: Field,
    siblings: [Field; MERKLE_DEPTH],
    indices: [bool; MERKLE_DEPTH],
) {
    assert(merkle_root(leaf, siblings, indices) == root, "merkle_verify: root mismatch");
}

/// Hash-ElGamal encryption of four field limbs (elgamal.ts `encrypt`):
///   S     = r_enc * apk          (shared secret)
///   c1    = r_enc * G            (ephemeral public point)
///   ct[i] = msg[i] + p2([S.x, S.y, i])   for i = 0..3
/// Returns `([c1.x, c1.y], ct)`.
///
/// Scalar convention (Task 8's spend circuit must pass witnesses the same
/// way): r_enc lives in Grumpkin's scalar field -- the BN254 *base* field,
/// which is larger than the native Field modulus -- so it cannot be a
/// single Field. It enters as the canonical value's 128-bit limbs,
/// `r_enc = r_enc_lo + 2^128 * r_enc_hi` (the `EmbeddedCurveScalar` /
/// `std::field::bn254::decompose` split), each limb range-checked to 128
/// bits. Callers reduce mod the Grumpkin group order before splitting,
/// exactly as the harness's `mul()` reduces its scalar.
///
/// A degenerate shared secret (r_enc = 0 mod group order, or apk the
/// identity) would make every pad `p2([0, 0, i])`; the harness throws on
/// that and this function is unsatisfiable, keeping the two contracts
/// aligned.
pub fn elgamal_encrypt(
    msg: [Field; 4],
    apk_x: Field,
    apk_y: Field,
    r_enc_lo: Field,
    r_enc_hi: Field,
) -> ([Field; 2], [Field; 4]) {
    r_enc_lo.assert_max_bit_size::<128>();
    r_enc_hi.assert_max_bit_size::<128>();
    let r_enc = EmbeddedCurveScalar::new(r_enc_lo, r_enc_hi);
    let apk = EmbeddedCurvePoint::new(apk_x, apk_y);
    let s = multi_scalar_mul([apk], [r_enc]);
    assert(!s.is_infinite(), "elgamal_encrypt: degenerate shared secret");
    let c1 = fixed_base_scalar_mul(r_enc);
    let mut ct: [Field; 4] = [0; 4];
    for i in 0..4 {
        ct[i] = msg[i] + p2([s.x, s.y, i as Field]);
    }
    ([c1.x, c1.y], ct)
}

mod tests {
    use super::{
        elgamal_encrypt, enroll_nullifier, merkle_root, merkle_verify, note_nullifier, owner_pk,
        p2, payment_commit, person_id, tally_commit,
    };
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    #[test]
    fn p2_arity_is_part_of_the_domain() {
        assert(p2([5]) != p2([5, 0]));
        assert(p2([5, 0]) != p2([5, 0, 0]));
    }

    #[test]
    fn p2_matches_bbjs_at_arities_6_to_9() {
        // Known-answer pins for the sponge's block schedule beyond the
        // arities the consistency gate compares live against bb.js (1-5):
        // 6 = two full rate-3 blocks, 7 and 8 = two blocks plus a tail of
        // one and two, 9 = three full blocks. Reference values computed
        // with @aztec/bb.js poseidon2Hash over the inputs [1..N].
        assert_eq(
            p2([1, 2, 3, 4, 5, 6]),
            0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a,
        );
        assert_eq(
            p2([1, 2, 3, 4, 5, 6, 7]),
            0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238,
        );
        assert_eq(
            p2([1, 2, 3, 4, 5, 6, 7, 8]),
            0x01dec21c6e1b30609eda618d7e35e5d9d6152f8fa67320d939c1a89603647142,
        );
        assert_eq(
            p2([1, 2, 3, 4, 5, 6, 7, 8, 9]),
            0x174b592c95a1811beff20ff96e1276cad3d155670a909f90c3658841f0f70fea,
        );
    }

    #[test]
    fn merkle_fold_direction_follows_index_bit() {
        // Level-0 orientation: indices[0] = false folds p2([leaf, sib]),
        // indices[0] = true folds p2([sib, leaf]); upper levels identical.
        let leaf = 42;
        let mut sibs: [Field; 16] = [0; 16];
        for k in 0..16 {
            sibs[k] = 100 + (k as Field);
        }
        let mut right_idx: [bool; 16] = [false; 16];
        right_idx[0] = true;

        let mut expect_left = p2([leaf, sibs[0]]);
        let mut expect_right = p2([sibs[0], leaf]);
        for k in 1..16 {
            expect_left = p2([expect_left, sibs[k]]);
            expect_right = p2([expect_right, sibs[k]]);
        }
        assert_eq(merkle_root(leaf, sibs, [false; 16]), expect_left);
        assert_eq(merkle_root(leaf, sibs, right_idx), expect_right);
        assert(expect_left != expect_right);
    }

    #[test]
    fn merkle_zero_subtree_chain_and_verify() {
        // zeros[k] = p2([zeros[k-1], zeros[k-1]]); the empty-tree root is
        // zeros[16], reached by folding the zero leaf up an all-zero path.
        let mut zeros: [Field; 17] = [0; 17];
        for k in 1..17 {
            zeros[k] = p2([zeros[k - 1], zeros[k - 1]]);
        }
        let mut sibs: [Field; 16] = [0; 16];
        for k in 0..16 {
            sibs[k] = zeros[k];
        }
        assert_eq(merkle_root(0, sibs, [false; 16]), zeros[16]);
        merkle_verify(0, zeros[16], sibs, [false; 16]);
    }

    #[test(should_fail_with = "merkle_verify: root mismatch")]
    fn merkle_verify_rejects_wrong_root() {
        merkle_verify(1, 12345, [0; 16], [false; 16]);
    }

    #[test]
    fn note_domains_are_separated() {
        // The six formulas over overlapping raw inputs (5, 6, 7, 8) stay
        // pairwise distinct: tags and arity keep note types apart.
        let outputs = [
            person_id(5),
            owner_pk(5),
            payment_commit(5, 6, 7),
            tally_commit(5, 6, 7, 8),
            enroll_nullifier(5),
            note_nullifier(5, 6),
        ];
        for i in 0..6 {
            for j in 0..6 {
                if i != j {
                    assert(outputs[i] != outputs[j]);
                }
            }
        }
        // The domain tag itself matters, not just arity.
        assert(payment_commit(5, 6, 7) != p2([5, 6, 7]));
    }

    #[test]
    fn elgamal_pads_and_c1_from_unit_scalar() {
        // r_enc = 1: c1 = G and S = apk, so ct[i] - msg[i] must be the pad
        // p2([apk.x, apk.y, i]) -- pinning the pad formula and limb-index
        // placement without reference values.
        let g = EmbeddedCurvePoint::generator();
        let apk = g.double();
        let msg = [1, 2, 3, 4];
        let (c1, ct) = elgamal_encrypt(msg, apk.x, apk.y, 1, 0);
        assert_eq(c1[0], g.x);
        assert_eq(c1[1], g.y);
        for i in 0..4 {
            assert_eq(ct[i] - msg[i], p2([apk.x, apk.y, i as Field]));
        }
    }

    #[test(should_fail_with = "elgamal_encrypt: degenerate shared secret")]
    fn elgamal_rejects_zero_scalar() {
        let g = EmbeddedCurvePoint::generator();
        let _ = elgamal_encrypt([0, 0, 0, 0], g.x, g.y, 0, 0);
    }
}

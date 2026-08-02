// Enrollment circuit: the one-time, per-person entry into the pool.
//
// The prover holds a person-level secret and shows, without revealing it:
//   pid = person_id(person_secret)              (private intermediate)
//   E   = enroll_nullifier(pid)                 (public output)
//   C_t = tally_commit(pid, 0, d_now, r_t)      (public output)
// E is a deterministic function of the person alone -- no salt, no day --
// so one person can only ever produce one value of E, and the pool's
// seen-enrollments set turns that into "one genesis tally note per
// person". C_t seeds that tally note with subtotal 0 on the (public)
// current day d_now; its salt r_t keeps the note commitment hiding even
// though everything else about genesis state is fixed.
//
// Credential layer: mocked by design in this prototype. person_secret is a
// free witness standing in for a value derived from a verified government
// credential (e.g. a passport chip signature checked in-circuit). A
// production enrollment circuit would additionally constrain person_secret
// to be so derived -- that constraint is what binds "one E" to "one legal
// person" rather than "one chosen secret". This prototype deliberately
// omits it to study the spending-limit mechanics downstream of identity.

use common::{enroll_nullifier, person_id, tally_commit};

fn main(person_secret: Field, r_t: Field, d_now: pub Field) -> pub (Field, Field) {
    let pid = person_id(person_secret);
    let e = enroll_nullifier(pid);
    let c_t_genesis = tally_commit(pid, 0, d_now, r_t);
    (e, c_t_genesis)
}

mod tests {
    use super::main;
    use common::{enroll_nullifier, person_id, tally_commit};

    #[test]
    fn outputs_compose_the_library_formulas() {
        // Distinct argument values (7, 8, 9) so any argument-order swap in
        // main -- r_t for d_now, or a subtotal slot mix-up -- breaks the
        // equality instead of aliasing.
        let (e, c_t) = main(7, 8, 9);
        let pid = person_id(7);
        assert_eq(e, enroll_nullifier(pid));
        assert_eq(c_t, tally_commit(pid, 0, 9, 8));
    }

    #[test]
    fn genesis_subtotal_is_pinned_to_zero() {
        // The limit mechanism depends on every person starting at s = 0;
        // a genesis note minted at any other subtotal must not verify.
        let (_, c_t) = main(7, 8, 9);
        let pid = person_id(7);
        assert(c_t != tally_commit(pid, 1, 9, 8));
    }

    #[test]
    fn nullifier_binds_the_person_not_the_salt_or_day() {
        // Re-enrolling with a fresh salt on a later day yields a fresh
        // tally note but the SAME E -- which is exactly what lets the pool
        // reject it.
        let (e1, c1) = main(7, 8, 9);
        let (e2, c2) = main(7, 1000, 20260802);
        assert_eq(e1, e2);
        assert(c1 != c2);
    }

    #[test]
    fn different_secrets_diverge() {
        let (e1, c1) = main(7, 8, 9);
        let (e2, c2) = main(8, 8, 9);
        assert(e1 != e2);
        assert(c1 != c2);
    }
}

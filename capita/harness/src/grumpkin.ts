import { P } from "./constants.js";

// Grumpkin: the short-Weierstrass curve y^2 = x^3 - 17 over the BN254
// *scalar* field P (from constants.ts). Grumpkin and BN254 form a 2-cycle:
// Grumpkin's base field (where the coordinates below live) is BN254's scalar
// field, and Grumpkin's group order is BN254's *base*-field modulus -- a
// DIFFERENT, slightly larger prime. Consequences that matter here:
//   - Point coordinates are always < P and safe to feed to p2().
//   - Scalars (spending keys, encryption randomness) live mod GRUMPKIN_ORDER,
//     NOT mod P. mul() reduces them; never pass a raw scalar to p2().
//
// All group operations here are variable-time bigint arithmetic. This module
// mirrors the circuit spec for the research harness; it is not hardened
// against timing side channels and must not be reused for live secrets.

export type Pt = { x: bigint; y: bigint; inf: boolean };

// Grumpkin group order = BN254 base-field modulus (the 2-cycle partner
// prime, i.e. the alt_bn128 coordinate-field modulus of EIP-196). The
// "group order" test verifies this constant against G computationally.
export const GRUMPKIN_ORDER =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// Curve constant: y^2 = x^3 + B with B = -17 mod P.
const B = P - 17n;

/** The point at infinity (group identity). x/y are dummy zeros; check `inf`. */
export const INF: Pt = Object.freeze({ x: 0n, y: 0n, inf: true });

const mod = (a: bigint): bigint => ((a % P) + P) % P;

function powMod(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

// Modular inverse via extended Euclid. P is prime, so this fails only for 0.
function invMod(a: bigint): bigint {
  let r0 = mod(a), r1 = P;
  let s0 = 1n, s1 = 0n;
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error("invMod: 0 has no inverse mod P");
  return mod(s0);
}

// Tonelli-Shanks square root mod P. P = 1 + 2^28 * odd, so the simple
// p = 3 mod 4 exponentiation shortcut does not apply. Only used at module
// load to derive the generator's y-coordinate, so the trial search for a
// quadratic non-residue z is a one-time cost.
function sqrtMod(n: bigint): bigint {
  const v = mod(n);
  if (v === 0n) return 0n;
  if (powMod(v, (P - 1n) / 2n) !== 1n) {
    throw new Error("sqrtMod: value is not a quadratic residue mod P");
  }
  let q = P - 1n, s = 0n;
  while ((q & 1n) === 0n) { q >>= 1n; s += 1n; }
  let z = 2n;
  while (powMod(z, (P - 1n) / 2n) !== P - 1n) z += 1n;
  let m = s;
  let c = powMod(z, q);
  let t = powMod(v, q);
  let r = powMod(v, (q + 1n) / 2n);
  while (t !== 1n) {
    let i = 0n;
    for (let t2 = t; t2 !== 1n; t2 = (t2 * t2) % P) i += 1n;
    const b = powMod(c, 1n << (m - i - 1n));
    m = i;
    c = (b * b) % P;
    t = (t * c) % P;
    r = (r * b) % P;
  }
  return r;
}

// Generator: x = 1, y = the even square root of 1 - 17 = -16 mod P. P is odd,
// so exactly one of the two roots {y, P-y} is even -- the choice is
// deterministic. Task 5's consistency gate reconciles these coordinates with
// the Noir embedded-curve generator; if they differ, the circuit's
// coordinates win and get adopted here.
const gy = (() => {
  const root = sqrtMod(mod(1n - 17n));
  return (root & 1n) === 0n ? root : P - root;
})();

export const G: Pt = Object.freeze({ x: 1n, y: gy, inf: false });

export function isOnCurve(pt: Pt): boolean {
  if (pt.inf) return true;
  return mod(pt.y * pt.y) === mod(pt.x * pt.x * pt.x + B);
}

export function negate(pt: Pt): Pt {
  if (pt.inf) return { x: 0n, y: 0n, inf: true };
  return { x: pt.x, y: mod(-pt.y), inf: false };
}

// Group law. Every return is a fresh object so callers never alias inputs.
// Precondition: finite inputs carry coordinates already normalized into
// [0, P). The x-comparison below is raw bigint equality, so an unnormalized
// coordinate (e.g. x + P) would silently take the chord branch where the
// tangent applies. Every point this module produces satisfies this; points
// constructed by hand (Tasks 4-8) must respect it too.
export function add(a: Pt, b: Pt): Pt {
  if (a.inf) return { ...b };
  if (b.inf) return { ...a };
  let lambda: bigint;
  if (a.x === b.x) {
    // Same x: either b = -a (vertical chord, sum is infinity -- this also
    // covers the y = 0 self-inverse doubling case, since then y + y = 0),
    // or a = b and the tangent-line doubling formula applies.
    if (mod(a.y + b.y) === 0n) return { x: 0n, y: 0n, inf: true };
    lambda = mod(3n * a.x * a.x * invMod(mod(2n * a.y)));
  } else {
    lambda = mod((b.y - a.y) * invMod(mod(b.x - a.x)));
  }
  const x3 = mod(lambda * lambda - a.x - b.x);
  const y3 = mod(lambda * (a.x - x3) - a.y);
  return { x: x3, y: y3, inf: false };
}

// Double-and-add scalar multiplication. The scalar is reduced mod
// GRUMPKIN_ORDER (Grumpkin's scalar field), so callers may pass any bigint.
export function mul(k: bigint, pt: Pt): Pt {
  let n = ((k % GRUMPKIN_ORDER) + GRUMPKIN_ORDER) % GRUMPKIN_ORDER;
  let acc: Pt = { x: 0n, y: 0n, inf: true };
  let base: Pt = { ...pt };
  while (n > 0n) {
    if (n & 1n) acc = add(acc, base);
    base = add(base, base);
    n >>= 1n;
  }
  return acc;
}
